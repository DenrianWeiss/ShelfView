using System.Runtime.InteropServices;
using System.Text.Json;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Redfish;
/// <summary>一次登录会话：持有连接与派生端点；dispose 时注销自有会话。</summary>
public sealed partial class RedfishSession : IAsyncDisposable
{
    internal uint RequestTimeoutMs { get; set; } = 5000;
    public const uint LogoutTimeoutMs = 15000;
    private readonly RedfishRuntime _runtime;
    private IntPtr _connection;
    private IntPtr _endpoint;
    private bool _loggedOut;
    private bool _disposed;
    internal RedfishSession(RedfishRuntime runtime, IntPtr connection, uint authenticationFlags)
    {
        _runtime = runtime;
        AuthenticationFlags = authenticationFlags;
        _connection = connection;
        NativeMethods.bc_redfish_connection_retain(connection);
        _endpoint = NativeMethods.bc_redfish_connection_endpoint(connection);
        if (_endpoint == IntPtr.Zero)
            throw new BcException(Bc.ShuttingDown, Loc.T("error.endpointUnavailable"));
        NativeMethods.bc_endpoint_retain(_endpoint);
    }

    public uint AuthenticationFlags { get; }
    /// <summary>Dispose/Logout 时的注销结果；BC_OK 之外表示设备可能仍有未确认会话。</summary>
    public uint LastLogoutStatus { get; internal set; } = Bc.Ok;

    public static async Task<RedfishSession> LoginAsync(RedfishRuntime runtime, string address, DeviceCredential credential, string caFile, uint certPolicy, uint timeoutMs, CancellationToken cancellation, uint tlsMin = 12, Socks5Connection? proxy = null)
    {
        var endpoint = await CreateEndpointAsync(runtime, address, caFile, certPolicy, credential, tlsMin, proxy).ConfigureAwait(false);
        IntPtr operation = IntPtr.Zero;
        try
        {
            var tcs = new TaskCompletionSource<BcRedfishAuthResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            var handle = GCHandle.Alloc(tcs);
            uint status;
            try
            {
                var submitted = await runtime.InvokeAsync(() =>
                {
                    var code = SubmitLogin(endpoint, credential, timeoutMs, handle, out var op);
                    return (code, op);
                }).ConfigureAwait(false);
                (status, operation) = submitted;
            }
            catch
            {
                handle.Free();
                throw;
            }

            if (status != Bc.Ok)
            {
                handle.Free();
                throw new BcException(status, Loc.F("error.context", ("what", Loc.T("core.login")), ("detail", Bc.StatusText(status))));
            }

            await using var registration = cancellation.Register(() => _ = runtime.InvokeAsync(() => NativeMethods.bc_redfish_auth_cancel(operation))).ConfigureAwait(false);
            var result = await tcs.Task.ConfigureAwait(false);
            if (result.Status != Bc.Ok)
                throw new DiscoveryFailure(result.Status, result.HttpStatus, result.Flags);
            return await runtime.InvokeAsync(() => new RedfishSession(runtime, result.Connection, result.Flags)).ConfigureAwait(false);
        }
        finally
        {
            await runtime.InvokeAsync(() =>
            {
                if (operation != IntPtr.Zero)
                    NativeMethods.bc_redfish_auth_release(operation);
                NativeMethods.bc_endpoint_release(endpoint);
                return 0;
            }).ConfigureAwait(false);
        }
    }

    private static async Task<IntPtr> CreateEndpointAsync(RedfishRuntime runtime, string address, string caFile, uint certPolicy, DeviceCredential credential, uint tlsMin = 12, Socks5Connection? proxy = null)
    {
        using var origin = BcStringPinned.Pin(address.Contains("://", StringComparison.Ordinal) ? address : "https://" + address);
        using var ca = BcStringPinned.Pin(string.IsNullOrEmpty(caFile) ? null : caFile);
        using var user = BcStringPinned.Pin(credential.Username);
        using var password = BcStringPinned.Pin(credential.Password);
        using var device = BcStringPinned.Pin("desktop-discovery");
        var options = new BcEndpointOptions
        {
            StructSize = (uint)Marshal.SizeOf<BcEndpointOptions>(),
            AbiVersion = Bc.AbiVersion,
            Origin = origin.Value,
            CaFile = ca.Value,
            Username = user.Value,
            Password = password.Value,
            DeviceId = device.Value,
            EndpointId = device.Value,
            CertPolicy = certPolicy,
            TlsMin = tlsMin,
        };
        return await runtime.InvokeAsync(() =>
        {
            var status = NativeConnections.CreateEndpoint(runtime.Context, ref options, proxy, out var endpoint);
            Bc.Check(status, "core.createEndpoint");
            return endpoint;
        }).ConfigureAwait(false);
    }

    private static uint SubmitLogin(IntPtr endpoint, DeviceCredential credential, uint timeoutMs, GCHandle handle, out IntPtr operation)
    {
        using var user = BcStringPinned.Pin(credential.Username);
        using var password = BcStringPinned.Pin(credential.Password);
        var options = new BcRedfishLoginOptions
        {
            StructSize = (uint)Marshal.SizeOf<BcRedfishLoginOptions>(),
            AbiVersion = Bc.AbiVersion,
            Mode = RedfishAbi.LoginAuto,
            RequestTimeoutMs = Math.Max(1, timeoutMs),
            Username = user.Value,
            Password = password.Value,
        };
        return NativeMethods.bc_redfish_login(endpoint, ref options, LoginTrampoline, GCHandle.ToIntPtr(handle), out operation);
    }

    private static readonly BcRedfishAuthCompletion LoginTrampoline = OnLoginCompleted;
    private static void OnLoginCompleted(IntPtr operation, IntPtr result, IntPtr userdata)
    {
        var tcs = (TaskCompletionSource<BcRedfishAuthResult>)GCHandle.FromIntPtr(userdata).Target!;
        try
        {
            if (result == IntPtr.Zero)
                tcs.TrySetException(new BcException(Bc.ProtocolError, Loc.T("core.loginNoResult")));
            else
                tcs.TrySetResult(Marshal.PtrToStructure<BcRedfishAuthResult>(result));
        }
        catch (Exception ex)
        {
            tcs.TrySetException(ex);
        }
        finally
        {
            GCHandle.FromIntPtr(userdata).Free();
        }
    }

    public bool IsSessionAuth
    {
        get
        {
            var info = NativeMethods.bc_redfish_connection_info_get(_connection);
            if (info == IntPtr.Zero)
                return false;
            return Marshal.PtrToStructure<BcRedfishConnectionInfo>(info).Mode == RedfishAbi.LoginSession;
        }
    }

    private abstract class OpState
    {
        public readonly TaskCompletionSource<object?> Done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public volatile bool UserCancelled;
        public bool Completed;
        public abstract object? Snapshot(IntPtr operation, IntPtr result);
    }

    private sealed class OpState<T> : OpState
    {
        public readonly Func<IntPtr, IntPtr, T> SnapshotFunc;
        public OpState(Func<IntPtr, IntPtr, T> snapshot) => SnapshotFunc = snapshot;
        public override object? Snapshot(IntPtr operation, IntPtr result) => SnapshotFunc(operation, result)!;
    }

    private static void FreeState(OpState state, IntPtr userdata)
    {
        GCHandle.FromIntPtr(userdata).Free();
    }

    private static readonly BcRedfishCompletion Trampoline = OnCompleted;
    private static void OnCompleted(IntPtr operation, IntPtr result, IntPtr userdata)
    {
        var state = (OpState)GCHandle.FromIntPtr(userdata).Target!;
        state.Completed = true;
        try
        {
            var value = state.Snapshot(operation, result);
            if (state.UserCancelled)
                state.Done.TrySetCanceled();
            else
                state.Done.TrySetResult(value);
        }
        catch (Exception ex)
        {
            state.Done.TrySetException(ex);
        }
        finally
        {
            NativeMethods.bc_redfish_release(operation);
            GCHandle.FromIntPtr(userdata).Free();
        }
    }

    private static readonly BcRedfishAuthCompletion AuthTrampoline = OnAuthCompleted;
    private sealed class AuthOpState : OpState
    {
        public override object? Snapshot(IntPtr operation, IntPtr result)
        {
            if (result == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.probeNoResult"));
            return Marshal.PtrToStructure<BcRedfishAuthResult>(result);
        }
    }

    private static void OnAuthCompleted(IntPtr operation, IntPtr result, IntPtr userdata)
    {
        var state = (OpState)GCHandle.FromIntPtr(userdata).Target!;
        state.Completed = true;
        try
        {
            var value = state.Snapshot(operation, result);
            if (state.UserCancelled)
                state.Done.TrySetCanceled();
            else
                state.Done.TrySetResult(value);
        }
        catch (Exception ex)
        {
            state.Done.TrySetException(ex);
        }
        finally
        {
            NativeMethods.bc_redfish_auth_release(operation);
            GCHandle.FromIntPtr(userdata).Free();
        }
    }

    private delegate uint SubmitDelegate(BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    private async Task<T> RunAsync<T>(SubmitDelegate submit, Func<IntPtr, IntPtr, T> snapshot, Func<IntPtr, uint>? cancel, CancellationToken cancellation, string what)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var state = new OpState<T>(snapshot);
        var handle = GCHandle.Alloc(state);
        uint status;
        IntPtr operation;
        try
        {
            var submitted = await _runtime.InvokeAsync(() =>
            {
                var code = submit(Trampoline, GCHandle.ToIntPtr(handle), out var op);
                return (code, op);
            }).ConfigureAwait(false);
            (status, operation) = submitted;
        }
        catch
        {
            handle.Free();
            throw;
        }

        if (status != Bc.Ok)
        {
            handle.Free();
            throw new BcException(status, Loc.F("error.context", ("what", Loc.T(what)), ("detail", Bc.StatusText(status))),
                writeMayHaveTakenEffect: false);
        }

        await using var registration = cancellation.Register(() =>
        {
            state.UserCancelled = true;
            if (cancel != null)
                _ = _runtime.InvokeAsync(() => state.Completed ? Bc.Ok : cancel(operation));
        }).ConfigureAwait(false);
        return (T)(await state.Done.Task.ConfigureAwait(false))!;
    }

    private static BcRedfishOptions Options(uint timeoutMs, uint maxSystems = 256) => new()
    {
        StructSize = (uint)Marshal.SizeOf<BcRedfishOptions>(),
        AbiVersion = Bc.AbiVersion,
        RequestTimeoutMs = Math.Max(1, timeoutMs),
        MaxSystems = maxSystems,
    };
    private static BcRedfishCollectionOptions CollectionOptions(uint timeoutMs, uint maxMembers = 256) => new()
    {
        StructSize = (uint)Marshal.SizeOf<BcRedfishCollectionOptions>(),
        AbiVersion = Bc.AbiVersion,
        RequestTimeoutMs = Math.Max(1, timeoutMs),
        MaxMembers = maxMembers,
    };
    internal static string Text(BcString value) => value.Data == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(value.Data, checked((int)value.Length)) ?? string.Empty;
    private static IReadOnlyList<string> Strings(IntPtr pointer, uint count)
    {
        if (pointer == IntPtr.Zero || count == 0)
            return Array.Empty<string>();
        var result = new List<string>((int)count);
        var stride = Marshal.SizeOf<BcString>();
        for (var i = 0; i < count; i++)
            result.Add(Text(Marshal.PtrToStructure<BcString>(IntPtr.Add(pointer, i * stride))));
        return result;
    }

    private static BcRedfishResult SnapshotResult(IntPtr operation, IntPtr result)
    {
        if (result == IntPtr.Zero)
            throw new BcException(Bc.ProtocolError, Loc.T("core.operationNoResult"));
        return Marshal.PtrToStructure<BcRedfishResult>(result);
    }

    public async Task<IReadOnlyList<string>> DiscoverSystemsAsync(uint timeoutMs, CancellationToken cancellation)
    {
        var result = await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_discover(_endpoint, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            Bc.Check(r.Status, "core.discoverSystems");
            return Strings(r.Systems, r.SystemCount);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.discoverSystems").ConfigureAwait(false);
        return (IReadOnlyList<string>)result;
    }

    public readonly record struct SystemSnapshot(DiscoveredSystem System, IReadOnlyList<string> Chassis, uint ContextStatus);
    public async Task<SystemSnapshot> GetSystemAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_get_system(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            Bc.Check(r.Status, "core.readSystem");
            var identity = NativeMethods.bc_redfish_system_identity_get(op);
            string manufacturer = "", model = "", hostName = "", serial = "", uuid = "";
            if (identity != IntPtr.Zero)
            {
                var value = Marshal.PtrToStructure<BcRedfishSystemIdentity>(identity);
                manufacturer = Text(value.Manufacturer);
                model = Text(value.Model);
                hostName = Text(value.HostName);
                serial = Text(value.SerialNumber);
                uuid = Text(value.Uuid);
            }

            var system = new DiscoveredSystem(uri, Text(r.Name), manufacturer, model, hostName, r.PowerState, Text(r.RawPowerState))
            {
                SerialNumber = serial,
                Uuid = uuid,
            };
            IReadOnlyList<string> chassis = Array.Empty<string>();
            uint contextStatus = Bc.Ok;
            var context = NativeMethods.bc_redfish_context_info_get(op);
            if (context != IntPtr.Zero)
            {
                var ctx = Marshal.PtrToStructure<BcRedfishContextInfo>(context);
                chassis = Strings(ctx.Chassis, ctx.ChassisCount);
                contextStatus = ctx.Status;
            }

            return new SystemSnapshot(system, chassis, contextStatus);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readSystem").ConfigureAwait(false);
    }

    public readonly record struct SensorReadingInfo(string Uri, string Name, string Units, uint UnitCode, string Health, string State, string ReadingTime, double Reading, double Celsius, uint TemperatureFlags, string PhysicalContext, IReadOnlyList<string> RelatedItems, uint ContextStatus);
    public async Task<SensorReadingInfo> GetSensorAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        var snapshot = await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_get_sensor(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            Bc.Check(r.Status, "core.readSensors");
            var info = NativeMethods.bc_redfish_sensor_info_get(op);
            var context = NativeMethods.bc_redfish_context_info_get(op);
            if (info == IntPtr.Zero || context == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.sensorSnapshotMissing"));
            var sensor = Marshal.PtrToStructure<BcRedfishSensorInfo>(info);
            var ctx = Marshal.PtrToStructure<BcRedfishContextInfo>(context);
            var temperature = new BcTemperatureReading();
            // Shared readings lose the CPU role after relationship classification.
            var tempStatus = NativeMethods.bc_redfish_sensor_temperature_reading(op, 1, ref temperature);
            if (tempStatus != Bc.Ok && tempStatus != Bc.Unsupported)
                Bc.Check(tempStatus, "core.mapSensors");
            return new SensorReadingInfo(uri, Text(r.Name), Text(sensor.Units), temperature.Unit, Text(sensor.Health), Text(sensor.State), Text(sensor.ReadingTime), sensor.Reading, temperature.Value, temperature.Flags, Text(ctx.PhysicalContext), Strings(ctx.RelatedItems, ctx.RelatedCount), ctx.Status);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readSensors").ConfigureAwait(false);
        return snapshot;
    }

    public async Task<uint> PatchResourceAsync(string uri, byte[] body, uint timeoutMs, CancellationToken cancellation)
    {
        using var path = BcStringPinned.Pin(uri);
        var pinned = GCHandle.Alloc(body, GCHandleType.Pinned);
        try
        {
            var bytes = new BcBytes
            {
                Data = pinned.AddrOfPinnedObject(),
                Length = (ulong)body.Length
            };
            return await RunAsync((BcRedfishCompletion complete, IntPtr user, out IntPtr operation) =>
            {
                var options = Options(timeoutMs);
                return NativeMethods.bc_redfish_patch(_endpoint, path.Value, bytes, ref options, complete, user, out operation);
            }, (op, result) =>
            {
                var value = SnapshotResult(op, result);
                Bc.Check(value.Status, "common.set");
                return value.Flags;
            }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "common.set").ConfigureAwait(false);
        }
        finally
        {
            pinned.Free();
        }
    }

    public async Task<JsonElement> GetResourceAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_get_resource(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var response = SnapshotResult(op, res);
            if (response.Status != Bc.Ok)
                throw new BcException(response.Status, Bc.StatusText(response.Status), response.HttpStatus);
            var pointer = NativeMethods.bc_redfish_resource_info_get(op);
            if (pointer == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.probeNoResult"));
            var info = Marshal.PtrToStructure<BcRedfishResourceInfo>(pointer);
            return ParseResource(info);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readSystem").ConfigureAwait(false);
    }

    private static JsonElement ParseResource(BcRedfishResourceInfo info)
    {
        var bytes = new byte[checked((int)info.Json.Length)];
        Marshal.Copy(info.Json.Data, bytes, 0, bytes.Length);
        using var json = JsonDocument.Parse(bytes);
        return json.RootElement.Clone();
    }

    public async Task<(IReadOnlyList<string> Systems, string SensorCollectionUri, uint Status)> GetChassisAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        var (systems, sensors, status, _) = await GetChassisResourceAsync(uri, timeoutMs, cancellation).ConfigureAwait(false);
        return (systems, sensors, status);
    }

    internal async Task<(IReadOnlyList<string> Systems, string SensorCollectionUri, uint Status, JsonElement Resource)> GetChassisResourceAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_get_resource(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            Bc.Check(r.Status, "core.readChassisContext");
            var resource = NativeMethods.bc_redfish_resource_info_get(op);
            var context = NativeMethods.bc_redfish_context_info_get(op);
            if (resource == IntPtr.Zero || context == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.chassisSnapshotMissing"));
            var info = Marshal.PtrToStructure<BcRedfishResourceInfo>(resource);
            var odata = Text(info.OdataType);
            if (!odata.StartsWith("#Chassis.", StringComparison.Ordinal) || !odata.EndsWith(".Chassis", StringComparison.Ordinal))
                throw new BcException(Bc.ProtocolError, Loc.T("core.notChassis"));
            var ctx = Marshal.PtrToStructure<BcRedfishContextInfo>(context);
            Bc.Check(ctx.Status, "core.readChassisContext");
            return (Strings(ctx.Systems, ctx.SystemCount), Text(ctx.SensorCollectionUri), ctx.Status, ParseResource(info));
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readChassisContext").ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<string>> GetCollectionAsync(string uri, uint kind, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = CollectionOptions(timeoutMs);
            return NativeMethods.bc_redfish_get_collection(_endpoint, pinned.Value, kind, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            Bc.Check(r.Status, "core.readCollection");
            var info = NativeMethods.bc_redfish_collection_info_get(op);
            if (info == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.collectionSnapshotMissing"));
            var value = Marshal.PtrToStructure<BcRedfishCollectionInfo>(info);
            return Strings(value.Members, value.MemberCount);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readCollection").ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<string>> DiscoverVirtualMediaAsync(string managerUri, uint timeoutMs, CancellationToken cancellation)
        => (await DiscoverVirtualMediaCollectionAsync(managerUri, timeoutMs, cancellation).ConfigureAwait(false)).Members;

    public async Task<(bool Supported, IReadOnlyList<string> Members)> DiscoverVirtualMediaCollectionAsync(string managerUri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(managerUri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = CollectionOptions(timeoutMs);
            return NativeMethods.bc_redfish_discover_virtual_media(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            if (r.Status == Bc.Unsupported)
                return (false, (IReadOnlyList<string>)Array.Empty<string>());
            Bc.Check(r.Status, "core.discoverMedia");
            var info = NativeMethods.bc_redfish_collection_info_get(op);
            if (info == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.collectionSnapshotMissing"));
            var value = Marshal.PtrToStructure<BcRedfishCollectionInfo>(info);
            return (true, Strings(value.Members, value.MemberCount));
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.discoverMedia").ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<string>> DiscoverManagersAsync(uint timeoutMs, CancellationToken cancellation)
    {
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = CollectionOptions(timeoutMs);
            return NativeMethods.bc_redfish_discover_managers(_endpoint, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            Bc.Check(r.Status, "core.discoverManagers");
            var info = NativeMethods.bc_redfish_collection_info_get(op);
            if (info == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.collectionSnapshotMissing"));
            var value = Marshal.PtrToStructure<BcRedfishCollectionInfo>(info);
            return Strings(value.Members, value.MemberCount);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.discoverManagers").ConfigureAwait(false);
    }

    public async Task<VirtualMediaDevice> GetVirtualMediaAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_get_virtual_media(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            Bc.Check(r.Status, "core.readMedia", r.HttpStatus);
            var info = NativeMethods.bc_redfish_virtual_media_info_get(op);
            if (info == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.mediaSnapshotMissing"));
            var value = Marshal.PtrToStructure<BcRedfishVirtualMediaInfo>(info);
            return new VirtualMediaDevice(uri, Text(value.Id), Text(value.Name), value.Image.Data == IntPtr.Zero ? null : Text(value.Image), value.ImageName.Data == IntPtr.Zero ? null : Text(value.ImageName), value.ConnectedVia.Data == IntPtr.Zero ? null : Text(value.ConnectedVia), Strings(value.MediaTypes, value.MediaTypeCount), (value.Flags & RedfishAbi.VmInserted) != 0, (value.Flags & RedfishAbi.VmWriteProtected) != 0, (value.Flags & RedfishAbi.VmInsertAction) != 0, (value.Flags & RedfishAbi.VmEjectAction) != 0) { InsertedKnown = (value.Flags & RedfishAbi.VmInsertedPresent) != 0 };
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readMedia").ConfigureAwait(false);
    }

    public async Task InsertVirtualMediaAsync(string mediaUri, string image, bool writeProtected, uint timeoutMs, CancellationToken cancellation) =>
        _ = await InsertVirtualMediaWithResultAsync(mediaUri, image, writeProtected, timeoutMs, cancellation).ConfigureAwait(false);

    public async Task<RedfishMediaWriteResult> InsertVirtualMediaWithResultAsync(string mediaUri, string image, bool writeProtected,
        uint timeoutMs, CancellationToken cancellation, RedfishTaskPersistenceScope? persistence = null)
    {
        using var media = BcStringPinned.Pin(mediaUri);
        using var imagePinned = BcStringPinned.Pin(image);
        using var budget = new OperationBudget(timeoutMs);
        using var registration = cancellation.Register(budget.Cancel);
        return await MediaWriteAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) => {
            var options = Options(budget.RemainingMilliseconds());
            var insert = new BcRedfishVirtualMediaInsertOptions {
                StructSize = (uint)Marshal.SizeOf<BcRedfishVirtualMediaInsertOptions>(), Image = imagePinned.Value,
                Flags = RedfishAbi.VmWriteProtectedSet, WriteProtected = writeProtected ? 1u : 0u,
            };
            return NativeMethods.bc_redfish_virtual_media_insert(_endpoint, media.Value, ref insert, ref options, completion, userdata, out operation);
        }, "core.mountMedia", budget, cancellation, persistence).ConfigureAwait(false);
    }

    public async Task EjectVirtualMediaAsync(string mediaUri, uint timeoutMs, CancellationToken cancellation) =>
        _ = await EjectVirtualMediaWithResultAsync(mediaUri, timeoutMs, cancellation).ConfigureAwait(false);

    public async Task<RedfishMediaWriteResult> EjectVirtualMediaWithResultAsync(string mediaUri, uint timeoutMs,
        CancellationToken cancellation, RedfishTaskPersistenceScope? persistence = null)
    {
        using var media = BcStringPinned.Pin(mediaUri);
        using var budget = new OperationBudget(timeoutMs);
        using var registration = cancellation.Register(budget.Cancel);
        return await MediaWriteAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) => {
            var options = Options(budget.RemainingMilliseconds());
            return NativeMethods.bc_redfish_virtual_media_eject(_endpoint, media.Value, ref options, completion, userdata, out operation);
        }, "core.ejectMedia", budget, cancellation, persistence).ConfigureAwait(false);
    }

    public readonly record struct ResetCapabilities(uint SupportedResetTypes, string Target);
    public readonly record struct BootState(uint Target, uint Mode, uint Flags, uint SupportedTargets, uint SupportedModes, uint Status);
    public readonly record struct BootApplyResult(uint Flags, BootState? State);
    public readonly record struct PowerResult(uint Flags);
    public async Task<ResetCapabilities?> GetResetCapabilitiesAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync<ResetCapabilities?>((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_get_reset_capabilities(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            if (r.Status == Bc.Unsupported)
                return null;
            Bc.Check(r.Status, "core.readPowerActions", r.HttpStatus);
            var info = NativeMethods.bc_redfish_reset_info_get(op);
            if (info == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.powerSnapshotMissing"));
            var value = Marshal.PtrToStructure<BcRedfishResetInfo>(info);
            return new ResetCapabilities(value.SupportedResetTypes, Text(value.Target));
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readPowerActions").ConfigureAwait(false);
    }

    public async Task<PowerResult> ResetAsync(string uri, uint action, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_reset(_endpoint, pinned.Value, action, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            Bc.Check(r.Status, "core.powerAction");
            return new PowerResult(r.Flags);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.powerAction").ConfigureAwait(false);
    }

    private static BootState ReadBootState(IntPtr operation)
    {
        var info = NativeMethods.bc_redfish_boot_info_get(operation);
        if (info == IntPtr.Zero)
            throw new BcException(Bc.ProtocolError, Loc.T("core.bootSnapshotMissing"));
        var value = Marshal.PtrToStructure<BcRedfishBootInfo>(info);
        return new BootState(value.Boot.Target, value.Boot.Mode, value.Boot.Flags, value.Boot.SupportedTargets, value.SupportedModes, value.Boot.Status);
    }

    public async Task<BootState?> GetBootAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync<BootState?>((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_get_boot(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            if (r.Status == Bc.Unsupported)
                return null;
            Bc.Check(r.Status, "core.readBoot", r.HttpStatus);
            return ReadBootState(op);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readBoot").ConfigureAwait(false);
    }

    public async Task<BootApplyResult?> SetBootOnceAsync(string uri, uint target, uint mode, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync<BootApplyResult?>((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_boot_set_once(_endpoint, pinned.Value, target, mode, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            if (r.Status == Bc.Unsupported)
                return null;
            Bc.Check(r.Status, "core.writeBoot");
            BootState? state = null;
            if (NativeMethods.bc_redfish_boot_info_get(op) != IntPtr.Zero)
                state = ReadBootState(op);
            return new BootApplyResult(r.Flags, state);
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.writeBoot").ConfigureAwait(false);
    }

    public async Task<GraphicalConsoleInfo?> GetGraphicalConsoleAsync(string uri, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return NativeMethods.bc_redfish_get_graphical_console(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var r = SnapshotResult(op, res);
            if (r.Status == Bc.Unsupported)
                return (GraphicalConsoleInfo? )null;
            Bc.Check(r.Status, "core.readGraphicalConsole");
            var info = NativeMethods.bc_redfish_graphical_console_info_get(op);
            if (info == IntPtr.Zero)
                return null;
            var value = Marshal.PtrToStructure<BcRedfishGraphicalConsoleInfo>(info);
            return new GraphicalConsoleInfo((value.Flags & RedfishAbi.ConsoleServiceEnabled) != 0 && value.ServiceEnabled != 0, (value.Flags & RedfishAbi.ConsolePortPresent) != 0 ? value.Port : null, (value.Flags & RedfishAbi.ConsoleSessionsPresent) != 0 ? value.MaxSessions : null, Strings(value.ConnectTypes, value.ConnectTypeCount));
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readGraphicalConsole").ConfigureAwait(false);
    }

    public async Task LogoutAsync(uint timeoutMs, CancellationToken cancellation)
    {
        if (_loggedOut)
            return;
        _loggedOut = true;
        LastLogoutStatus = Bc.OutcomeUnknown;
        var result = await RunAsync<BcRedfishAuthResult>((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) => NativeMethods.bc_redfish_logout(_connection, Math.Max(1, timeoutMs), AuthTrampoline, userdata, out operation), (op, res) =>
        {
            if (res == IntPtr.Zero)
                throw new BcException(Bc.ProtocolError, Loc.T("core.logoutNoResult"));
            var value = Marshal.PtrToStructure<BcRedfishAuthResult>(res);
            LastLogoutStatus = SensorCompatibility.AcceptsLogout(value.HttpStatus, value.ErrorBody) ? Bc.Ok : value.Status;
            value.Status = LastLogoutStatus;
            return value;
        }, null, cancellation, "core.logout").ConfigureAwait(false);
        Bc.Check(result.Status, "core.logout");
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        try
        {
            if (!_loggedOut && IsSessionAuth)
            {
                try
                {
                    await LogoutAsync(LogoutTimeoutMs, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                { /* 注销失败保留未确认状态，由上层标记 */
                }
            }
        }
        finally
        {
            await _runtime.InvokeAsync(() =>
            {
                NativeMethods.bc_redfish_connection_release(_connection);
                NativeMethods.bc_endpoint_release(_endpoint);
                _connection = IntPtr.Zero;
                _endpoint = IntPtr.Zero;
                _disposed = true;
                return 0;
            }).ConfigureAwait(false);
        }
    }
}

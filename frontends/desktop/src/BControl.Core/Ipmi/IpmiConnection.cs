using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Ipmi;
public sealed record IpmiConnectionInfo(uint CipherSuiteId, byte AuthAlgorithm, byte IntegrityAlgorithm, byte ConfidentialityAlgorithm, uint BmcSessionId, uint MaximumPrivilege);
public sealed record IpmiCapabilities(uint CipherSuiteId, uint SdrRecordCount, uint ChassisPowerState, uint SelRecordCount, uint Flags)
{
    public bool AlternateSerialCandidate => (Flags & 32) != 0;
    public FeatureDetection KvmDetection => FeatureDetection.FromProbe(DeviceFeature.Kvm,
        status: (Flags & 16) != 0 ? Bc.Unsupported : Bc.Ok);
    public bool? GraphicalConsole => KvmDetection.State == DetectionState.Unsupported ? false : null;
}
public sealed record IpmiChassisStatus(uint PowerState, uint Flags, byte RawPowerState, uint PowerRestorePolicy);
public sealed class SolUnavailableException(bool disabled) : Exception(Loc.T(disabled ? "sol.disabled" : "sol.unsupported"));
public sealed record SolConfig(bool Enabled, bool ForceAuthentication, bool ForceEncryption, byte Privilege, byte VolatileBitRate, byte NonvolatileBitRate, byte PayloadChannel, byte PayloadVersion, ushort PayloadPort, bool ConfigurationKnown = true);
/// <summary>确认 suite 3 所需的显式用户确认。</summary>
public sealed class Suite3ConfirmationRequiredException : Exception
{
    public Suite3ConfirmationRequiredException() : base(Loc.T("add.suite3Required"))
    {
    }
}

/// <summary>
/// 一个已认证的 RMCP+ 会话。所有 C 调用在专属工作线程上串行执行；
/// SOL 泵运行时占用同一线程（与 C 核心的串行约束一致）。
/// </summary>
public sealed partial class IpmiConnection : IAsyncDisposable
{
    private readonly IntPtr _session;
    private readonly IntPtr _crypto;
    private readonly IntPtr _io;
    private readonly IpmiIoGuard _ioGuard;
    private readonly CancellationTokenSource _operationCancellation;
    private readonly ushort _port;
    private readonly bool _usesProxy;
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly BlockingCollection<WorkItem> _queue = new();
    private readonly Thread _worker;
    private readonly TaskCompletionSource _workerStopped = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _closed;
    private Task? _disposeTask;
    private readonly object _disposeLock = new();
    private SolSession? _activeSol;
    public uint LastCloseStatus { get; private set; } = Bc.Ok;

    private sealed record WorkItem(Func<object?> Invoke, TaskCompletionSource<object?> Done);
    private IpmiConnection(IntPtr session, IntPtr crypto, IntPtr io, ushort port, bool usesProxy, IpmiIoGuard guard, OperationBudget? operation, CancellationToken cancellation)
    {
        _session = session;
        _crypto = crypto;
        _io = io;
        _port = port;
        _usesProxy = usesProxy;
        _ioGuard = guard;
        _operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(_disposeCts.Token,
            operation == null ? CancellationToken.None : cancellation);
        _ioGuard.Configure(operation, _operationCancellation.Token);
        _worker = new Thread(WorkerLoop)
        {
            IsBackground = true,
            Name = "bcontrol-ipmi-session"
        };
        _worker.Start();
    }

    // A supplied operation covers the entire session and must outlive it.
    // Without one, cancellation and the startup budget apply only to opening.
    public static async Task<IpmiConnection> OpenAsync(string host, ushort port, string username, string password, bool suite3Allowed, CancellationToken cancellation = default, Socks5Connection? proxy = null, HostTimeout? timeout = null, OperationBudget? operation = null)
    {
        using var startupBudget = operation == null ? new OperationBudget(timeout?.Milliseconds ?? 15000) : null;
        var budget = operation ?? startupBudget!;
        IpmiIoGuard? guard = null;
        var crypto = IntPtr.Zero;
        var io = IntPtr.Zero;
        var session = IntPtr.Zero;
        try
        {
            return await Task.Run(() =>
            {
                cancellation.ThrowIfCancellationRequested();
                _ = budget.RemainingMilliseconds();
                Bc.Check(NativeMethods.bc_ipmi_openssl_crypto_create(out crypto), "core.createCrypto");
                using var hostPinned = BcStringPinned.Pin(host);
                using var pinnedProxy = proxy?.Pin();
                var ioStatus = pinnedProxy == null
                    ? NativeMethods.bc_ipmi_udp_create_timeout(hostPinned.Value, port, budget.RemainingMilliseconds(), out io)
                    : NativeMethods.bc_ipmi_socks5_create(hostPinned.Value, port, ref pinnedProxy.Value, Math.Min(timeout?.Milliseconds ?? 5000, budget.RemainingMilliseconds()), out io);
                Bc.Check(ioStatus, "core.createUdp");
                guard = new IpmiIoGuard(io, budget, cancellation);
                using var user = BcStringPinned.Pin(username);
                using var pass = BcStringPinned.Pin(password);
                var options = new BcIpmiSessionOptions
                {
                    StructSize = (uint)Marshal.SizeOf<BcIpmiSessionOptions>(),
                    AbiVersion = Bc.AbiVersion,
                    Io = guard.Io,
                    Crypto = crypto,
                    TimeoutMs = timeout?.Milliseconds ?? 3000,
                    Retries = 3,
                    Suite3Policy = suite3Allowed ? IpmiAbi.Suite3Confirmed : IpmiAbi.Suite3Allowed,
                    Username = user.Value,
                    Password = pass.Value,
                };
                Bc.Check(NativeMethods.bc_ipmi_session_create(ref options, out session), "core.createSession");
                var status = NativeMethods.bc_ipmi_session_open(session);
                if (status == Bc.ConfirmationRequired) throw new Suite3ConfirmationRequiredException();

                Bc.Check(status, "core.openSession");
                cancellation.ThrowIfCancellationRequested();
                var connection = new IpmiConnection(session, crypto, io, port, proxy != null, guard, operation, cancellation);
                session = crypto = io = IntPtr.Zero; guard = null;
                return connection;
            }, cancellation).ConfigureAwait(false);
        }
        finally
        {
            if (session != IntPtr.Zero)
            {
                using var cleanup = new OperationBudget(3000);
                guard?.Configure(cleanup, CancellationToken.None);
                NativeMethods.bc_ipmi_session_close(session);
                NativeMethods.bc_ipmi_session_destroy(session);
            }

            guard?.Dispose();
            if (io != IntPtr.Zero)
                DestroyIo(io, proxy != null);
            if (crypto != IntPtr.Zero)
                NativeMethods.bc_ipmi_openssl_crypto_destroy(crypto);
        }
    }

    private static void DestroyIo(IntPtr io, bool usesProxy)
    {
        if (usesProxy) NativeMethods.bc_ipmi_socks5_destroy(io);
        else NativeMethods.bc_ipmi_udp_destroy(io);
    }

    private void WorkerLoop()
    {
        try
        {
            foreach (var item in _queue.GetConsumingEnumerable())
            {
                if (_disposeCts.IsCancellationRequested)
                {
                    item.Done.TrySetCanceled();
                    continue;
                }

                try
                {
                    _ioGuard.EnsureAvailable();
                    item.Done.TrySetResult(item.Invoke());
                }
                catch (Exception ex)
                {
                    item.Done.TrySetException(ex);
                }
            }
        }
        finally
        {
            _workerStopped.TrySetResult();
        }
    }

    private Task<T> EnqueueWork<T>(Func<T> work)
    {
        ObjectDisposedException.ThrowIf(_closed != 0, this);
        if (_activeSol?.PumpActive == true)
            throw new BcException(Bc.Busy, Bc.StatusText(Bc.Busy));
        var done = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _queue.Add(new WorkItem(() => work(), done));
        return Await<T>(done);
    }

    private static async Task<T> Await<T>(TaskCompletionSource<object?> done) => (T)(await done.Task.ConfigureAwait(false))!;
    public Task<IpmiConnectionInfo> GetInfoAsync() => EnqueueWork(() =>
    {
        var info = Marshal.PtrToStructure<BcIpmiSessionInfo>(NativeMethods.bc_ipmi_session_info_get(_session));
        return new IpmiConnectionInfo(info.CipherSuiteId, info.AuthAlgorithm, info.IntegrityAlgorithm, info.ConfidentialityAlgorithm, info.BmcSessionId, info.MaximumPrivilege);
    });
    public Task<IpmiCapabilities> ProbeAsync() => EnqueueWork(() =>
    {
        var caps = new BcIpmiCapabilities
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiCapabilities>()
        };
        Bc.Check(NativeMethods.bc_ipmi_session_probe(_session, ref caps), "core.probeCapabilities");
        return new IpmiCapabilities(caps.CipherSuiteId, caps.SdrRecordCount, caps.ChassisPowerState, caps.SelRecordCount, caps.Flags);
    });
    public Task<IpmiChassisStatus> GetChassisStatusAsync() => EnqueueWork(() =>
    {
        var status = new BcIpmiChassisStatus
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiChassisStatus>()
        };
        Bc.Check(NativeMethods.bc_ipmi_chassis_status_get(_session, ref status), "core.readChassis");
        return new IpmiChassisStatus(status.PowerState, status.Flags, status.RawPowerState, status.PowerRestorePolicy);
    });
    public Task<SolConfig?> GetSolConfigAsync() => EnqueueWork<SolConfig?>(() =>
    {
        var config = new BcIpmiSolConfig
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiSolConfig>()
        };
        var status = NativeMethods.bc_ipmi_sol_config_get(_session, ref config, out var completion);
        if (SerialNative.bc_serial_fallback_allowed(status, completion) != 0)
            return null;
        Bc.Check(status, "core.readSolConfig");
        return new SolConfig(config.Enabled != 0, config.ForceAuthentication != 0, config.ForceEncryption != 0, config.Privilege, config.VolatileBitRate, config.NonvolatileBitRate, config.PayloadChannel, config.PayloadVersion, config.PayloadPort, config.Enabled != 2);
    });
    public async Task<SolSession> OpenSolAsync(byte instance = 1, CancellationToken cancellation = default)
    {
        var sol = await EnqueueWork(() =>
        {
            var options = new BcIpmiSolOptions
            {
                StructSize = (uint)Marshal.SizeOf<BcIpmiSolOptions>(),
                AbiVersion = Bc.AbiVersion,
                ReceiveCapacity = 8192,
                SendCapacity = 8192,
                RetryIntervalMs = 500,
                Retries = 3,
                KeepaliveMs = 15000,
                Instance = instance,
                SessionPort = _port,
            };
            var status = NativeMethods.bc_ipmi_sol_open(_session, ref options, NowMs(), out var handle);
            // 失败也可能返回非空对象，必须 close/destroy 清理。
            if (status != Bc.Ok)
            {
                var info = new BcIpmiSolInfo { StructSize = (uint)Marshal.SizeOf<BcIpmiSolInfo>() };
                if (handle != IntPtr.Zero)
                {
                    NativeMethods.bc_ipmi_sol_info_get(handle, ref info);
                    NativeMethods.bc_ipmi_sol_close(handle);
                    var closed = new BcIpmiSolInfo { StructSize = (uint)Marshal.SizeOf<BcIpmiSolInfo>() };
                    var infoStatus = NativeMethods.bc_ipmi_sol_info_get(handle, ref closed);
                    NativeMethods.bc_ipmi_sol_destroy(handle);
                    Bc.Check(infoStatus, "core.activateSol");
                    Bc.Check(closed.CleanupStatus, "core.activateSol");
                }

                if (SerialNative.bc_serial_fallback_allowed(status, info.CompletionCode) != 0)
                    throw new SolUnavailableException(info.CompletionCode == 0x81);
                Bc.Check(status, "core.activateSol");
            }

            return handle;
        }).ConfigureAwait(false);
        try { return _activeSol = new SolSession(this, sol, _disposeCts.Token); }
        catch { await CloseSolAsync(sol).ConfigureAwait(false); throw; }
    }

    internal Task CloseSolAsync(IntPtr sol) => EnqueueWork<object?>(() =>
    {
        NativeMethods.bc_ipmi_sol_close(sol);
        NativeMethods.bc_ipmi_sol_destroy(sol);
        return null;
    });
    internal static ulong NowMs() => (ulong)(Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency);
    public ValueTask DisposeAsync()
    {
        lock (_disposeLock)
            return new ValueTask(_disposeTask ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        if (_activeSol != null)
            await _activeSol.DisposeAsync().ConfigureAwait(false);
        Interlocked.Exchange(ref _closed, 1);
        _disposeCts.Cancel();
        _queue.CompleteAdding();
        await _workerStopped.Task.ConfigureAwait(false);
        await Task.Run(() =>
        {
            using var cleanup = new OperationBudget(3000);
            _ioGuard.Configure(cleanup, CancellationToken.None);
            LastCloseStatus = NativeMethods.bc_ipmi_session_close(_session);
            NativeMethods.bc_ipmi_session_destroy(_session);
            _ioGuard.Dispose();
            DestroyIo(_io, _usesProxy);
            NativeMethods.bc_ipmi_openssl_crypto_destroy(_crypto);
        }).ConfigureAwait(false);
        _operationCancellation.Dispose();
    }
}

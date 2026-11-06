using System.Runtime.InteropServices;
using BControl.Core.Localization;
using BControl.Core.Native;
using SensorReadingInfo = BControl.Core.Redfish.RedfishSession.SensorReadingInfo;

namespace BControl.Core.Redfish;
/// <summary>添加向导的只读探测与首页概况读取；超时/取消/注销语义与 Swift ProbeRun 一致。</summary>
public static class DiscoveryService
{
    public const uint DefaultBudgetMs = 15000;
    public const uint RequestTimeoutMs = 5000;
    public sealed record ProbeResult(IReadOnlyList<DiscoveredSystem> Systems, uint AuthenticationFlags, uint LogoutStatus);
    public static Task<ProbeResult> ProbeAsync(string address, DeviceCredential credential, string caFile = "", uint certPolicy = Bc.CertStrict, CancellationToken cancellation = default, uint budgetMilliseconds = DefaultBudgetMs, IProgress<string>? progress = null, uint tlsMin = 12, Socks5Connection? proxy = null, HostTimeout? timeout = null) => RunSessionAsync(address, credential, caFile, certPolicy, cancellation, budgetMilliseconds, progress, async (session, remaining, ct) =>
    {
        var paths = await session.DiscoverSystemsAsync(Math.Min(session.RequestTimeoutMs, remaining(null)), ct).ConfigureAwait(false);
        var systems = new List<DiscoveredSystem>();
        foreach (var path in paths)
        {
            EnsureBudget(remaining, ct);
            progress?.Report(Loc.F("add.readingSystem", ("uri", path)));
            systems.Add((await session.GetSystemAsync(path, Math.Min(session.RequestTimeoutMs, remaining(null)), ct).ConfigureAwait(false)).System);
        }

        return new ProbeResult(systems, session.AuthenticationFlags, session.LastLogoutStatus);
    }, tlsMin, proxy, timeout);
    public static Task<DeviceOverview> OverviewAsync(string address, DeviceCredential credential, string systemUri, string caFile = "", uint certPolicy = Bc.CertStrict, CancellationToken cancellation = default, uint? budgetMilliseconds = null, uint tlsMin = 12, Socks5Connection? proxy = null, HostTimeout? timeout = null) => RunSessionAsync(address, credential, caFile, certPolicy, cancellation, budgetMilliseconds ?? DefaultBudgetMs, null, (session, remaining, ct) => ReadOverviewAsync(session, systemUri, remaining, ct), tlsMin, proxy, timeout, budgetMilliseconds);
    public sealed record ControlSnapshot(RedfishSession.ResetCapabilities? Power, RedfishSession.BootState? Boot, uint AuthenticationFlags);
    public static Task<ControlSnapshot> ReadControlsAsync(string address, DeviceCredential credential, string systemUri, string caFile = "", uint certPolicy = Bc.CertStrict, CancellationToken cancellation = default, uint budgetMilliseconds = DefaultBudgetMs, uint tlsMin = 12, Socks5Connection? proxy = null, HostTimeout? timeout = null) => RunSessionAsync(address, credential, caFile, certPolicy, cancellation, budgetMilliseconds, null, async (session, remaining, ct) =>
    {
        systemUri = await ResolveSystemAsync(session, systemUri, remaining, ct).ConfigureAwait(false);
        var power = await session.GetResetCapabilitiesAsync(systemUri, Math.Min(session.RequestTimeoutMs, remaining(null)), ct).ConfigureAwait(false);
        EnsureBudget(remaining, ct);
        var boot = await session.GetBootAsync(systemUri, Math.Min(session.RequestTimeoutMs, remaining(null)), ct).ConfigureAwait(false);
        return new ControlSnapshot(power, boot, session.AuthenticationFlags);
    }, tlsMin, proxy, timeout);
    public static Task<uint> PowerAsync(string address, DeviceCredential credential, string systemUri, uint action, string caFile = "", uint certPolicy = Bc.CertStrict, CancellationToken cancellation = default, uint budgetMilliseconds = DefaultBudgetMs, uint tlsMin = 12, Socks5Connection? proxy = null, HostTimeout? timeout = null) => RunSessionAsync(address, credential, caFile, certPolicy, cancellation, budgetMilliseconds, null, async (session, remaining, ct) =>
    {
        systemUri = await ResolveSystemAsync(session, systemUri, remaining, ct).ConfigureAwait(false);
        return (await session.ResetAsync(systemUri, action, Math.Min(session.RequestTimeoutMs, remaining(null)), ct).ConfigureAwait(false)).Flags;
    }, tlsMin, proxy, timeout);
    public static Task<RedfishSession.BootApplyResult?> SetBootOnceAsync(string address, DeviceCredential credential, string systemUri, uint target, uint mode, string caFile = "", uint certPolicy = Bc.CertStrict, CancellationToken cancellation = default, uint budgetMilliseconds = DefaultBudgetMs, uint tlsMin = 12, Socks5Connection? proxy = null, HostTimeout? timeout = null) => RunSessionAsync(address, credential, caFile, certPolicy, cancellation, budgetMilliseconds, null, async (session, remaining, ct) =>
    {
        systemUri = await ResolveSystemAsync(session, systemUri, remaining, ct).ConfigureAwait(false);
        return await session.SetBootOnceAsync(systemUri, target, mode, Math.Min(session.RequestTimeoutMs, remaining(null)), ct).ConfigureAwait(false);
    }, tlsMin, proxy, timeout);
    internal static async Task<string> ResolveSystemAsync(RedfishSession session, string systemUri, Func<uint?, uint> remaining, CancellationToken cancellation)
    {
        if (!string.IsNullOrEmpty(systemUri))
            return systemUri;
        EnsureBudget(remaining, cancellation);
        var systems = await session.DiscoverSystemsAsync(Math.Min(session.RequestTimeoutMs, remaining(null)), cancellation).ConfigureAwait(false);
        if (systems.Count != 1)
            throw new OverviewException(OverviewProblem.SelectionRequired);
        return systems[0];
    }

    private static void EnsureBudget(Func<uint?, uint> remaining, CancellationToken cancellation)
    {
        if (cancellation.IsCancellationRequested)
            throw new DiscoveryFailure(Bc.Cancelled, 0, 0);
        if (remaining(null) == 0)
            throw new DiscoveryFailure(Bc.Timeout, 0, 0);
    }

    internal static async Task<TResult> RunSessionAsync<TResult>(string address, DeviceCredential credential, string caFile, uint certPolicy, CancellationToken cancellation, uint budgetMs, IProgress<string>? progress, Func<RedfishSession, Func<uint?, uint>, CancellationToken, Task<TResult>> body, uint tlsMin = 12, Socks5Connection? proxy = null, HostTimeout? timeout = null, uint? budgetLimitMilliseconds = null)
    {
        var budget = Math.Min(timeout?.Milliseconds ?? budgetMs, budgetLimitMilliseconds ?? uint.MaxValue);
        if (budget == 0) throw new DiscoveryFailure(Bc.Timeout, 0, 0);
        using var operation = new OperationBudget(budget);
        var requestedCancellation = cancellation;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromMilliseconds(budget));
        cancellation = deadline.Token;
        using var registration = requestedCancellation.Register(operation.Cancel);
        var runtime = RedfishRuntime.Create();
        RedfishSession? session = null;
        try
        {
            uint Remaining(uint? limit = null)
            {
                var remaining = operation.RemainingMilliseconds();
                return limit.HasValue ? Math.Min(remaining, limit.Value) : remaining;
            }

            EnsureBudget(Remaining, cancellation);
            progress?.Report(Loc.T("add.authenticating"));
            session = await RedfishSession.LoginAsync(runtime, address, credential, caFile, certPolicy, Math.Min(timeout?.Milliseconds ?? RequestTimeoutMs, Remaining(null)), cancellation, tlsMin, proxy).ConfigureAwait(false);
            session.RequestTimeoutMs = timeout?.Milliseconds ?? RequestTimeoutMs;
            TResult result;
            try
            {
                result = await body(session, Remaining, cancellation).ConfigureAwait(false);
            }
            finally
            {
                using var cleanup = new OperationBudget(RedfishSession.LogoutTimeoutMs);
                using var cleanupCancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(RedfishSession.LogoutTimeoutMs));
                try
                {
                    await session.LogoutAsync(cleanup.RemainingMilliseconds(), cleanupCancellation.Token).ConfigureAwait(false);
                }
                catch (BcException ex)
                {
                    session.LastLogoutStatus = ex.Status;
                }
                catch (OperationCanceledException)
                {
                    session.LastLogoutStatus = Bc.Timeout;
                }
                catch
                {
                    session.LastLogoutStatus = Bc.ProtocolError;
                }
            }

            if (session.LastLogoutStatus != Bc.Ok && result is not DeviceOverview && result is not ProbeResult && result is not Ipmi.ManagementSnapshot)
                throw new DiscoveryFailure(Bc.OutcomeUnknown, 0, session.AuthenticationFlags, session.LastLogoutStatus);
            return result switch
            {
                DeviceOverview overview => (TResult)(object)(overview with
                {
                    LogoutStatus = session.LastLogoutStatus
                }

                ),
                ProbeResult probe => (TResult)(object)(probe with
                {
                    LogoutStatus = session.LastLogoutStatus
                }

                ),
                Ipmi.ManagementSnapshot management => (TResult)(object)(management with
                {
                    LogoutStatus = session.LastLogoutStatus
                }

                ),
                _ => result,
            };
        }
        catch (DiscoveryFailure error) when (error.Status == Bc.Cancelled && deadline.IsCancellationRequested && !requestedCancellation.IsCancellationRequested)
        {
            throw new DiscoveryFailure(Bc.Timeout, error.HttpStatus, error.AuthenticationFlags, error.CleanupStatus);
        }
        catch (BcException error) when (error.Status == Bc.Timeout ||
            (error.Status == Bc.Cancelled && deadline.IsCancellationRequested && !requestedCancellation.IsCancellationRequested))
        {
            throw new DiscoveryFailure(Bc.Timeout, error.HttpStatus, session?.AuthenticationFlags ?? 0, session?.LastLogoutStatus);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !requestedCancellation.IsCancellationRequested)
        {
            throw new DiscoveryFailure(Bc.Timeout, 0, session?.AuthenticationFlags ?? 0, session?.LastLogoutStatus);
        }
        finally
        {
            if (session != null)
                await session.DisposeAsync().ConfigureAwait(false);
            await runtime.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task<DeviceOverview> ReadOverviewAsync(RedfishSession session, string systemUri, Func<uint?, uint> remaining, CancellationToken cancellation)
    {
        var paths = await session.DiscoverSystemsAsync(Math.Min(session.RequestTimeoutMs, remaining(null)), cancellation).ConfigureAwait(false);
        string selected;
        if (string.IsNullOrEmpty(systemUri))
        {
            if (paths.Count != 1)
                throw new OverviewException(OverviewProblem.SelectionRequired);
            selected = paths[0];
        }
        else
        {
            if (!paths.Contains(systemUri))
                throw new OverviewException(OverviewProblem.SelectionRequired);
            selected = systemUri;
        }

        var snapshot = await session.GetSystemAsync(selected, Math.Min(session.RequestTimeoutMs, remaining(null)), cancellation).ConfigureAwait(false);
        var observed = DateTimeOffset.UtcNow;
        uint status = snapshot.ContextStatus;
        var owned = new List<SensorReadingInfo>();
        var shared = new List<SensorReadingInfo>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var chassisPaths = snapshot.Chassis;
        if (status == Bc.Ok && chassisPaths.Count == 0)
            status = Bc.Unsupported;
        foreach (var chassisUri in chassisPaths)
        {
            try
            {
                var(systems, sensorCollection, ctxStatus) = await session.GetChassisAsync(chassisUri, Math.Min(session.RequestTimeoutMs, remaining(null)), cancellation).ConfigureAwait(false);
                if (ctxStatus != Bc.Ok)
                {
                    if (status == Bc.Ok)
                        status = ctxStatus;
                    continue;
                }

                if (systems.Count > 0 && !systems.Any(s => Belongs(s, selected))) continue;
                if (string.IsNullOrEmpty(sensorCollection))
                {
                    var chassis = await session.GetResourceAsync(chassisUri, Math.Min(session.RequestTimeoutMs, remaining(null)), cancellation);
                    var fallback = await LegacySensors.TemperaturesAsync(chassis, uri => session.GetResourceAsync(uri, Math.Min(session.RequestTimeoutMs, remaining(null)), cancellation));
                    var isExclusive = (systems.Count == 1 && systems[0] == selected) || (systems.Count == 0 && paths.Count == 1);
                    var otherSystems = paths.Concat(systems).Where(s => s != selected).ToArray();
                    foreach (var sensor in fallback)
                    {
                        if (!seen.Add(sensor.Uri)) continue;
                        if (seen.Count > 256) { status = Bc.LimitExceeded; return Build(); }
                        var own = sensor.RelatedItems.Any(r => Belongs(r, selected)) || (isExclusive && sensor.RelatedItems.Count == 0);
                        var foreign = sensor.RelatedItems.Any(r => otherSystems.Any(s => Belongs(r, s)));
                        if (foreign && !own) continue;
                        if (foreign || !own) shared.Add(sensor with { TemperatureFlags = sensor.TemperatureFlags & ~16u });
                        else owned.Add(sensor);
                    }
                    if (!LegacySensors.Advertised(chassis) && status == Bc.Ok)
                        status = Bc.Unsupported;
                    continue;
                }

                var exclusive = (systems.Count == 1 && systems[0] == selected) || (systems.Count == 0 && paths.Count == 1);
                var others = new HashSet<string>(paths.Concat(systems), StringComparer.Ordinal);
                others.Remove(selected);
                var members = await session.GetCollectionAsync(sensorCollection, RedfishAbi.CollectionSensors, Math.Min(session.RequestTimeoutMs, remaining(null)), cancellation).ConfigureAwait(false);
                foreach (var uri in members)
                {
                    if (!seen.Add(uri))
                        continue;
                    if (seen.Count > 256)
                    {
                        if (status == Bc.Ok)
                            status = Bc.LimitExceeded;
                        return Build();
                    }

                    try
                    {
                        EnsureBudget(remaining, cancellation);
                        var sensor = await session.GetSensorAsync(uri, Math.Min(session.RequestTimeoutMs, remaining(null)), cancellation).ConfigureAwait(false);
                        var own = sensor.RelatedItems.Any(r => Belongs(r, selected)) || (exclusive && sensor.RelatedItems.Count == 0);
                        var foreign = sensor.RelatedItems.Any(r => others.Any(o => Belongs(r, o)));
                        if (foreign && !own)
                            continue;
                        var common = foreign || !own;
                        if (common)
                            shared.Add(sensor with { TemperatureFlags = sensor.TemperatureFlags & ~16u });
                        else
                            owned.Add(sensor);
                    }
                    catch (DiscoveryFailure failure)
                    {
                        if (status == Bc.Ok)
                            status = failure.Status;
                        if (failure.Status is Bc.Cancelled or Bc.Timeout || failure.HttpStatus is 401 or 403)
                            return Build();
                    }
                    catch (BcException ex)
                    {
                        if (status == Bc.Ok)
                            status = ex.Status;
                    }
                }
            }
            catch (DiscoveryFailure failure)
            {
                if (status == Bc.Ok)
                    status = failure.Status;
                if (failure.Status is Bc.Cancelled or Bc.Timeout)
                    return Build();
            }
            catch (BcException ex)
            {
                if (status == Bc.Ok)
                    status = ex.Status;
            }
        }

        return Build();
        DeviceOverview Build() => new(snapshot.System, observed, Summarize(owned), Summarize(shared), status, session.AuthenticationFlags, session.LastLogoutStatus);
    }

    private static bool Belongs(string resource, string system) => resource == system || resource.StartsWith(system + "/", StringComparison.Ordinal) || resource.StartsWith(system + "#", StringComparison.Ordinal);
    private static TemperatureSummary Summarize(IReadOnlyList<SensorReadingInfo> sensors)
    {
        if (sensors.Count == 0)
            return new TemperatureSummary(null, null, null);
        var readings = new BcTemperatureReading[sensors.Count];
        for (var i = 0; i < sensors.Count; i++)
        {
            var flags = sensors[i].TemperatureFlags;
            // Celsius 换算已由核心的 sensor_temperature_reading 完成；单位标志保持原样。
            readings[i] = new BcTemperatureReading
            {
                Value = sensors[i].Celsius,
                Unit = sensors[i].UnitCode,
                Flags = flags
            };
        }

        var summary = new BcTemperatureSummary
        {
            StructSize = (uint)Marshal.SizeOf<BcTemperatureSummary>()
        };
        var status = NativeMethods.bc_temperature_summarize(readings, (uint)readings.Length, ref summary);
        if (status != Bc.Ok)
            return new TemperatureSummary(null, null, null);
        TemperaturePoint? Point(uint index, double celsius)
        {
            if (index == uint.MaxValue || index >= sensors.Count)
                return null;
            var sensor = sensors[(int)index];
            return new TemperaturePoint(sensor.Uri, sensor.Name, sensor.Units, sensor.Reading, celsius, sensor.Health, string.IsNullOrEmpty(sensor.ReadingTime) ? null : sensor.ReadingTime, false);
        }

        return new TemperatureSummary(Point(summary.CpuIndex, summary.CpuCelsius), Point(summary.NormalIndex, summary.NormalCelsius), Point(summary.AlertIndex, summary.AlertCelsius))
        { Primary = TemperatureSummary.Select(readings, Point) };
    }
}

public enum OverviewProblem
{
    SelectionRequired,
    Unsupported,
    SessionUnconfirmed,
    CredentialsUnavailable
}

public sealed class OverviewException : Exception
{
    public OverviewProblem Problem { get; }

    public OverviewException(OverviewProblem problem) : base(problem.ToString()) => Problem = problem;
}

using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Redfish;
public sealed record DeviceCredential(string Username, string Password);
public sealed record DiscoveredSystem(string Uri, string Name, string Manufacturer, string Model, string HostName, uint PowerState, string RawPowerState)
{
    public bool? GraphicalConsole { get; init; }
    public string SerialNumber { get; init; } = "";
    public string Uuid { get; init; } = "";
}

public sealed record TemperaturePoint(string Uri, string Name, string Unit, double Reading, double Celsius, string Health, string? ReadingTime, bool Retained)
{
    public bool ChassisFallback { get; init; }
}
public sealed record TemperatureSummary(TemperaturePoint? Cpu, TemperaturePoint? NormalMaximum, TemperaturePoint? AlertMaximum)
{
    public TemperaturePoint? Primary { get; init; }
    internal static TemperaturePoint? Select(BcTemperatureReading[] readings, Func<uint, double, TemperaturePoint?> point)
    {
        var selection = new BcTemperatureSelection { StructSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<BcTemperatureSelection>() };
        Bc.Check(NativeMethods.bc_temperature_select(readings, (uint)readings.Length, ref selection), "overview.primaryTemperature");
        return point(selection.Index, selection.Celsius) is { } value ? value with { ChassisFallback = (selection.Flags & 1) != 0 } : null;
    }
    public TemperatureSummary RetainMissingFrom(TemperatureSummary? previous)
    {
        TemperaturePoint? Retain(TemperaturePoint? current, TemperaturePoint? prior) => current ?? (prior is { } p ? p with
        {
            Retained = true
        }

        : null);
        previous ??= new TemperatureSummary(null, null, null);
        return new TemperatureSummary(Retain(Cpu, previous.Cpu), Retain(NormalMaximum, previous.NormalMaximum), Retain(AlertMaximum, previous.AlertMaximum))
        { Primary = Retain(Primary, previous.Primary ?? previous.Cpu) };
    }
}

public sealed record DeviceOverview(DiscoveredSystem System, DateTimeOffset ObservedAt, TemperatureSummary Temperatures, TemperatureSummary SharedTemperatures, uint TemperatureStatus, uint AuthenticationFlags, uint LogoutStatus)
{
    public DeviceOverview RetainMissingTemperaturesFrom(DeviceOverview? previous)
    {
        if (TemperatureStatus == Bc.Ok || previous == null)
            return this;
        return this with
        {
            Temperatures = Temperatures.RetainMissingFrom(previous.Temperatures),
            SharedTemperatures = SharedTemperatures.RetainMissingFrom(previous.SharedTemperatures),
        };
    }
}

public sealed record VirtualMediaDevice(string Uri, string Id, string Name, string? Image, string? ImageName, string? ConnectedVia, IReadOnlyList<string> MediaTypes, bool Inserted, bool WriteProtected, bool CanInsert, bool CanEject)
{
    public bool InsertedKnown { get; init; } = true;
    public bool HasManagedSource { get; init; }
    public BControl.Core.Storage.RemoteMediaSourceVerification SourceVerification { get; init; }
    public bool SourceUnverified => InsertedKnown && Inserted && !SourceMismatch && (string.IsNullOrEmpty(Image) || HasManagedSource &&
        SourceVerification is BControl.Core.Storage.RemoteMediaSourceVerification.Unknown or BControl.Core.Storage.RemoteMediaSourceVerification.Unverified);
    public bool SourceMismatch => Inserted && HasManagedSource && SourceVerification == BControl.Core.Storage.RemoteMediaSourceVerification.Mismatch;
    public string DisplayImage => !string.IsNullOrEmpty(Image) ? Image : !string.IsNullOrEmpty(ImageName) ? ImageName
        : !InsertedKnown ? Loc.T("common.unknown") : Inserted ? Loc.T("media.mounted") : Loc.T("media.notMounted");
}

public sealed record GraphicalConsoleInfo(bool ServiceEnabled, uint? Port, uint? MaxSessions, IReadOnlyList<string> ConnectTypes);
public sealed class DiscoveryFailure : Exception
{
    public uint Status { get; }
    public uint HttpStatus { get; }
    public uint AuthenticationFlags { get; }
    public uint? CleanupStatus { get; }

    public DiscoveryFailure(uint status, uint httpStatus, uint authenticationFlags, uint? cleanupStatus = null) : base(Describe(status, httpStatus, authenticationFlags, cleanupStatus))
    {
        Status = status;
        HttpStatus = httpStatus;
        AuthenticationFlags = authenticationFlags;
        CleanupStatus = cleanupStatus;
    }

    private static string Describe(uint status, uint http, uint flags, uint? cleanup)
    {
        var message = status switch
        {
            Bc.Cancelled => Loc.T("error.cancelled"),
            Bc.Timeout => Loc.T("error.deviceTimeout"),
            Bc.TlsError => Loc.T("error.tls"),
            _ => http is 401 or 403 ? Loc.T("error.auth") : Loc.F("error.context", ("what", Loc.T("error.probeFailed")), ("detail", Loc.Instance.Status(status))),
        };
        if ((flags & RedfishAbi.AuthSessionMayExist) != 0 || (cleanup.HasValue && cleanup.Value != Bc.Ok))
            message = Loc.F("error.joinDetail", ("message", message), ("detail", Loc.T("error.sessionMayExist")));
        return message;
    }
}

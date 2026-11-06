using System.Runtime.InteropServices;
using System.Text;
using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Core.Redfish;

namespace BControl.Core.Ipmi;
public sealed record IpmiSensor(byte Number, byte Type, string Name, string Units, double? Reading, uint Health, uint DiscreteStates, uint DiscreteValidMask, uint Status)
{
    public byte EntityId { get; init; }
    public IReadOnlyList<ManagementField> Details { get; init; } = Array.Empty<ManagementField>();
}

public sealed record IpmiSensors(IReadOnlyList<IpmiSensor> Sensors, uint Status, bool Truncated);
public sealed partial class IpmiConnection
{
    private static void CheckCompletion(uint status, byte completion, string key)
    {
        Bc.Check(status, key);
        if (completion != 0)
            throw new BcException(completion == 0xD4 ? Bc.AuthenticationFailed : Bc.ProtocolError, Loc.F("manage.ipmi.completion", ("message", Loc.T(key)), ("code", $"0x{completion:X2}")));
    }

    private static RedfishSession.BootState BootState(BcIpmiBootInfo info) => new(info.Boot.Target, info.Boot.Mode, info.Boot.Flags, info.Boot.SupportedTargets, 6, info.Boot.Status);
    public Task<RedfishSession.BootState?> GetBootAsync() => EnqueueWork<RedfishSession.BootState?>(() =>
    {
        var info = new BcIpmiBootInfo
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiBootInfo>()
        };
        var status = IpmiManagementNative.bc_ipmi_boot_get(_session, ref info, out var completion);
        if (status == Bc.Unsupported || completion is 0xC1 or 0x80)
            return null;
        CheckCompletion(status, completion, "core.readBoot");
        return BootState(info);
    });
    public Task<uint> GetPowerActionsAsync() => EnqueueWork(() =>
    {
        var info = new BcIpmiChassisCapabilities
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiChassisCapabilities>(),
            AbiVersion = Bc.AbiVersion,
        };
        var status = IpmiManagementNative.bc_ipmi_chassis_capabilities_get(_session, ref info);
        if (status is Bc.Timeout or Bc.Cancelled)
            Bc.Check(status, "core.probeCapabilities");
        // Chassis Control is standard; only diagnostic interrupt needs capability evidence.
        var mask = (1u << 0) | (1u << 1) | (1u << 2) | (1u << 4) | (1u << 8);
        if (status == Bc.Ok && (info.Flags & 4) != 0)
            mask |= 1u << 5;
        return mask;
    });
    public Task PowerAsync(uint action) => EnqueueWork<object?>(() =>
    {
        byte command = action switch
        {
            0 => 1,
            1 => 0,
            2 => 5,
            4 => 3,
            5 => 4,
            8 => 2,
            _ => throw new ArgumentOutOfRangeException(nameof(action))};
        CheckCompletion(IpmiManagementNative.bc_ipmi_chassis_control(_session, command, out var completion), completion, "core.powerAction");
        return null;
    });
    public Task<RedfishSession.BootApplyResult?> SetBootOnceAsync(uint target, uint mode) => EnqueueWork<RedfishSession.BootApplyResult?>(() =>
    {
        var result = new BcIpmiBootResult
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiBootResult>()
        };
        var status = IpmiManagementNative.bc_ipmi_boot_set_once_guarded(_session, target, mode, _ioGuard.Handle, ref result);
        CheckCompletion(status, result.Completion, "core.writeBoot");
        if (result.CleanupStatus != Bc.Ok)
            throw new BcException(result.CleanupStatus, Loc.T("error.sessionMayExist"));
        return new RedfishSession.BootApplyResult((result.Flags & 2) != 0 ? RedfishAbi.BootVerified : 0, result.VerifyStatus == Bc.Ok ? BootState(result.After) : null);
    });
    private static IReadOnlyList<ManagementField> SensorDetails(BcSensorDetails details)
    {
        var keys = new[]
        {
            "lowerCaution",
            "lowerCritical",
            "lowerFatal",
            "upperCaution",
            "upperCritical",
            "upperFatal"
        };
        var fields = new List<ManagementField>();
        for (var index = 0; index < 6; index++)
        {
            var available = (details.ThresholdMask & (1u << index)) != 0;
            var state = details.ThresholdFields[index];
            if (available || state.Status != Bc.Ok)
                fields.Add(new(Loc.T("manage.redfish.threshold." + keys[index]), available ? details.Thresholds[index].ToString("G", System.Globalization.CultureInfo.CurrentCulture) : Bc.StatusText(state.Status)));
        }

        return fields;
    }

    public Task<IpmiSensors> GetSensorsAsync(CancellationToken cancellation = default, bool temperaturesOnly = false) => EnqueueWork(() =>
    {
        var catalog = new BcIpmiSensorCatalog
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiSensorCatalog>(),
            AbiVersion = Bc.AbiVersion,
        };
        var status = IpmiManagementNative.bc_ipmi_sensor_catalog_get(_session, ref catalog);
        if (status != Bc.Ok && status != Bc.LimitExceeded)
            Bc.Check(status, "manage.ipmi.tab.sensors");
        var sensors = new List<IpmiSensor>();
        foreach (var item in catalog.Sensors.Take((int)Math.Min(catalog.Count, 256)))
        {
            cancellation.ThrowIfCancellationRequested();
            if (temperaturesOnly && item.Sensor.Type != 1)
                continue;
            var descriptor = item;
            var details = new BcSensorDetails
            {
                StructSize = (uint)Marshal.SizeOf<BcSensorDetails>(),
                AbiVersion = Bc.AbiVersion
            };
            var current = IpmiManagementNative.bc_ipmi_sensor_details_get(_session, ref descriptor, ref details);
            if (status == Bc.Ok && current != Bc.Ok)
                status = current;
            var end = Array.IndexOf(item.Name, (byte)0);
            sensors.Add(new IpmiSensor(item.Sensor.Number, item.Sensor.Type, Encoding.UTF8.GetString(item.Name, 0, end < 0 ? item.Name.Length : end), RedfishSession.Text(details.Units), (details.Flags & 1) != 0 ? details.Reading : null, details.Health, details.DiscreteStates, details.DiscreteValidMask, current) { EntityId = item.Sensor.EntityId, Details = SensorDetails(details), });
        }

        return new IpmiSensors(sensors, status, (catalog.Flags & 1) != 0);
    });
}

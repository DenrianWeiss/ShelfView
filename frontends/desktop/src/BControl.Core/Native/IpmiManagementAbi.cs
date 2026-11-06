using System.Runtime.InteropServices;

namespace BControl.Core.Native;
[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiBootInfo
{
    public uint StructSize;
    public BcBootInfo Boot;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Raw;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiBootResult
{
    public uint StructSize, Flags, WriteStatus, CleanupStatus, VerifyStatus;
    public byte Completion, CleanupCompletion;
    public ushort Reserved;
    public BcIpmiBootInfo Before, After;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSensorRecord
{
    public uint Flags;
    public byte Number, Type, EventType, EntityId, EntityInstance, OwnerId, OwnerLun;
    public byte Linearization, AnalogFormat, UnitBase, UnitModifierType, UnitRate, UnitModifier, UnitPercentage;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
    public byte[] Units;
    public int M, B, K1, K2;
    public uint Accuracy;
    public byte Nominal, NormalMax, NormalMin, SensorMax, SensorMin;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public byte[] RawThresholds;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public double[] Thresholds;
    public uint ThresholdMask;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)]
    public byte[] Id;
    public byte IdLength;
    public ushort Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSensorDescriptor
{
    public uint StructSize, AbiVersion;
    public BcIpmiSensorRecord Sensor;
    public ushort RecordId, ReadableMask;
    public byte RecordType, OwnerChannel, ShareIndex, ShareCount, Capabilities, IdEncoding, RawIdLength, ComparisonMask;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] RawId;
    public uint NameStatus;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] Name;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSensorCatalog
{
    public uint StructSize, AbiVersion, Flags, RecordCount, Count;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public BcIpmiSensorDescriptor[] Sensors;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcSensorField
{
    public uint State, Status;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcSensorDetails
{
    public uint StructSize, AbiVersion, Status, Flags;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
    public BcSensorField[] Fields;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public BcSensorField[] ThresholdFields;
    public double Reading;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public double[] Thresholds;
    public uint ThresholdMask, ActiveThresholdMask, ActiveThresholdValidMask, DiscreteStates, DiscreteValidMask, Health, RawStatus;
    public BcString Units, HealthText, StateText, ReadingTime;
    public BcBytes ThresholdsJson;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiChassisCapabilities
{
    public uint StructSize, AbiVersion, Flags;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Addresses;
}

internal static class IpmiManagementNative
{
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_boot_get(IntPtr session, ref BcIpmiBootInfo info, out byte completion);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_boot_set_once_guarded(IntPtr session, uint target, uint mode, IntPtr guard, ref BcIpmiBootResult result);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_chassis_control(IntPtr session, byte action, out byte completion);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_chassis_capabilities_get(IntPtr session, ref BcIpmiChassisCapabilities info);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_sensor_catalog_get(IntPtr session, ref BcIpmiSensorCatalog catalog);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_sensor_details_get(IntPtr session, ref BcIpmiSensorDescriptor sensor, ref BcSensorDetails details);
}

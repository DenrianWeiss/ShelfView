using System.Runtime.InteropServices;

namespace BControl.Core.Native;
[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSelInfo
{
    public uint StructSize;
    public uint AbiVersion;
    public byte Version;
    public uint RecordCount;
    public uint FreeSpace;
    public uint AdditionTimestamp;
    public uint EraseTimestamp;
    public byte OperationSupport;
    public byte ReserveSupported;
    public byte Overflow;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
    public byte[] Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSelEntry
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Status;
    public ushort RecordId;
    public byte RecordType;
    public byte Flags;
    public uint Timestamp;
    public byte RawLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
    public byte[] Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Raw;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSelLog
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Status;
    public uint Flags;
    public BcIpmiSelInfo Info;
    public uint Count;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public BcIpmiSelEntry[] Entries;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiFruAreaInfo
{
    public uint StructSize;
    public uint AbiVersion;
    public uint AreaSize;
    public byte WordAccess;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
    public byte[] Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiFruField
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Status;
    public byte FieldType;
    public byte RawLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public byte[] Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 63)]
    public byte[] Raw;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public byte[] Text;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiFruChassis
{
    public uint Status;
    public byte Present;
    public byte ChassisType;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public byte[] Reserved;
    public uint Flags;
    public BcIpmiFruField PartNumber;
    public BcIpmiFruField SerialNumber;
    public uint CustomCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public BcIpmiFruField[] Custom;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiFruBoard
{
    public uint Status;
    public byte Present;
    public byte Language;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public byte[] Reserved;
    public uint Flags;
    public uint MfgDate;
    public BcIpmiFruField Manufacturer;
    public BcIpmiFruField Product;
    public BcIpmiFruField Serial;
    public BcIpmiFruField PartNumber;
    public BcIpmiFruField FileId;
    public uint CustomCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public BcIpmiFruField[] Custom;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiFruProduct
{
    public uint Status;
    public byte Present;
    public byte Language;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public byte[] Reserved;
    public uint Flags;
    public BcIpmiFruField Manufacturer;
    public BcIpmiFruField Name;
    public BcIpmiFruField PartNumber;
    public BcIpmiFruField Version;
    public BcIpmiFruField Serial;
    public BcIpmiFruField AssetTag;
    public BcIpmiFruField FileId;
    public uint CustomCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public BcIpmiFruField[] Custom;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiFruInfo
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Status;
    public uint Flags;
    public byte FruId;
    public byte HeaderVersion;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public byte[] Reserved;
    public BcIpmiFruAreaInfo Area;
    public uint InternalStatus;
    public BcIpmiFruChassis Chassis;
    public BcIpmiFruBoard Board;
    public BcIpmiFruProduct Product;
    public uint MultiStatus;
    public uint MultiLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] MultiRaw;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiFruInventory
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Status;
    public uint Flags;
    public uint Count;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public uint[] DeviceStatus;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public uint[] DeviceSize;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] DeviceAccess;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiLanParameter
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Status;
    public byte Selector;
    public byte BlockSelector;
    public byte CompletionCode;
    public byte Revision;
    public byte Flags;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
    public byte[] Reserved;
    public uint DataLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] Data;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiLanChannel
{
    public uint StructSize;
    public uint AbiVersion;
    public byte Channel;
    public byte MediumType;
    public byte IsLan;
    public byte Flags;
    public uint Status;
    public byte CompletionCode;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
    public byte[] Reserved;
    public uint SupportedCount;
    public uint UnsupportedCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 27)]
    public BcIpmiLanParameter[] Parameters;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiLanConfig
{
    public uint StructSize;
    public uint AbiVersion;
    public byte ChannelCount;
    public byte LanChannelCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public byte[] Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
    public BcIpmiLanChannel[] Channels;
}

internal static class IpmiInventoryNative
{
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_sel_log_get(IntPtr session, ref BcIpmiSelLog log);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_fru_inventory_get(IntPtr session, ref BcIpmiFruInventory inventory);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_fru_info_get(IntPtr session, byte id, ref BcIpmiFruInfo info);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_lan_config_scan(IntPtr session, ref BcIpmiLanConfig config);
}

using System.Runtime.InteropServices;

namespace BControl.Core.Native;
[StructLayout(LayoutKind.Sequential)]
internal struct BcIdracLaunchUri
{
    public uint StructSize, Flags;
    public BcString Scheme, Host, Path, Query;
    public uint Port;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIdracLaunch
{
    public uint StructSize, Port;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 257)]
    public byte[] PrimaryKey;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 257)]
    public byte[] SecondaryKey;
}

internal static class IdracNative
{
    private const string Library = "bcontrol_idrac";
    [DllImport("bcontrol_console", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_launch_from_idrac(ref BcIdracLaunch descriptor, out IntPtr launch);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_idrac_kvm_launch_location(byte[] data, uint length, byte[] output, uint capacity, out uint written);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_idrac_kvm_discover_launch(ref BcIdracLaunchUri uri, BcString host, uint port, out BcIdracLaunch launch, out BcServiceProfile profile);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_idrac_kvm_discover_attributes(byte[] data, uint length, out BcServiceProfile profile);
}

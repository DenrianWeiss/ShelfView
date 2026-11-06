using System.Runtime.InteropServices;

namespace BControl.Core.Native;
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint BcMediaRead(IntPtr user, ulong offset, uint length, IntPtr output);
[StructLayout(LayoutKind.Sequential)]
internal struct BcMediaSource
{
    public uint StructSize;
    public IntPtr User;
    public ulong Size;
    public IntPtr Read;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcMediaOfferInfo { internal uint StructSize, Flags, Port; }

internal static class MediaNative
{
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_media_offer(IntPtr console, out IntPtr offer);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_offer_info_get(IntPtr offer, ref BcMediaOfferInfo info);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_media_offer_destroy(IntPtr offer);
}

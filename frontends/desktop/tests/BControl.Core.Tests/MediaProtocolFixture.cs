using System.Runtime.InteropServices;
using BControl.Core.Native;
namespace BControl.Core.Tests;
internal static class MediaProtocolFixture {
    private const string Mega = "bcontrol_megarac";
    [DllImport(Mega, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_megarac_cd_create(ref BcMediaSource source, out IntPtr cd);
    [DllImport(Mega, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_megarac_cd_handle(IntPtr cd, byte[] input, uint length, byte[] output, uint capacity, out uint written);
    [DllImport(Mega, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_megarac_cd_destroy(IntPtr cd);
}

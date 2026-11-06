using System.Runtime.InteropServices;
namespace BControl.Core.Native;
internal static class HttpNative
{
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bc_request_response(IntPtr request);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_request_cancel(IntPtr request);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_request_retain(IntPtr request);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_request_release(IntPtr request);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern BcString bc_request_cookie_header(IntPtr request);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern BcString bc_request_csrf_token(IntPtr request);
}

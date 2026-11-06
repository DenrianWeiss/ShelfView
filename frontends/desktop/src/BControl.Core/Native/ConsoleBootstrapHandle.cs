using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace BControl.Core.Native;
internal sealed class ConsoleBootstrapHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private const string Library = "bcontrol_console";
    private ConsoleBootstrapHandle(IntPtr pointer) : base(true) => SetHandle(pointer);
    internal static ConsoleBootstrapHandle Create(ConsoleLaunchHandle launch) {
        Bc.Check(bc_console_bootstrap_create(launch, out var pointer), "media.title");
        return new(pointer);
    }
    internal unsafe void Feed(byte[] bytes) {
        fixed (byte* pointer = bytes)
            Bc.Check(bc_console_bootstrap_feed(this, new BcBytes { Data = (IntPtr)pointer, Length = (ulong)bytes.Length }), "media.title");
    }
    internal byte[] TakeOutput() {
        var bytes = new byte[65536];
        Bc.Check(bc_console_bootstrap_output(this, bytes, (uint)bytes.Length, out var size), "media.title");
        Array.Resize(ref bytes, (int)size);
        return bytes;
    }
    internal IntPtr Offer() {
        var status = bc_console_bootstrap_media_offer(this, out var offer);
        if (status != Bc.Busy) Bc.Check(status, "media.title");
        return offer;
    }
    internal byte[] CloseNotification() {
        TakeOutput();
        Bc.Check(bc_console_bootstrap_close(this), "media.title");
        return TakeOutput();
    }
    protected override bool ReleaseHandle() { bc_console_bootstrap_destroy(handle); return true; }
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_bootstrap_create(ConsoleLaunchHandle launch, out IntPtr bootstrap);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_bootstrap_feed(ConsoleBootstrapHandle bootstrap, BcBytes bytes);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_bootstrap_output(ConsoleBootstrapHandle bootstrap, byte[] bytes, uint capacity, out uint size);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_bootstrap_media_offer(ConsoleBootstrapHandle bootstrap, out IntPtr offer);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_bootstrap_close(ConsoleBootstrapHandle bootstrap);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bc_console_bootstrap_destroy(IntPtr bootstrap);
}

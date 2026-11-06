using Microsoft.Win32.SafeHandles;

namespace BControl.Core.Native;

internal sealed class ConsoleLaunchHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal ConsoleLaunchHandle(IntPtr value) : base(true) { SetHandle(value); }
    protected override bool ReleaseHandle()
    {
        ConsoleNative.bc_console_launch_destroy(handle);
        return true;
    }
}

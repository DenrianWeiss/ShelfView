namespace BControl.Core.Native;

// 与 include/bcontrol/boot.h 保持一致。
public static class BootAbi
{
    public const uint None = 0;
    public const uint Pxe = 1;
    public const uint Disk = 2;
    public const uint Cd = 3;
    public const uint Setup = 4;
    public const uint Usb = 5;
    public const uint UefiShell = 6;

    public const uint ModePreserve = 0;
    public const uint ModeLegacy = 1;
    public const uint ModeUefi = 2;

    public const uint Enabled = 1;
    public const uint Persistent = 2;
    public const uint TargetsKnown = 4;
    public const uint Locked = 8;
    public const uint OnceSupported = 16;
    public const uint OnceInferred = 32;
}

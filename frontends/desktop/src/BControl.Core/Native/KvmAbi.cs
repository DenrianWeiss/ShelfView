using System.Runtime.InteropServices;

namespace BControl.Core.Native;

// 与 include/bcontrol/kvm.h / kvm_transport.h 一致。
internal static class KvmAbi
{
    public const uint Ready = 1;
    public const uint FrameReady = 2;
    public const uint DesktopResized = 4;

    public const uint TransportTcp = 1;
    public const uint TransportTls = 2;
    public const uint TransportWs = 3;
    public const uint TransportWss = 4;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcKvmOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint MaxWidth;
    public uint MaxHeight;
    public uint Reserved;
    public IntPtr Framebuffer;
    public ulong FramebufferCapacity;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcKvmFrame
{
    public uint StructSize;
    public uint Flags;
    public uint Width;
    public uint Height;
    public uint Stride;
    public uint NameLength;
    public BcString Name;
    public IntPtr Pixels;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcKvmTransportOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public BcString Url;
    public BcString CaFile;
    public BcString Username;
    public BcString Password;
    public IntPtr Headers;
    public uint HeaderCount;
    public uint CertPolicy;
    public uint TlsMin;
    public uint TlsMax;
    public uint TimeoutMs;
    public uint Flags;
    public BcString Subprotocols;
    public uint Reserved;
}

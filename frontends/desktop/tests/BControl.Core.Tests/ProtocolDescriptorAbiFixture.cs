using System.Runtime.InteropServices;

namespace BControl.Core.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct BcMegaracKvmInfo
{
    public uint StructSize;
    public uint Kind;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public byte[] Host;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] Token;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] Cookie;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] Session;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] ClientIp;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] ServerIp;
    public uint Port;
    public uint Secure;
    public uint SinglePort;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcWebEntryOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public ulong Generation;
    public uint TimeoutMs;
    public uint MaxRequests;
    public uint MaxDepth;
    public ulong MaxBytes;
    public IntPtr ClockMs;
    public IntPtr ClockUser;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcWebSessionOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint TimeoutMs;
    public BcString Username;
    public BcString Password;
    public BcString ClientId;
    public IntPtr ClockMs;
    public IntPtr ClockUser;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcJviewerArtifactOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint TimeoutMs;
    public ulong Generation;
    public IntPtr ClockMs;
    public IntPtr ClockUser;
    public IntPtr Headers;
    public uint HeaderCount;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcHuaweiKvmParams
{
    public uint StructSize;
    public uint AbiVersion;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] Host;
    public ushort Port;
    public ushort VmmPort;
    public uint Privilege;
    public uint Compress;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] VerifyValue;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
    public byte[] VerifyValueExt;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 68)]
    public byte[] Decrykey;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 160)]
    public byte[] Title;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcHuaweiLaunchOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Contract;
    public uint TimeoutMs;
    public uint Modes;
    public BcString ExportUri;
    public BcString DownloadUri;
    public BcString Nonce;
    public ulong Generation;
    public IntPtr ClockMs;
    public IntPtr ClockUser;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcHuaweiLaunchResult
{
    public uint StructSize;
    public uint Flags;
    public uint Status;
    public uint HttpStatus;
    public BcConsoleFailure Failure;
    public IntPtr Descriptor;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcConsoleDiscoveryPrefix
{
    public uint StructSize, State, Format, Status, HttpStatus;
    public ulong EndpointRevision, Generation;
    public BcServiceProfile Profile;
    public BcConsoleFailure Failure;
    public BcMegaracKvmInfo Megarac;
    public BcHuaweiKvmParams Huawei;
}

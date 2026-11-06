using System.Runtime.InteropServices;

namespace BControl.Core.Native;

// 与 include/bcontrol/ipmi.h / ipmi_session.h / ipmi_sol.h / ipmi_platform.h 一致。
internal static class IpmiAbi
{
    public const uint Suite3Disallowed = 0;
    public const uint Suite3Allowed = 1;
    public const uint Suite3Confirmed = 2;

    public const uint CapabilityChassisStatus = 1;
    public const uint CapabilitySdr = 2;
    public const uint CapabilitySel = 4;
    public const uint CapabilityFru = 8;

    public const uint SolActive = 1;
    public const uint SolClosed = 2;
    public const uint SolFailed = 3;
    public const uint SolOutcomeUnknown = 4;

    public const uint SolFlushToBmc = 1;
    public const uint SolFlushFromBmc = 2;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiCrypto
{
    public uint StructSize;
    public uint AbiVersion;
    public IntPtr Userdata;
    public IntPtr Hmac;
    public IntPtr Encrypt;
    public IntPtr Decrypt;
    public IntPtr Random;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiIo
{
    public uint StructSize;
    public uint AbiVersion;
    public IntPtr Userdata;
    public IntPtr Send;
    public IntPtr Receive;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSessionOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public IntPtr Io;
    public IntPtr Crypto;
    public uint TimeoutMs;
    public uint Retries;
    public uint Suite3Policy;
    public uint Channel;
    public BcString Username;
    public BcString Password;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSessionInfo
{
    public uint CipherSuiteId;
    public byte AuthAlgorithm;
    public byte IntegrityAlgorithm;
    public byte ConfidentialityAlgorithm;
    public uint BmcSessionId;
    public uint ConsoleSessionId;
    public uint MaximumPrivilege;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiCapabilities
{
    public uint StructSize;
    public uint Flags;
    public uint CipherSuiteId;
    public uint SdrRecordCount;
    public uint ChassisPowerState;
    public uint SelRecordCount;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiChassisStatus
{
    public uint StructSize;
    public uint PowerState;
    public uint Flags;
    public byte RawPowerState;
    public byte LastPowerEvent;
    public byte MiscState;
    public byte AcpiPowerState;
    public uint PowerRestorePolicy;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSolOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint ReceiveCapacity;
    public uint SendCapacity;
    public uint RetryIntervalMs;
    public uint Retries;
    public uint KeepaliveMs;
    public ushort SessionPort;
    public byte Instance;
    public byte Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSolInfo
{
    public uint StructSize;
    public uint State;
    public uint Flags;
    public uint ReceivePending;
    public uint SendPending;
    public uint Status;
    public uint CleanupStatus;
    public ushort Port;
    public ushort InboundPayloadSize;
    public ushort OutboundPayloadSize;
    public byte Instance;
    public byte CompletionCode;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcIpmiSolConfig
{
    public uint StructSize;
    public byte Enabled;
    public byte ForceAuthentication;
    public byte ForceEncryption;
    public byte Privilege;
    public byte VolatileBitRate;
    public byte NonvolatileBitRate;
    public byte PayloadChannel;
    public byte PayloadVersion;
    public ushort PayloadPort;
    public ushort Reserved2;
}

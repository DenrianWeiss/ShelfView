using System.Runtime.InteropServices;
using BControl.Core.Localization;

namespace BControl.Core.Native;
/// <summary>ABI 常量与错误码；与 include/bcontrol/bcontrol.h 保持一致。</summary>
public static class Bc
{
    public const uint AbiVersion = 1;
    public const uint Ok = 0;
    public const uint InvalidArgument = 1;
    public const uint NoMemory = 2;
    public const uint Busy = 3;
    public const uint Unsupported = 4;
    public const uint Cancelled = 5;
    public const uint Timeout = 6;
    public const uint TlsError = 7;
    public const uint LimitExceeded = 8;
    public const uint IoError = 9;
    public const uint ShuttingDown = 10;
    public const uint OutcomeUnknown = 11;
    public const uint HttpError = 12;
    public const uint ProtocolError = 13;
    public const uint RedfishError = 14;
    public const uint ConfirmationRequired = 15;
    public const uint AuthenticationFailed = 16;
    public const uint CertStrict = 0;
    public const uint CertSkipChain = 1;
    public const uint CertSkipAll = 2;
    public const uint AuthNone = 0;
    public const uint AuthBasic = 1;
    public const uint AuthToken = 2;
    public const uint PowerUnknown = 0;
    public const uint PowerOn = 1;
    public const uint PowerOff = 2;
    public const uint PoweringOn = 3;
    public const uint PoweringOff = 4;
    public static string StatusString(uint status)
    {
        var ptr = NativeMethods.bc_status_string(status);
        return ptr == IntPtr.Zero ? "unknown" : Marshal.PtrToStringUTF8(ptr) ?? "unknown";
    }

    /// <summary>面向界面的状态文案；需要原始 token 时仍用 <see cref = "StatusString"/>。</summary>
    public static string StatusText(uint status) => Loc.Instance.Status(status);
    internal static void Check(uint status, string whatKey, uint httpStatus = 0)
    {
        if (status != Ok)
            throw new BcException(status, Loc.F("error.context", ("what", Loc.T(whatKey)), ("detail", StatusText(status))), httpStatus);
    }
}

public sealed class BcException : Exception
{
    public uint Status { get; }
    public uint HttpStatus { get; }
    public bool? WriteMayHaveTakenEffect { get; }

    public BcException(uint status, string message, uint httpStatus = 0, bool? writeMayHaveTakenEffect = null) : base(message)
    {
        Status = status;
        HttpStatus = httpStatus;
        WriteMayHaveTakenEffect = writeMayHaveTakenEffect;
    }
}

/// <summary> borrowed C 字符串视图；仅在调用的原生调用生命周期内有效。 </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct BcString
{
    public IntPtr Data;
    public ulong Length;
    public static BcString From(string? value)
    {
        if (value == null)
            return new BcString
            {
                Data = IntPtr.Zero,
                Length = 0
            };
        // 调用方必须保持指针有效直到原生调用返回；使用 UTF8 编码的托管缓冲由调用点处理。
        throw new InvalidOperationException(Loc.T("core.internal"));
    }
}

internal sealed class BcStringPinned : IDisposable
{
    private GCHandle _handle;
    public BcString Value;
    public static BcStringPinned Pin(string? text)
    {
        var pinned = new BcStringPinned();
        if (text == null)
        {
            pinned.Value = new BcString();
            return pinned;
        }

        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        pinned._handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        pinned.Value = new BcString
        {
            Data = pinned._handle.AddrOfPinnedObject(),
            Length = (ulong)bytes.Length
        };
        return pinned;
    }

    public void Dispose()
    {
        if (_handle.IsAllocated)
        {
            if (_handle.Target is byte[] bytes)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
            _handle.Free();
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcBytes
{
    public IntPtr Data;
    public ulong Length;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcDisplayTile
{
    public uint StructSize, PixelFormat, CanvasWidth, CanvasHeight, X, Y, Width, Height, Stride;
    public BcBytes Pixels;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcContextOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public IntPtr Transport;
    public ulong MaxResponseBytes;
    public uint MaxRequests;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcEndpointOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public BcString DeviceId;
    public BcString EndpointId;
    public BcString Origin;
    public BcString CaFile;
    public BcString Username;
    public BcString Password;
    public uint CertPolicy;
    public uint TlsMin;
    public uint TlsMax;
    public uint Reserved;
    public uint Flags;
    public uint Reserved2;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcAuthOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Mode;
    public uint Reserved;
    public BcString Username;
    public BcString Password;
    public BcString Token;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct BcResponse
{
    public uint StructSize;
    public uint Status;
    public uint HttpStatus;
    public uint CertPolicy;
    public ulong EndpointRevision;
    public BcBytes Body;
    public BcString Error;
    public BcString TlsVersion;
    public BcString Cipher;
    public uint PeerVerified;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcTemperatureReading
{
    public double Value;
    public uint Unit;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcTemperatureSummary
{
    public uint StructSize;
    public uint Flags;
    public uint CpuIndex;
    public uint NormalIndex;
    public uint AlertIndex;
    public uint Reserved;
    public double CpuCelsius;
    public double NormalCelsius;
    public double AlertCelsius;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcTemperatureSelection
{
    public uint StructSize, Source, Flags, Index;
    public double Celsius;
}

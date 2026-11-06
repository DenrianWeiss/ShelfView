using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace BControl.Core.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct BcSerialInfo
{
    public uint StructSize, State, Capabilities, Status, CleanupStatus;
    public uint ReceivePending, SendPending, ProtocolFlags, RemotePort;
}

// Owns only the stream wrapper. Its protocol connection outlives this handle.
internal sealed class SerialStreamHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SerialStreamHandle(IntPtr value) : base(true) => SetHandle(value);
    internal static SerialStreamHandle Borrow(IntPtr connection)
    {
        IntPtr stream;
        var status = SerialNative.bc_ipmi_sol_stream(connection, out stream);
        Bc.Check(status, "sol.title");
        return new SerialStreamHandle(stream);
    }
    protected override bool ReleaseHandle() { SerialNative.bc_serial_destroy(handle); return true; }
}

internal static class SerialNative
{
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_sol_stream(IntPtr connection, out IntPtr stream);
    [DllImport(NativeLibs.KvmNet, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_serial_open(ref SerialOpenOptions options, out IntPtr stream);
    [DllImport(NativeLibs.KvmNet, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bc_serial_fallback_allowed(uint status, byte completion);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_serial_read(SerialStreamHandle stream, ulong now, uint timeout, byte[] data, uint capacity, out uint length);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_serial_write(SerialStreamHandle stream, BcBytes data, out uint accepted);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_serial_info_get(SerialStreamHandle stream, ref BcSerialInfo info);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_serial_close(SerialStreamHandle stream);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_serial_destroy(IntPtr stream);
}

[StructLayout(LayoutKind.Sequential)]
internal struct SerialOpenOptions {
    internal uint StructSize, AbiVersion;
    internal BcString Host, Username, Password, CaFile;
    internal uint CertPolicy, TlsMin, TlsMax, TimeoutMs;
    internal IntPtr Proxy;
}

using System.Runtime.InteropServices;

namespace BControl.Core.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct BcConsoleInput
{
    public uint StructSize, Type, Keysym, Down, Buttons, X, Y, Width, Height;
    public int Wheel;
}
[StructLayout(LayoutKind.Sequential)]
internal struct BcConsoleInfo
{
    internal uint StructSize, Flags, KeyboardLeds, TickIntervalMs;
    internal BcServiceProfile Profile;
    internal BcConsoleFailure Failure;
    internal bool Ready => (Flags & 2) != 0;
    internal bool MediaRemovalUnconfirmed => (Flags & 128) == 0 || (Flags & 256) != 0;
    internal bool Terminated => (Flags & (32 | 64)) != 0;
}
internal static class ConsoleNative
{
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_feed(IntPtr session, uint channel, byte[] data, uint length);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_output(IntPtr session, uint channel, byte[] data, uint capacity, out uint written);
    internal const uint Refresh = 1, Heartbeat = 2, QueryInputState = 4, Close = 8, Start = 16,
        MediaEnable = 32, MediaDisable = 64, SourceAttach = 128, SourceDetach = 256;
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_controls(IntPtr session);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_control(IntPtr session, uint operation);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_session_info_get(IntPtr session, ref BcConsoleInfo info);
    internal static BcConsoleInfo Info(IntPtr session) {
        var info = new BcConsoleInfo { StructSize = (uint)Marshal.SizeOf<BcConsoleInfo>() };
        Bc.Check(bc_console_session_info_get(session, ref info), "kvm.title");
        return info;
    }
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_feed_some(IntPtr session, uint channel, IntPtr data, uint length, out uint consumed);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_session_name(IntPtr session, byte[] data, uint capacity, out uint written);
    internal static string Name(IntPtr session)
    {
        var bytes = new byte[1024];
        var status = bc_console_session_name(session, bytes, (uint)bytes.Length, out var written);
        if (status == Bc.Unsupported) return "";
        Bc.Check(status, "kvm.title");
        return System.Text.Encoding.UTF8.GetString(bytes, 0, checked((int)written));
    }
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_poll(IntPtr session, uint timeoutMilliseconds);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_tick(IntPtr session, ulong nowMilliseconds);
    internal static uint[] CopyChord(IReadOnlyList<uint> keys) {
        if (keys.Count is < 1 or > 8) throw new ArgumentException("Invalid key chord");
        return keys.ToArray();
    }
    internal static void SendChord(IntPtr session, uint[] keys) {
        if (keys.Length == 0) return;
        Bc.Check(bc_console_session_chord(session, keys, (uint)keys.Length), "core.kvmInput");
    }
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_session_chord(IntPtr session, [In] uint[] keys, uint count);
    internal static bool SupportsScroll(IntPtr session) => (bc_console_session_input_capabilities(session) & 1) != 0;
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_session_input_capabilities(IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint DecodeSubmit(IntPtr user, IntPtr job);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_decode_job_size(IntPtr job);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_decode_job_execute(IntPtr job);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_decode_job_destroy(IntPtr job);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint Emit(IntPtr user, IntPtr data, uint length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate byte LedSnapshot(IntPtr user);
    [DllImport("bcontrol_console", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_console_session_create(ref BcConsoleOptions options, out IntPtr session);
    [DllImport("bcontrol_console", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_launch_from_token(uint protocol, uint generation, BcString token, out IntPtr launch);
    [DllImport("bcontrol_console", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_console_launch_destroy(IntPtr launch);
    internal static uint Create(ConsoleLaunchHandle launch, BcConsoleOptions options, out IntPtr session)
    {
        bool retained = false;
        try
        {
            launch.DangerousAddRef(ref retained);
            options.StructSize = (uint)Marshal.SizeOf<BcConsoleOptions>();
            options.AbiVersion = Bc.AbiVersion;
            options.Launch = launch.DangerousGetHandle();
            return bc_console_session_create(ref options, out session);
        }
        finally { if (retained) launch.DangerousRelease(); }
    }
    internal static uint Create(ConsoleLaunchHandle launch, BcKvmOptions display, Emit emit, LedSnapshot? leds, out IntPtr session)
    {
        try
        {
            return Create(launch, new BcConsoleOptions { Display = display,
                Emit = Marshal.GetFunctionPointerForDelegate(emit),
                Leds = leds == null ? IntPtr.Zero : Marshal.GetFunctionPointerForDelegate(leds) }, out session);
        }
        finally { GC.KeepAlive(emit); GC.KeepAlive(leds); }
    }
    internal static uint Create(ConsoleLaunchHandle launch, DecodeSubmit submit, out IntPtr session)
    {
        try { return Create(launch, new BcConsoleOptions { Submit = Marshal.GetFunctionPointerForDelegate(submit) }, out session); }
        finally { GC.KeepAlive(submit); }
    }
    internal static uint Create(uint protocol, BcKvmOptions display, BcString token, uint generation,
        Emit emit, LedSnapshot? leds, out IntPtr session)
    {
        session = IntPtr.Zero;
        var status = bc_console_launch_from_token(protocol, generation, token, out var handle);
        if (status != Bc.Ok) return status;
        using var launch = new ConsoleLaunchHandle(handle);
        return Create(launch, display, emit, leds, out session);
    }
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_input(IntPtr session, ref BcConsoleInput input);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_session_tile(IntPtr session, ref BcDisplayTile tile);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_console_session_ack_display(IntPtr session);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_console_session_destroy(IntPtr session);
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcConsoleOptions
{
    internal uint StructSize, AbiVersion;
    internal BcKvmOptions Display;
    internal IntPtr Launch, Emit, Leds, User, Submit;
    internal IntPtr Receive, TransportUser, Clock, ClockUser;
    internal uint HandshakeTimeoutMs, HeartbeatIntervalMs;
}

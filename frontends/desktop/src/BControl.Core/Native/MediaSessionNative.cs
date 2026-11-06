using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace BControl.Core.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct MediaSessionInfo
{
    internal uint StructSize, Flags;
    internal ulong BytesRead;
    internal uint State, Status, DeviceCode, HeartbeatIntervalMs;
    internal ulong Packets, Requests, BytesServed;
    internal readonly bool Ready => (Flags & 32) != 0;
    internal readonly bool Ejecting => (Flags & 64) != 0;
    internal readonly bool RemovalUnconfirmed => (Flags & 128) != 0;
    internal readonly bool Failed => (Flags & 256) != 0;
    internal readonly bool Connected => (Flags & 1) != 0;
    internal readonly bool SourceAttached => (Flags & 2) != 0;
    internal readonly bool MountConfirmed => (Flags & 4) != 0;
    internal readonly bool RemovalConfirmed => (Flags & 8) != 0;
    internal readonly ulong? SourceBytesRead => (Flags & 16) != 0 ? BytesRead : null;
}

internal sealed class MediaSessionHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private sealed record Published(MediaSessionInfo Info);
    private Published _published = new(default);
    internal MediaSessionInfo Cached => Volatile.Read(ref _published).Info;
    internal const uint Eject = 1, KeepAlive = 2, CloseRequest = 3, Start = 4;
    private MediaSessionHandle(IntPtr value) : base(true) => SetHandle(value);
    internal static MediaSessionHandle Create(IntPtr offer, BcMediaSource? source, BcConsoleSend? emit = null,
        BcConsoleReceive? receive = null, BcClock? clock = null, uint timeout = 10000,
        uint heartbeat = 1000, uint flags = 0, uint instance = 0)
    {
        var pointer = IntPtr.Zero;
        try
        {
            if (source is { } value) {
                pointer = Marshal.AllocHGlobal(Marshal.SizeOf<BcMediaSource>());
                Marshal.StructureToPtr(value, pointer, false);
            }
            var options = new MediaOptions {
                StructSize = (uint)Marshal.SizeOf<MediaOptions>(), AbiVersion = Bc.AbiVersion,
                Offer = offer, Source = pointer, Emit = emit == null ? IntPtr.Zero : Marshal.GetFunctionPointerForDelegate(emit),
                Receive = receive == null ? IntPtr.Zero : Marshal.GetFunctionPointerForDelegate(receive),
                Clock = clock == null ? IntPtr.Zero : Marshal.GetFunctionPointerForDelegate(clock),
                TimeoutMs = timeout, HeartbeatIntervalMs = heartbeat, Flags = flags, Instance = instance
            };
            Bc.Check(MediaSessionNative.bc_media_session_create(ref options, out var session), "media.title");
            return new(session);
        }
        finally { if (pointer != IntPtr.Zero) Marshal.FreeHGlobal(pointer); }
    }
    internal static MediaSessionHandle CreateToken(uint protocol, string token, BcMediaSource? source,
        BcConsoleSend? emit = null, BcConsoleReceive? receive = null, BcClock? clock = null,
        uint timeout = 10000, uint flags = 0)
    {
        using var pin = BcStringPinned.Pin(token);
        Bc.Check(MediaSessionNative.bc_media_offer_from_token(protocol, 0, pin.Value, out var offer), "media.title");
        try { return Create(offer, source, emit, receive, clock, timeout, flags: flags); }
        finally { MediaNative.bc_media_offer_destroy(offer); }
    }
    internal IEnumerable<byte[]> TakeOutput()
    {
        while (true) {
            var status = MediaSessionNative.bc_media_session_output(this, null, 0, out var size);
            if (status == Bc.Busy) yield break;
            if (status != Bc.LimitExceeded) Bc.Check(status, "media.title");
            var bytes = new byte[size];
            if (status != Bc.Ok) Bc.Check(MediaSessionNative.bc_media_session_output(this, bytes, size, out _), "media.title");
            yield return bytes;
        }
    }
    internal void Check(uint status)
    {
        if (status == Bc.Ok) return;
        var pointer = MediaSessionNative.bc_media_session_failure_get(this);
        if (pointer != IntPtr.Zero) {
            var failure = Marshal.PtrToStructure<BcConsoleFailure>(pointer);
            if (failure.Status == status) {
                var key = failure.Cause switch {
                    2 => "error.accessDenied", 3 or 4 => "kvm.error.sessionRejected",
                    10 => "media.licenseRequired", 11 => "media.notConfigured", _ => null
                };
                if (key != null) throw new BcException(status, Localization.Loc.T(key));
            }
        }
        Bc.Check(status, "media.title");
    }
    internal uint Attach(BcMediaSource source) => MediaSessionNative.bc_media_session_attach(this, ref source);
    internal uint Tick(ulong now) => MediaSessionNative.bc_media_session_tick(this, now);
    internal void ObserveMount(bool inserted) { Bc.Check(MediaSessionNative.bc_media_session_observe_mount(this, inserted ? 1 : 0), "media.title"); Snapshot(); }
    internal unsafe uint Feed(byte[] bytes, uint length)
    {
        if (length > bytes.Length) return Bc.InvalidArgument;
        fixed (byte* pointer = bytes)
            return MediaSessionNative.bc_media_session_feed(this, new BcBytes { Data = (IntPtr)pointer, Length = length });
    }
    internal uint Poll(uint timeout) => MediaSessionNative.bc_media_session_poll(this, timeout);
    internal uint Control(uint command) => MediaSessionNative.bc_media_session_control(this, command);
    internal MediaSessionInfo Snapshot()
    {
        var info = new MediaSessionInfo { StructSize = (uint)Marshal.SizeOf<MediaSessionInfo>() };
        Bc.Check(MediaSessionNative.bc_media_session_info_get(this, ref info), "media.title");
        Volatile.Write(ref _published, new Published(info));
        return info;
    }
    protected override bool ReleaseHandle() { MediaSessionNative.bc_media_session_destroy(handle); return true; }
}

[StructLayout(LayoutKind.Sequential)]
internal struct MediaOptions {
    internal uint StructSize, AbiVersion;
    internal IntPtr Offer, Source, Emit, Receive, Clock, User;
    internal uint TimeoutMs, HeartbeatIntervalMs, Flags, Instance;
}
internal static class MediaSessionNative
{
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bc_media_session_failure_get(MediaSessionHandle session);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_output(MediaSessionHandle session, byte[]? bytes, uint capacity, out uint written);
    [DllImport("bcontrol_console", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_create(ref MediaOptions options, out IntPtr session);
    [DllImport("bcontrol_console", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_offer_from_token(uint protocol, uint kind, BcString token, out IntPtr offer);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_attach(MediaSessionHandle session, ref BcMediaSource source);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_observe_mount(MediaSessionHandle session, int inserted);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_tick(MediaSessionHandle session, ulong now);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_info_get(MediaSessionHandle session, ref MediaSessionInfo info);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_feed(MediaSessionHandle session, BcBytes bytes);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_poll(MediaSessionHandle session, uint timeout);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_media_session_control(MediaSessionHandle session, uint command);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_media_session_destroy(IntPtr session);
}

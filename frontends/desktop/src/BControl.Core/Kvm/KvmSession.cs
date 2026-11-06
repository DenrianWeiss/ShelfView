using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Kvm;
public sealed record KvmFrame(uint Width, uint Height, uint Stride, string Name, byte[] PixelsRgba);
/// <summary>
/// RFB transport and ordered input share one owner; video decoding runs independently.
/// </summary>
public sealed class KvmSession : IKvmSession
{
    private IntPtr _transport;
    private IntPtr _console;
    private ConsoleNative.Emit? _emit;
    private Thread? _loop;
    private volatile bool _closing;
    private readonly KvmInputDispatcher _inputs = new();
    private readonly ConcurrentQueue<byte[]> _output = new();
    private KvmDecodeStream<byte[]>? _decode;
    private int _outputBytes;
    private int _disposed;
    private KvmFrame? _latestFrame;
    public KvmFrame? LatestFrame => Volatile.Read(ref _latestFrame);

    public event Action<KvmFrame>? FrameReceived;
    public event Action<string>? Failed;
    public event Action? Closed;
    public bool IsConnected => _loop != null && !_closing && _loop.IsAlive;

    public static async Task<KvmSession> ConnectAsync(string url, string? caFile, string? username, string? password, uint certPolicy, uint timeoutMs, CancellationToken cancellation, uint tlsMin = 12, Socks5Connection? proxy = null)
    {
        var session = new KvmSession();
        try
        {
            await Task.Run(() =>
            {
                using var urlPin = BcStringPinned.Pin(url);
                using var caPin = BcStringPinned.Pin(caFile);
                using var userPin = BcStringPinned.Pin(username);
                using var passPin = BcStringPinned.Pin(password);
                var options = new BcKvmTransportOptions
                {
                    StructSize = (uint)Marshal.SizeOf<BcKvmTransportOptions>(),
                    AbiVersion = Bc.AbiVersion,
                    Url = urlPin.Value,
                    CaFile = caPin.Value,
                    Username = userPin.Value,
                    Password = passPin.Value,
                    CertPolicy = certPolicy,
                    TlsMin = tlsMin,
                    TimeoutMs = timeoutMs,
                };
                Bc.Check(NativeConnections.Connect(ref options, proxy, out session._transport), "core.createKvmTransport");
                var kvmOptions = new BcKvmOptions
                {
                    StructSize = (uint)Marshal.SizeOf<BcKvmOptions>(),
                    AbiVersion = Bc.AbiVersion,
                };
                session._emit = (_, data, length) =>
                {
                    try
                    {
                        var bytes = new byte[checked((int)length)];
                        Marshal.Copy(data, bytes, 0, bytes.Length);
                        return NativeMethods.bc_kvm_transport_send(session._transport, bytes, length);
                    }
                    catch { return Bc.IoError; }
                };
                Bc.Check(ConsoleNative.Create(1, kvmOptions, default, 0, session._emit, null, out session._console), "core.createKvmDecoder");
                session.SupportsScroll = ConsoleNative.SupportsScroll(session._console);
            }, cancellation).ConfigureAwait(false);
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        session._decode = new KvmDecodeStream<byte[]>(session.Decode);
        session._loop = new Thread(session.Loop)
        {
            IsBackground = true,
            Name = "bcontrol-kvm"
        };
        session._loop.Start();
        return session;
    }

    private void Loop()
    {
        var inbound = new byte[65536];
        try
        {
            while (!_closing)
            {
                _decode!.ThrowIfFailed();
                FlushOutput();
                _inputs.Drain();
                var status = NativeMethods.bc_kvm_transport_recv(_transport, inbound, (uint)inbound.Length, out var received, 20);
                if (status == Bc.Ok && received > 0)
                    _decode.Submit(inbound.AsSpan(0, checked((int)received)).ToArray(), (int)received);
                if (status != Bc.Ok && status != Bc.Timeout)
                    Bc.Check(status, "core.kvmInput");
            }
        }
        catch (Exception ex)
        {
            if (!_closing)
                Failed?.Invoke(ex.Message);
        }
        finally
        {
            _closing = true;
            _inputs.Close();
            Closed?.Invoke();
        }
    }

    private void Decode(byte[] bytes)
    {
        Bc.Check(ConsoleNative.bc_console_session_feed(_console, 0, bytes, (uint)bytes.Length), "core.kvmInput");
        var outbound = new byte[65536];
        while (true)
        {
            Bc.Check(ConsoleNative.bc_console_session_output(_console, 0, outbound, (uint)outbound.Length, out var written), "core.kvmOutput");
            if (written == 0) break;
            if (Interlocked.Add(ref _outputBytes, (int)written) > 1024 * 1024)
            {
                Interlocked.Add(ref _outputBytes, -(int)written);
                Bc.Check(Bc.LimitExceeded, "core.kvmOutput");
            }
            _output.Enqueue(outbound.AsSpan(0, (int)written).ToArray());
        }
        if (ConsoleDisplay.ReadFrame(_console) is not { } snapshot) return;
        Volatile.Write(ref _latestFrame, snapshot);
        FrameReceived?.Invoke(snapshot);
    }

    private void FlushOutput()
    {
        while (_output.TryDequeue(out var bytes))
        {
            Interlocked.Add(ref _outputBytes, -bytes.Length);
            Bc.Check(NativeMethods.bc_kvm_transport_send(_transport, bytes, (uint)bytes.Length), "core.kvmOutput");
        }
    }

    private Task SendInput(Action<KvmFrame> send)
    {
        return _inputs.Enqueue(() =>
        {
            if (_closing) throw new ObjectDisposedException(nameof(KvmSession));
            var frame = LatestFrame;
            if (frame == null) return;
            FlushOutput();
            send(frame);
        });
    }

    private void SubmitInput(BcConsoleInput input)
    {
        input.StructSize = (uint)Marshal.SizeOf<BcConsoleInput>();
        Bc.Check(ConsoleNative.bc_console_session_input(_console, ref input), "core.kvmInput");
    }
    public Task SendKeyAsync(int down, uint keysym) => SendInput(_ =>
        SubmitInput(new BcConsoleInput { Type = 1, Keysym = keysym, Down = (uint)down }));

    public Task SendChordAsync(IReadOnlyList<uint> keys) {
        var copy = ConsoleNative.CopyChord(keys);
        return SendInput(_ => ConsoleNative.SendChord(_console, copy));
    }
    public bool SupportsScroll { get; private set; }
    public Task SendScrollAsync(byte buttons, ushort x, ushort y, sbyte wheel) => SendPointerInput(3, buttons, x, y, wheel);
    public Task SendPointerAsync(byte buttons, ushort x, ushort y) => SendPointerInput(2, buttons, x, y, 0);
    private Task SendPointerInput(uint type, byte buttons, ushort x, ushort y, sbyte wheel) => SendInput(frame =>
        SubmitInput(new BcConsoleInput { Type = type, Buttons = buttons, X = Math.Min(x, frame.Width - 1),
            Y = Math.Min(y, frame.Height - 1), Width = frame.Width, Height = frame.Height, Wheel = wheel }));

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        _closing = true;
        await Task.Run(() => { if (_loop != null && Thread.CurrentThread != _loop) _loop.Join(); }).ConfigureAwait(false);
        _inputs.Close();
        if (_decode != null) await _decode.DisposeAsync().ConfigureAwait(false);
        await Task.Run(() =>
        {
            if (_console != IntPtr.Zero) ConsoleNative.bc_console_session_control(_console, ConsoleNative.Close);
            ConsoleNative.bc_console_session_destroy(_console);
            _console = IntPtr.Zero;
            _emit = null;
            if (_transport != IntPtr.Zero)
            {
                NativeMethods.bc_kvm_transport_close(_transport);
                NativeMethods.bc_kvm_transport_destroy(_transport);
                _transport = IntPtr.Zero;
            }
        }).ConfigureAwait(false);
    }
}

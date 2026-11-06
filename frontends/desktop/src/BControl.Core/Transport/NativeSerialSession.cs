using System.Runtime.InteropServices;
using BControl.Core.Ipmi;
using BControl.Core.Native;
namespace BControl.Core.Transport;

public sealed class NativeSerialSession : ISerialSession
{
    private ushort _remotePort;
    private SerialStreamHandle? _stream;
    private readonly object _gate = new();
    private readonly SemaphoreSlim _writes = new(1);
    private readonly CancellationTokenSource _stop = new();
    private Task? _pump, _dispose;
    private uint _cleanupStatus;
    private Action<byte[]>? _received;
    public event Action<SolState>? Ended;
    public event Action? WriteAccessChanged;
    private volatile bool _canWrite;
    public bool CanWrite => PumpActive && _canWrite;
    public event Action<byte[]>? Received
    {
        add { lock (_gate) { _received += value; _pump ??= Task.Run(Pump); } }
        remove { lock (_gate) _received -= value; }
    }
    public bool PumpActive => !_stop.IsCancellationRequested && _pump?.IsCompleted != true;

    public static Task<NativeSerialSession> OpenAsync(string host, string username, string password, string? caFile, uint certPolicy, uint minimumTls, Socks5Connection? proxy = null, HostTimeout? timeout = null) => Task.Run(() =>
    {
        using var hostPin = BcStringPinned.Pin(host);
        using var user = BcStringPinned.Pin(username);
        using var pass = BcStringPinned.Pin(password);
        using var ca = BcStringPinned.Pin(caFile);
        var options = new SerialOpenOptions {
            StructSize = (uint)Marshal.SizeOf<SerialOpenOptions>(), AbiVersion = Bc.AbiVersion,
            Host = hostPin.Value, Username = user.Value, Password = pass.Value, CaFile = ca.Value,
            CertPolicy = certPolicy, TlsMin = minimumTls, TimeoutMs = timeout?.Milliseconds ?? 5000
        };
        using var proxyPin = proxy?.Pin();
        var pointer = IntPtr.Zero;
        var session = new NativeSerialSession();
        try {
            if (proxyPin != null) {
                pointer = Marshal.AllocHGlobal(Marshal.SizeOf<BcSocks5Proxy>());
                Marshal.StructureToPtr(proxyPin.Value, pointer, false); options.Proxy = pointer;
            }
            Bc.Check(SerialNative.bc_serial_open(ref options, out var stream), "sol.title");
            session._stream = new SerialStreamHandle(stream);
        }
        finally { if (pointer != IntPtr.Zero) Marshal.FreeHGlobal(pointer); }
        return session;
    });

    private void Pump()
    {
        uint failure = Bc.Ok;
        var buffer = new byte[65536];
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                uint status, count; Action<byte[]>? received; bool changed;
                lock (_gate)
                {
                    status = SerialNative.bc_serial_read(_stream!, IpmiConnection.NowMs(), 50, buffer, (uint)buffer.Length, out count);
                    received = _received;
                    var info = new BcSerialInfo { StructSize = (uint)Marshal.SizeOf<BcSerialInfo>() };
                    Bc.Check(SerialNative.bc_serial_info_get(_stream!, ref info), "sol.title");
                    var writable = (info.Capabilities & 2) != 0;
                    changed = writable != _canWrite; _canWrite = writable; _remotePort = (ushort)info.RemotePort;
                }
                if (status != Bc.Ok && status != Bc.Timeout) Bc.Check(status, "sol.title");
                if (changed) WriteAccessChanged?.Invoke();
                if (count > 0) received?.Invoke(buffer.AsSpan(0, (int)count).ToArray());
                Thread.Yield();
            }
        }
        catch (BcException ex) { failure = ex.Status; }
        catch { failure = Bc.IoError; }
        finally
        {
            CloseNative();
            if (failure == Bc.Ok) failure = _cleanupStatus;
            Ended?.Invoke(new SolState(failure == Bc.Ok ? IpmiAbi.SolClosed : IpmiAbi.SolFailed,
                0, 0, 0, failure, _cleanupStatus, _remotePort, 0));
        }
    }
    public async Task WriteAsync(byte[] data, CancellationToken cancellation = default)
    {
        await _writes.WaitAsync(cancellation).ConfigureAwait(false);
        try
        {
            for (int offset = 0; offset < data.Length; offset += 4096)
            {
                cancellation.ThrowIfCancellationRequested();
                var chunk = data.AsSpan(offset, Math.Min(4096, data.Length - offset)).ToArray();
                await Task.Run(() =>
                {
                    lock (_gate)
                    {
                        ObjectDisposedException.ThrowIf(!PumpActive || _stream == null, this);
                        var pinned = GCHandle.Alloc(chunk, GCHandleType.Pinned);
                        try
                        {
                            var bytes = new BcBytes { Data = pinned.AddrOfPinnedObject(), Length = (ulong)chunk.Length };
                            Bc.Check(SerialNative.bc_serial_write(_stream!, bytes, out var accepted), "sol.title");
                            if (accepted != chunk.Length) Bc.Check(Bc.OutcomeUnknown, "sol.title");
                        }
                        finally { pinned.Free(); }
                    }
                }, cancellation).ConfigureAwait(false);
            }
        }
        finally { _writes.Release(); }
    }
    public ValueTask DisposeAsync()
    {
        lock (_gate) return new ValueTask(_dispose ??= DisposeCore());
    }
    private async Task DisposeCore()
    {
        _stop.Cancel();
        if (_pump != null) await _pump.ConfigureAwait(false);
        CloseNative();
        Bc.Check(_cleanupStatus, "sol.title");
    }
    private void CloseNative()
    {
        lock (_gate)
        {
            if (_stream == null) return;
            _cleanupStatus = SerialNative.bc_serial_close(_stream!);
            _stream!.Dispose(); _stream = null;
            _canWrite = false;
        }
    }
}

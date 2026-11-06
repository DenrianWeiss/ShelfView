using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Transport;

internal interface IConsoleSocket
{
    bool IsOpen { get; }
    void Abort();
    Task SendAsync(byte[] data, CancellationToken cancellation);
}

internal sealed class NativeConsoleSocket : IConsoleSocket, IAsyncDisposable
{
    private const int Capacity = 16 * 1024 * 1024;
    private readonly SemaphoreSlim _io = new(1), _reader = new(1);
    private readonly object _lifetime = new();
    private byte[]? _buffer;
    private IntPtr _transport;
    private bool _stopped;
    private NativeConsoleSocket(IntPtr transport) { _transport = transport; }
    public bool IsOpen { get { lock (_lifetime) return !_stopped && _transport != IntPtr.Zero; } }

    internal static IntPtr Open(Uri url, string? ca, uint policy, uint tlsMin, string subprotocol,
        IReadOnlyList<string> headers, Socks5Connection? proxy, uint timeoutMs, bool binaryOnly = false)
    {
        using var address = BcStringPinned.Pin(url.AbsoluteUri);
        using var caFile = BcStringPinned.Pin(ca ?? "");
        using var protocol = BcStringPinned.Pin(subprotocol);
        var pins = new List<BcStringPinned>();
        var values = IntPtr.Zero;
        try
        {
            var size = Marshal.SizeOf<BcString>();
            values = Marshal.AllocHGlobal(checked(size * headers.Count));
            for (var i = 0; i < headers.Count; i++)
            {
                var pin = BcStringPinned.Pin(headers[i]); pins.Add(pin);
                Marshal.StructureToPtr(pin.Value, values + size * i, false);
            }
            var options = new BcKvmTransportOptions { StructSize = (uint)Marshal.SizeOf<BcKvmTransportOptions>(),
                AbiVersion = Bc.AbiVersion, Url = address.Value, CaFile = caFile.Value, CertPolicy = policy,
                TlsMin = tlsMin, Flags = binaryOnly ? 4u : 0u, TimeoutMs = Math.Max(1, timeoutMs), Subprotocols = protocol.Value,
                Headers = values, HeaderCount = (uint)headers.Count };
            Bc.Check(NativeConnections.Connect(ref options, proxy, out var transport), "kvm.title");
            return transport;
        }
        finally
        {
            foreach (var pin in pins) pin.Dispose();
            Marshal.FreeHGlobal(values);
        }
    }
    internal static async Task<NativeConsoleSocket> ConnectAsync(Uri url, string? ca, uint policy, uint tlsMin,
        string subprotocol, IReadOnlyList<string> headers, Socks5Connection? proxy, uint timeoutMs, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        var transport = await Task.Run(() => {
            cancellation.ThrowIfCancellationRequested();
            return Open(url, ca, policy, tlsMin, subprotocol, headers, proxy, timeoutMs, binaryOnly: true);
        }).ConfigureAwait(false);
        try
        {
            cancellation.ThrowIfCancellationRequested();
            return new(transport);
        }
        catch { NativeMethods.bc_kvm_transport_interrupt(transport);
            await Task.Run(() => NativeMethods.bc_kvm_transport_destroy(transport)).ConfigureAwait(false); throw; }
    }
    public void Abort()
    {
        lock (_lifetime)
        {
            _stopped = true;
            if (_transport != IntPtr.Zero) NativeMethods.bc_kvm_transport_interrupt(_transport);
        }
    }
    private IntPtr Handle()
    {
        lock (_lifetime)
        {
            if (_stopped || _transport == IntPtr.Zero) throw new OperationCanceledException();
            return _transport;
        }
    }
    public async Task SendAsync(byte[] data, CancellationToken cancellation)
    {
        if (data.Length > Capacity) Bc.Check(Bc.LimitExceeded, "core.kvmInput");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        await _io.WaitAsync(timeout.Token).ConfigureAwait(false);
        try
        {
            var transport = Handle();
            using var registration = timeout.Token.Register(Abort);
            timeout.Token.ThrowIfCancellationRequested();
            var status = await Task.Run(() => NativeMethods.bc_kvm_transport_send(transport, data, (uint)data.Length)).ConfigureAwait(false);
            timeout.Token.ThrowIfCancellationRequested();
            if (status != Bc.Ok) Abort();
            Bc.Check(status, "core.kvmInput");
        }
        finally { _io.Release(); }
    }
    internal async Task<byte[]> ReceiveAsync(CancellationToken cancellation)
    {
        await _reader.WaitAsync(cancellation).ConfigureAwait(false);
        try
        {
            using var registration = cancellation.Register(Abort);
            while (true)
            {
                await _io.WaitAsync(cancellation).ConfigureAwait(false);
                try
                {
                    var transport = Handle();
                    cancellation.ThrowIfCancellationRequested();
                    var buffer = _buffer ??= new byte[Capacity];
                    var result = await Task.Run(() => {
                        var status = NativeMethods.bc_kvm_transport_recv(transport, buffer, Capacity, out var count, 20);
                        return (status, count);
                    }).ConfigureAwait(false);
                    cancellation.ThrowIfCancellationRequested();
                    if (result.status == Bc.Timeout) continue;
                    if (result.status != Bc.Ok) Abort();
                    Bc.Check(result.status, "kvm.title");
                    return buffer.AsSpan(0, checked((int)result.count)).ToArray();
                }
                finally { _io.Release(); }
            }
        }
        finally { _reader.Release(); }
    }
    public async ValueTask DisposeAsync()
    {
        Abort();
        await _io.WaitAsync().ConfigureAwait(false);
        try
        {
            IntPtr transport;
            lock (_lifetime) { transport = _transport; _transport = IntPtr.Zero; }
            _buffer = null;
            if (transport != IntPtr.Zero)
                await Task.Run(() => NativeMethods.bc_kvm_transport_destroy(transport)).ConfigureAwait(false);
        }
        finally { _io.Release(); }
    }
}

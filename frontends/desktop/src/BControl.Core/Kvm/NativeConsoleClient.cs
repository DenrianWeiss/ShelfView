using System.Runtime.InteropServices;
using BControl.Core.Media;
using BControl.Core.Redfish;
using BControl.Core.Native;

namespace BControl.Core.Kvm;

public sealed class NativeConsoleClient : IKvmSession, ILocalMediaConsole, ILocalMediaSession, IConsoleProtocol
{
    private sealed record Snapshot(ConsoleClientInfo Info);
    private Snapshot _snapshot = new(default);
    private ConsoleClientInfo Info => Volatile.Read(ref _snapshot).Info;
    private IntPtr _client;
    private readonly CancellationTokenSource _stop = new();
    private readonly SemaphoreSlim _io = new(1);
    private readonly object _lifetime = new();
    private readonly ClientCancelled _cancelled;
    private readonly ClientConfirm _confirm;
    private readonly CoreDecodeQueue _decode;
    private readonly ConsoleConnectionOptions _options;
    private LocalIsoSource? _source;
    private NativeConsoleClient? _parent;
    private int _children;
    private volatile bool _disposeRequested;
    private Task? _reader, _dispose;
    private KvmFrame? _frame;
    public event Action<KvmFrame>? FrameReceived;
    public event Action<string>? Failed;
    public event Action? Closed;
    public KvmFrame? LatestFrame => Volatile.Read(ref _frame);
    public bool IsConnected => !_disposeRequested && Info.State == ConsoleClientNative.Active && !_stop.IsCancellationRequested;
    public bool SupportsScroll => (Info.Flags & ConsoleClientNative.Scroll) != 0;
    public bool LocalMediaAvailable => IsConnected && (Info.Flags & ConsoleClientNative.LocalMedia) != 0;
    public bool CleanupSucceeded {
        get {
            var info = Info;
            return info.StructSize == 0 || info.State == ConsoleClientNative.Closed && info.CleanupStatus == Bc.Ok
                && (info.Flags & ConsoleClientNative.RemovalUnconfirmed) == 0;
        }
    }
    public string Name => _source?.Name ?? "";
    public (ulong Requests, ulong Bytes)? Statistics => _source?.Statistics;
    public bool IsActive => Info.State == ConsoleClientNative.Active && !_stop.IsCancellationRequested;
    public bool SourceAttached => (Info.Flags & ConsoleClientNative.SourceAttached) != 0;
    public bool MountConfirmed => (Info.Flags & ConsoleClientNative.MountConfirmed) != 0;
    public bool? DependsOnConsole => (Info.Flags & ConsoleClientNative.Dependent) != 0;
    public bool RemovalUnconfirmed => (Info.Flags & ConsoleClientNative.RemovalUnconfirmed) != 0;
    public string? Error { get; private set; }
    BcServiceProfile IConsoleProtocol.Profile => Info.Profile;
    BcConsoleFailure IConsoleProtocol.Failure => Info.Failure;

    private NativeConsoleClient(ConsoleConnectionOptions options, LocalIsoSource? source = null)
    {
        _options = options; _source = source;
        _decode = new(Present);
        _cancelled = _ => _stop.IsCancellationRequested ? 1 : 0;
        _confirm = (_, remaining) => {
            if (_stop.IsCancellationRequested || options.ConfirmPrivate == null) return 0;
            using var confirmation = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            confirmation.CancelAfter(TimeSpan.FromMilliseconds(remaining));
            try { return options.ConfirmPrivate(remaining, confirmation.Token).WaitAsync(confirmation.Token).GetAwaiter().GetResult() ? 1 : 0; }
            catch (OperationCanceledException) { return 0; }
            catch (TimeoutException) { return 0; }
            catch { return 0; }
        };
    }
    private void Create(DeviceCredential credential, IntPtr parent = default)
    {
        using var address = BcStringPinned.Pin(_options.Address);
        using var username = BcStringPinned.Pin(credential.Username);
        using var password = BcStringPinned.Pin(credential.Password);
        using var ca = BcStringPinned.Pin(_options.CaFile);
        var sourcePointer = IntPtr.Zero;
        try {
            if (_source != null) {
                sourcePointer = Marshal.AllocHGlobal(Marshal.SizeOf<BcMediaSource>());
                Marshal.StructureToPtr(_source.Native, sourcePointer, false);
            }
            var options = new ConsoleClientOptions {
                StructSize = (uint)Marshal.SizeOf<ConsoleClientOptions>(), AbiVersion = Bc.AbiVersion,
                Service = _source == null ? ConsoleClientNative.Console : ConsoleClientNative.Media, TimeoutMs = _options.Timeout?.Milliseconds ?? 60000,
                Address = address.Value, Username = username.Value, Password = password.Value, CaFile = ca.Value,
                CertPolicy = _options.CertPolicy, TlsMin = _options.MinimumTls, Source = sourcePointer,
                HttpContract = (uint)_options.HttpConnection, Preferred = _options.Protocol?.Profile ?? default,
                Submit = Marshal.GetFunctionPointerForDelegate(_decode.Submit),
                Cancelled = Marshal.GetFunctionPointerForDelegate(_cancelled), Confirm = Marshal.GetFunctionPointerForDelegate(_confirm)
            };
            uint CreateCore() => parent == IntPtr.Zero
                ? ConsoleClientNative.bc_console_client_create(ref options, out _client)
                : ConsoleClientNative.bc_console_client_media_create(parent, ref options, out _client);
            using var proxy = _options.Proxy?.Pin();
            var pointer = IntPtr.Zero;
            uint status;
            try {
                if (proxy != null) {
                    pointer = Marshal.AllocHGlobal(Marshal.SizeOf<BcSocks5Proxy>());
                    Marshal.StructureToPtr(proxy.Value, pointer, false); options.Proxy = pointer;
                }
                status = CreateCore();
            }
            finally { if (pointer != IntPtr.Zero) Marshal.FreeHGlobal(pointer); }
            Bc.Check(status, "kvm.title");
        }
        finally { if (sourcePointer != IntPtr.Zero) Marshal.FreeHGlobal(sourcePointer); }
    }
    public static async Task<NativeConsoleClient> ConnectAsync(ConsoleConnectionOptions options, DeviceCredential credential)
    {
        var client = new NativeConsoleClient(options);
        return await client.StartAsync(credential).ConfigureAwait(false);
    }
    internal static async Task<NativeConsoleClient> OpenMediaAsync(ConsoleConnectionOptions options, DeviceCredential credential, string path)
    {
        var client = new NativeConsoleClient(options, new LocalIsoSource(path));
        return await client.StartAsync(credential).ConfigureAwait(false);
    }
    private async Task<NativeConsoleClient> StartAsync(DeviceCredential credential, IntPtr parent = default)
    {
        using var cancellation = _options.Cancellation.Register(() => _stop.Cancel());
        try {
            _options.Cancellation.ThrowIfCancellationRequested();
            await Task.Run(() => { if (_source == null) Diagnostics.StartupAssets.Clear(_options.Address); Create(credential, parent); var status = ConsoleClientNative.bc_console_client_start(_client); if (_source == null) Diagnostics.StartupAssets.Capture(_client, _options.Address); SnapshotCore(); CheckStatus(status); }).ConfigureAwait(false);
            if ((Info.Flags & ConsoleClientNative.Dependent) == 0) await ReleaseParentAsync().ConfigureAwait(false);
            _reader = Task.Run(ReadLoopAsync);
            return this;
        }
        catch (Exception error) {
            if (_client != IntPtr.Zero) SnapshotCore();
            var profile = Info.Profile; var failure = Info.Failure;
            await DisposeAsync().ConfigureAwait(false);
            error.Data[ConsoleAttempt.Key] = new ConsoleAttempt(profile, failure, CleanupSucceeded);
            if (_source != null && RemovalUnconfirmed) throw new MediaStartupException(this, error);
            throw;
        }
    }
    private void CheckStatus(uint status)
    {
        if (status == Bc.Ok) return;
        if ((Info.Flags & ConsoleClientNative.HttpChoice) != 0) throw new ConsoleHttpSelectionRequiredException();
        if ((Info.Flags & ConsoleClientNative.LayoutChoice) != 0) throw new ConsoleLayoutSelectionRequiredException();
        if (status == Bc.Cancelled && _stop.IsCancellationRequested) throw new OperationCanceledException(_options.Cancellation);
        if (Info.Failure.Status == status) throw new ConsoleFailureException(Info.Failure);
        Bc.Check(status, "kvm.title");
    }
    public LocalMediaSnapshot MediaSnapshot()
    {
        var info = Info;
        return new(info.State == ConsoleClientNative.Active && !_stop.IsCancellationRequested,
            (info.Flags & ConsoleClientNative.SourceAttached) != 0, (info.Flags & ConsoleClientNative.MountConfirmed) != 0,
            Error ?? (info.Status == Bc.Ok ? null : Bc.StatusText(info.Status)));
    }
    private void SnapshotCore()
    {
        var info = new ConsoleClientInfo { StructSize = (uint)Marshal.SizeOf<ConsoleClientInfo>() };
        Bc.Check(ConsoleClientNative.bc_console_client_info_get(_client, ref info), "kvm.title");
        Volatile.Write(ref _snapshot, new(info));
    }
    private void Present()
    {
        var tile = new BcDisplayTile { StructSize = (uint)Marshal.SizeOf<BcDisplayTile>() };
        var status = ConsoleClientNative.bc_console_client_tile(_client, ref tile);
        if (status == Bc.Busy) return;
        Bc.Check(status, "kvm.title");
        KvmFrame frame;
        try {
            var pixels = new byte[checked((int)tile.Pixels.Length)];
            Marshal.Copy(tile.Pixels.Data, pixels, 0, pixels.Length);
            frame = new(tile.CanvasWidth, tile.CanvasHeight, tile.Stride, "", pixels);
        }
        finally { ConsoleClientNative.bc_console_client_ack_display(_client); }
        Volatile.Write(ref _frame, frame); FrameReceived?.Invoke(frame);
    }
    private async Task ReadLoopAsync()
    {
        try {
            while (!_stop.IsCancellationRequested) {
                _decode.ThrowIfFailed();
                await _io.WaitAsync(_stop.Token).ConfigureAwait(false);
                try {
                    var status = ConsoleClientNative.bc_console_client_poll(_client, 20); SnapshotCore();
                    if (!_stop.IsCancellationRequested && status != Bc.Timeout) CheckStatus(status);
                }
                finally { _io.Release(); }
                await Task.Delay(1, _stop.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (Exception error) { Error = error.Message; Failed?.Invoke(error.Message); _stop.Cancel(); }
        finally { Closed?.Invoke(); }
    }
    public Task SendKeyAsync(int down, uint keysym)
    {
        if (down is not (0 or 1)) throw new ArgumentOutOfRangeException(nameof(down));
        return Input(new() { Type = 1, Keysym = keysym, Down = (uint)down });
    }
    public Task SendChordAsync(IReadOnlyList<uint> keys)
    {
        var copy = ConsoleNative.CopyChord(keys);
        lock (_lifetime) if (IsConnected) Bc.Check(ConsoleClientNative.bc_console_client_chord(_client, copy, (uint)copy.Length), "kvm.title");
        return Task.CompletedTask;
    }
    public Task SendPointerAsync(byte buttons, ushort x, ushort y) => SendScrollAsync(buttons, x, y, 0);
    public Task SendScrollAsync(byte buttons, ushort x, ushort y, sbyte wheel)
    {
        if (LatestFrame is not { } frame) return Task.CompletedTask;
        return Input(new() { Type = wheel == 0 ? 2u : 3u, Buttons = buttons, X = Math.Min(x, frame.Width - 1),
            Y = Math.Min(y, frame.Height - 1), Width = frame.Width, Height = frame.Height, Wheel = wheel });
    }
    private Task Input(BcConsoleInput input)
    {
        input.StructSize = (uint)Marshal.SizeOf<BcConsoleInput>();
        lock (_lifetime) if (IsConnected) Bc.Check(ConsoleClientNative.bc_console_client_input(_client, ref input), "kvm.title");
        return Task.CompletedTask;
    }
    public async Task<ILocalMediaSession> MountIsoAsync(string path)
    {
        var child = new NativeConsoleClient(_options, new LocalIsoSource(path));
        try {
            lock (_lifetime) {
                if (!IsConnected) throw new ObjectDisposedException(nameof(NativeConsoleClient));
                ++_children; child._parent = this;
            }
            return await child.StartAsync(new("", ""), _client).ConfigureAwait(false);
        }
        catch { await child.DisposeAsync().ConfigureAwait(false); throw; }
    }
    public async Task<bool> CloseMediaAsync()
    {
        await DisposeAsync().ConfigureAwait(false);
        return CleanupSucceeded;
    }
    public async Task<bool> EjectAsync()
    {
        await _io.WaitAsync().ConfigureAwait(false);
        try {
            if (_client == IntPtr.Zero || _disposeRequested) return !RemovalUnconfirmed;
            var status = await Task.Run(() => ConsoleClientNative.bc_console_client_eject(_client)).ConfigureAwait(false);
            SnapshotCore(); if (status != Bc.Ok) Error = Bc.StatusText(status);
            return status == Bc.Ok && !RemovalUnconfirmed;
        }
        finally { _io.Release(); }
    }
    public ValueTask DisposeAsync()
    {
        lock (_lifetime) {
            _disposeRequested = true;
            if (_children != 0) return ValueTask.CompletedTask;
            return new(_dispose ??= CloseAsync());
        }
    }
    private async Task CloseAsync()
    {
        _stop.Cancel();
        if (_reader != null) await _reader.ConfigureAwait(false);
        await _decode.DisposeAsync().ConfigureAwait(false);
        await _io.WaitAsync().ConfigureAwait(false);
        try { await Task.Run(() => {
            lock (_lifetime) {
                if (_client != IntPtr.Zero) {
                    ConsoleClientNative.bc_console_client_close(_client); SnapshotCore();
                    ConsoleClientNative.bc_console_client_destroy(_client); _client = IntPtr.Zero;
                }
            }
        }).ConfigureAwait(false); }
        finally { _io.Release(); }
        _source?.Dispose();
        await ReleaseParentAsync().ConfigureAwait(false);
        GC.KeepAlive(_cancelled); GC.KeepAlive(_confirm);
    }
    private async Task ReleaseParentAsync()
    {
        if (_parent is { } parent) {
            _parent = null; bool close;
            lock (parent._lifetime) { --parent._children; close = parent._disposeRequested && parent._children == 0; }
            if (close) await parent.DisposeAsync().ConfigureAwait(false);
        }
    }

}

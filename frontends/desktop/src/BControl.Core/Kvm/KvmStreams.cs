using System.Threading.Channels;

namespace BControl.Core.Kvm;

public abstract record KvmInputEvent
{
    public sealed record Key(int Down, uint Keysym) : KvmInputEvent;
    public sealed record Pointer(byte Buttons, ushort X, ushort Y) : KvmInputEvent;
    public sealed record Scroll(byte Buttons, ushort X, ushort Y, sbyte Wheel) : KvmInputEvent;
    public sealed record Chord(IReadOnlyList<uint> Keys) : KvmInputEvent;
}

public sealed class KvmInputStream : IAsyncDisposable
{
    private sealed record Pending(KvmInputEvent Event, TaskCompletionSource Completion);
    private readonly Channel<Pending> _queue = Channel.CreateBounded<Pending>(new BoundedChannelOptions(1024)
    { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
    private readonly Task _worker;
    private Exception? _failure;

    public KvmInputStream(IKvmSession session)
    {
        _worker = Task.Run(async () =>
        {
            await foreach (var pending in _queue.Reader.ReadAllAsync())
            {
                try
                {
                    if (Volatile.Read(ref _failure) is { } failure) throw failure;
                    await session.SendInputAsync(pending.Event).ConfigureAwait(false);
                    pending.Completion.TrySetResult();
                }
                catch (Exception error)
                {
                    Interlocked.CompareExchange(ref _failure, error, null);
                    _queue.Writer.TryComplete();
                    pending.Completion.TrySetException(error);
                }
            }
        });
    }

    public Task SendAsync(KvmInputEvent input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input is KvmInputEvent.Key key && key.Down is not (0 or 1)) throw new ArgumentException("Invalid key state");
        if (input is KvmInputEvent.Chord chord)
        {
            if (chord.Keys.Count is < 1 or > 8) throw new ArgumentException("Invalid key chord");
            input = new KvmInputEvent.Chord(chord.Keys.ToArray());
        }
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_queue.Writer.TryWrite(new Pending(input, completion)))
        {
            var error = new InvalidOperationException(Localization.Loc.T("kvm.inputOverloaded"));
            Interlocked.CompareExchange(ref _failure, error, null);
            _queue.Writer.TryComplete();
            completion.SetException(_failure!);
        }
        return completion.Task;
    }

    public async ValueTask DisposeAsync()
    {
        _queue.Writer.TryComplete();
        await _worker.ConfigureAwait(false);
    }
}

public sealed class KvmVideoStream : IAsyncDisposable
{
    private readonly Channel<KvmFrame> _queue = Channel.CreateBounded<KvmFrame>(new BoundedChannelOptions(1)
    { SingleReader = true, FullMode = BoundedChannelFullMode.DropOldest });
    private readonly Task _worker;
    public KvmVideoStream(Func<KvmFrame, Task> present)
    {
        _worker = Task.Run(async () =>
        {
            await foreach (var frame in _queue.Reader.ReadAllAsync()) await present(frame).ConfigureAwait(false);
        });
    }
    // Only composed snapshots may replace older frames; never enqueue undecoded deltas here.
    public void Publish(KvmFrame frame) => _queue.Writer.TryWrite(frame);
    public async ValueTask DisposeAsync() { _queue.Writer.TryComplete(); await _worker.ConfigureAwait(false); }
}

// Bridges the ordered input stream to a protocol-owned scheduler without an
// unbounded second queue or reporting completion before the action runs.
internal sealed class KvmInputDispatcher
{
    private readonly object _gate = new();
    private readonly Queue<(Action Action, TaskCompletionSource Done)> _queue = new();
    private bool _closed;

    public Task Enqueue(Action action)
    {
        lock (_gate)
        {
            if (_closed) return Task.FromException(new ObjectDisposedException(nameof(KvmInputDispatcher)));
            if (_queue.Count >= 1024)
                return Task.FromException(new InvalidOperationException(Localization.Loc.T("kvm.inputOverloaded")));
            var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _queue.Enqueue((action, done));
            return done.Task;
        }
    }

    public void Drain()
    {
        while (true)
        {
            (Action Action, TaskCompletionSource Done) pending;
            lock (_gate) { if (!_queue.TryDequeue(out pending)) return; }
            try { pending.Action(); pending.Done.TrySetResult(); }
            catch (Exception error) { pending.Done.TrySetException(error); throw; }
        }
    }

    public void Close()
    {
        lock (_gate)
        {
            _closed = true;
            while (_queue.TryDequeue(out var pending))
                pending.Done.TrySetException(new ObjectDisposedException(nameof(KvmInputDispatcher)));
        }
    }
}

// Compressed deltas must remain ordered; unlike composed display snapshots they
// cannot be replaced with the newest frame. Overflow terminates the stream.
internal sealed class KvmDecodeStream<T> : IAsyncDisposable
{
    private readonly Channel<(T Value, int Bytes)> _queue = Channel.CreateBounded<(T, int)>(
        new BoundedChannelOptions(256) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
    private readonly Task _worker;
    private readonly int _capacity;
    private int _bytes;
    private volatile bool _stopping;
    private Exception? _failure;

    public KvmDecodeStream(Action<T> decode, int capacity = 32 * 1024 * 1024, Action<T>? release = null)
    {
        _capacity = capacity;
        _worker = Task.Run(async () =>
        {
            await foreach (var pending in _queue.Reader.ReadAllAsync())
            {
                try
                {
                    try { if (!_stopping) decode(pending.Value); }
                    finally { release?.Invoke(pending.Value); }
                }
                catch (Exception error)
                {
                    Interlocked.CompareExchange(ref _failure, error, null);
                    _stopping = true;
                    _queue.Writer.TryComplete();
                }
                finally { Interlocked.Add(ref _bytes, -pending.Bytes); }
            }
        });
    }

    public void ThrowIfFailed()
    {
        if (Volatile.Read(ref _failure) is { } error) throw error;
    }

    public void Submit(T value, int bytes)
    {
        ThrowIfFailed();
        if (_stopping) throw new ObjectDisposedException(nameof(KvmDecodeStream<T>));
        if (bytes < 0 || bytes > _capacity) throw new ArgumentOutOfRangeException(nameof(bytes));
        var total = Interlocked.Add(ref _bytes, bytes);
        if (total <= _capacity && _queue.Writer.TryWrite((value, bytes))) return;
        Interlocked.Add(ref _bytes, -bytes);
        var failure = new Native.BcException(Native.Bc.LimitExceeded, Native.Bc.StatusText(Native.Bc.LimitExceeded));
        Interlocked.CompareExchange(ref _failure, failure, null);
        _stopping = true;
        _queue.Writer.TryComplete();
        ThrowIfFailed();
    }

    public async ValueTask DisposeAsync()
    {
        _stopping = true;
        _queue.Writer.TryComplete();
        await _worker.ConfigureAwait(false);
    }
}

internal static class KvmPointer
{
    internal static async Task RfbScrollAsync(Func<byte, ushort, ushort, Task> send,
        byte buttons, ushort x, ushort y, sbyte wheel)
    {
        if (wheel == 0) return;
        buttons &= 7;
        try { await send((byte)(buttons | (wheel > 0 ? 8 : 16)), x, y).ConfigureAwait(false); }
        finally { await send(buttons, x, y).ConfigureAwait(false); }
    }
    internal static byte RfbButtons(byte hid) => (byte)((hid & ~6) | ((hid & 2) << 1) | ((hid & 4) >> 1));
}

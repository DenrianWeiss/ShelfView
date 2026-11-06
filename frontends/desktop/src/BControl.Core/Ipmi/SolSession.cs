using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Ipmi;
public sealed record SolState(uint State, uint Flags, uint ReceivePending, uint SendPending, uint Status, uint CleanupStatus, ushort Port, byte Instance);
public sealed class SolSession : ISerialSession
{
    private readonly IpmiConnection _connection;
    private readonly IntPtr _sol;
    private readonly SerialStreamHandle _stream;
    private readonly CancellationTokenSource _pumpCts = new();
    private readonly CancellationTokenRegistration _parentRegistration;
    private readonly SemaphoreSlim _writeGate = new(1);
    private readonly object _writeLock = new();
    private WriteRequest? _pending;
    private readonly Task _pump;
    private volatile SolState _lastState = new(IpmiAbi.SolActive, 0, 0, 0, Bc.Ok, Bc.Ok, 0, 1);
    private int _closed;
    private Task? _disposeTask;
    private readonly object _disposeLock = new();
    private int _bufferedBytes;
    private sealed class WriteRequest(byte[] data)
    {
        public byte[] Data { get; } = data;

        public int Offset;
        public TaskCompletionSource Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    internal SolSession(IpmiConnection connection, IntPtr sol, CancellationToken parentToken)
    {
        _connection = connection;
        _sol = sol;
        _stream = SerialStreamHandle.Borrow(sol);
        _parentRegistration = parentToken.Register(() => _pumpCts.Cancel());
        _pump = Task.Run(PumpLoop);
    }

    private readonly object _receiveLock = new();
    private readonly Queue<byte[]> _receivedBeforeSubscription = new();
    private Action<byte[]>? _received;
    public event Action<byte[]>? Received
    {
        add
        {
            lock (_receiveLock)
            {
                _received += value;
                while (_receivedBeforeSubscription.TryDequeue(out var bytes))
                    value?.Invoke(bytes);
                _bufferedBytes = 0;
            }
        }

        remove
        {
            lock (_receiveLock)
                _received -= value;
        }
    }

    public event Action<SolState>? Ended;
    public event Action? WriteAccessChanged { add { } remove { } }
    public bool CanWrite => PumpActive;
    public bool PumpActive => !_pump.IsCompleted && _closed == 0;

    private void PumpLoop()
    {
        var buffer = new byte[8192];
        uint failure = Bc.Ok;
        try
        {
            while (!_pumpCts.IsCancellationRequested)
            {
                for (var round = 0; round < 16 && !_pumpCts.IsCancellationRequested; round++)
                {
                    var status = SerialNative.bc_serial_read(_stream, IpmiConnection.NowMs(), round == 0 ? 50u : 0u,
                        buffer, (uint)buffer.Length, out var length);
                    if (status != Bc.Ok && status != Bc.Timeout) Bc.Check(status, "sol.title");
                    if (length == 0) break;
                    var bytes = buffer.AsSpan(0, (int)length).ToArray();
                    lock (_receiveLock)
                    {
                        if (_received == null)
                        {
                            _bufferedBytes += bytes.Length;
                            if (_bufferedBytes > 1024 * 1024)
                                Bc.Check(Bc.LimitExceeded, "sol.title");
                            _receivedBeforeSubscription.Enqueue(bytes);
                        }
                        else
                            _received.Invoke(bytes);
                    }
                }

                FlushWrites();
                var info = new BcIpmiSolInfo
                {
                    StructSize = (uint)Marshal.SizeOf<BcIpmiSolInfo>()
                };
                if (NativeMethods.bc_ipmi_sol_info_get(_sol, ref info) == Bc.Ok)
                {
                    _lastState = new(info.State, info.Flags, info.ReceivePending, info.SendPending, info.Status, info.CleanupStatus, info.Port, info.Instance);
                    if (info.State != IpmiAbi.SolActive)
                        break;
                }
            }
        }
        catch (BcException ex)
        {
            failure = ex.Status;
        }
        catch
        {
            failure = Bc.IoError;
        }
        finally
        {
            if (failure != Bc.Ok)
                _lastState = _lastState with
                {
                    State = IpmiAbi.SolFailed,
                    Status = failure
                };
            else if (_lastState.State == IpmiAbi.SolActive)
                _lastState = _lastState with
                {
                    State = IpmiAbi.SolClosed
                };
            lock (_writeLock)
            {
                _pending?.Done.TrySetException(new IOException(Bc.StatusText(_lastState.Status)));
                _pending = null;
            }

            Ended?.Invoke(_lastState);
        }
    }

    private void FlushWrites()
    {
        lock (_writeLock)
        {
            if (_pending is not { } request)
                return;
            var handle = GCHandle.Alloc(request.Data, GCHandleType.Pinned);
            try
            {
                var data = new BcBytes
                {
                    Data = IntPtr.Add(handle.AddrOfPinnedObject(), request.Offset),
                    Length = (ulong)(request.Data.Length - request.Offset)
                };
                var status = SerialNative.bc_serial_write(_stream, data, out var accepted);
                request.Offset += checked((int)accepted);
                if (status != Bc.Ok && status != Bc.Busy)
                    Bc.Check(status, "sol.title");
                if (request.Offset == request.Data.Length)
                {
                    _pending = null;
                    request.Done.TrySetResult();
                }
            }
            finally
            {
                handle.Free();
            }
        }
    }

    public async Task WriteAsync(byte[] data, CancellationToken cancellation = default)
    {
        await _writeGate.WaitAsync(cancellation).ConfigureAwait(false);
        try
        {
            for (var offset = 0; offset < data.Length; offset += 4096)
            {
                cancellation.ThrowIfCancellationRequested();
                var request = new WriteRequest(data.AsSpan(offset, Math.Min(4096, data.Length - offset)).ToArray());
                lock (_writeLock)
                {
                    ObjectDisposedException.ThrowIf(!PumpActive, this);
                    _pending = request;
                }

                await request.Done.Task.ConfigureAwait(false);
            }
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public Task<SolState> GetStateAsync() => Task.FromResult(_lastState);
    public ValueTask DisposeAsync()
    {
        lock (_disposeLock)
            return new ValueTask(_disposeTask ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        Interlocked.Exchange(ref _closed, 1);
        _pumpCts.Cancel();
        await _pump.ConfigureAwait(false);
        _stream.Dispose();
        await _connection.CloseSolAsync(_sol).ConfigureAwait(false);
        _parentRegistration.Dispose();
        _pumpCts.Dispose();
    }
}

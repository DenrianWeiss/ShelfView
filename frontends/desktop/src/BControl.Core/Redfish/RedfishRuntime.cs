using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Redfish;
/// <summary>libbcontrol + curl 传输的生命周期；与 Swift CurlLifecycle 相同的全局串行约束。</summary>
public sealed class RedfishRuntime : IAsyncDisposable
{
    internal static readonly object GlobalLock = new();
    private static int _activeTransports;
    private IntPtr _transport;
    private IntPtr _context;
    private Thread? _pollThread;
    private volatile bool _shutdown;
    private readonly ConcurrentQueue<Action> _work = new();
    internal Task<T> InvokeAsync<T>(Func<T> action)
    {
        if (_shutdown)
            return Task.FromException<T>(new ObjectDisposedException(nameof(RedfishRuntime)));
        var done = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        _work.Enqueue(() =>
        {
            try
            {
                done.TrySetResult(action());
            }
            catch (Exception ex)
            {
                done.TrySetException(ex);
            }
        });
        return done.Task;
    }

    private RedfishRuntime(IntPtr transport, IntPtr context)
    {
        _transport = transport;
        _context = context;
    }

    public static RedfishRuntime Create()
    {
        lock (GlobalLock)
        {
            IntPtr transport = IntPtr.Zero, context = IntPtr.Zero;
            try
            {
                Bc.Check(NativeMethods.bc_curl_transport_create(out transport), "core.createCurlTransport");
                Interlocked.Increment(ref _activeTransports);
                var options = new BcContextOptions
                {
                    StructSize = (uint)Marshal.SizeOf<BcContextOptions>(),
                    AbiVersion = Bc.AbiVersion,
                    Transport = transport,
                    MaxResponseBytes = 1024 * 1024,
                    MaxRequests = 8,
                };
                Bc.Check(NativeMethods.bc_context_create(ref options, out context), "core.createContext");
                var runtime = new RedfishRuntime(transport, context);
                runtime._pollThread = new Thread(runtime.PollLoop)
                {
                    IsBackground = true,
                    Name = "bcontrol-redfish-poll"
                };
                runtime._pollThread.Start();
                transport = IntPtr.Zero;
                context = IntPtr.Zero;
                return runtime;
            }
            finally
            {
                if (transport != IntPtr.Zero)
                {
                    NativeMethods.bc_curl_transport_destroy(transport);
                    Interlocked.Decrement(ref _activeTransports);
                }

                if (context != IntPtr.Zero)
                    NativeMethods.bc_context_destroy(context);
            }
        }
    }

    internal IntPtr Context => _context;

    private void PollLoop()
    {
        while (!_shutdown)
        {
            while (_work.TryDequeue(out var action))
                action();
            var status = NativeMethods.bc_context_poll(_context, 10);
            if (status != Bc.Ok && status != Bc.ShuttingDown)
                break;
        }

        while (_work.TryDequeue(out var action))
            action();
        NativeMethods.bc_context_poll(_context, 0);
    }

    public async ValueTask DisposeAsync()
    {
        if (_shutdown)
            return;
        _shutdown = true;
        await Task.Run(() =>
        {
            // 先停止 poll，避免 shutdown 与 poll 同时改动请求链；再取消并在同一线程排空回调。
            _pollThread?.Join();
            NativeMethods.bc_context_shutdown(_context);
            NativeMethods.bc_context_poll(_context, 0);
            Bc.Check(NativeMethods.bc_context_destroy(_context), "core.destroyContext");
        }).ConfigureAwait(false);
        _context = IntPtr.Zero;
        lock (GlobalLock)
        {
            NativeMethods.bc_curl_transport_destroy(_transport);
            Interlocked.Decrement(ref _activeTransports);
        }

        _transport = IntPtr.Zero;
    }
}

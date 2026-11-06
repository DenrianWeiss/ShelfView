using BControl.Core.Native;

namespace BControl.Core.Kvm;

internal sealed class CoreDecodeQueue : IAsyncDisposable
{
    private readonly KvmDecodeStream<IntPtr> _stream;
    internal ConsoleNative.DecodeSubmit Submit { get; }

    internal CoreDecodeQueue(Action present)
    {
        _stream = new KvmDecodeStream<IntPtr>(job =>
        {
            Bc.Check(ConsoleNative.bc_decode_job_execute(job), "kvm.title");
            present();
        }, release: ConsoleNative.bc_decode_job_destroy);
        Submit = (_, job) =>
        {
            try
            {
                _stream.Submit(job, checked((int)ConsoleNative.bc_decode_job_size(job)));
                return Bc.Ok;
            }
            catch (BcException error) { return error.Status; }
            catch { return Bc.LimitExceeded; }
        };
    }

    internal void ThrowIfFailed() => _stream.ThrowIfFailed();
    public ValueTask DisposeAsync() => _stream.DisposeAsync();
}

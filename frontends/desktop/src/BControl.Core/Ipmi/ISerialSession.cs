namespace BControl.Core.Ipmi;
public interface ISerialSession : IAsyncDisposable
{
    event Action<byte[]>? Received;
    event Action<SolState>? Ended;
    event Action? WriteAccessChanged;
    bool CanWrite { get; }
    bool PumpActive { get; }
    Task WriteAsync(byte[] data, CancellationToken cancellation = default);
}

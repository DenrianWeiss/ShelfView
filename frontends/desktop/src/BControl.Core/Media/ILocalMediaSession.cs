namespace BControl.Core.Media;
public sealed record LocalMediaSnapshot(bool Active, bool SourceAttached, bool Mounted, string? FailureMessage);

public interface ILocalMediaSession : IAsyncDisposable
{
    string Name { get; }

    (ulong Requests, ulong Bytes)? Statistics => null;

    bool IsActive { get; }
    bool SourceAttached => IsActive;
    // Protocol acknowledgement or management readback, not channel readiness.
    bool MountConfirmed => false;

    bool RemovalUnconfirmed { get; }
    bool? DependsOnConsole => null;

    string? Error { get; }

    LocalMediaSnapshot MediaSnapshot() => new(IsActive, SourceAttached, MountConfirmed, Error);

    Task<bool> EjectAsync();
    async Task<bool> CloseMediaAsync()
    {
        await DisposeAsync().ConfigureAwait(false);
        return !RemovalUnconfirmed;
    }
}

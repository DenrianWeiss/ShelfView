using System.Security.Cryptography;
using BControl.Core.Storage;

namespace BControl.Core.Media;
public interface IMediaRecoveryStore
{
    Task<bool> ReadPendingAsync(CancellationToken cancellation = default);
    Task BeginAsync(CancellationToken cancellation = default);
    Task ClearAsync(CancellationToken cancellation = default);
    Task ClearObservedAsync(CancellationToken cancellation = default) => ClearAsync(cancellation);
    Task AcknowledgeAsync(CancellationToken cancellation = default) => ClearAsync(cancellation);
    Task<IMediaRecoveryObservation> ObserveAsync(CancellationToken cancellation = default);
}
public interface IMediaRecoveryObservation : IDisposable
{
    MediaRecoveryState State { get; }
    Task ClearAsync(CancellationToken cancellation = default);
}
public sealed class VaultMediaRecoveryStore : IMediaRecoveryStore
{
    private readonly VaultStorageSession _session;
    private readonly VaultMediaScope _scope;
    public VaultMediaRecoveryStore(VaultStorageSession session, string address, string username)
    {
        _session = session; _scope = new(address, username);
    }
    public async Task<bool> ReadPendingAsync(CancellationToken cancellation = default)
    {
        var data = await _session.SnapshotAsync(cancellation).ConfigureAwait(false);
        try { return await Task.Run(() => _scope.Read(data).Pending, cancellation).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(data); }
    }
    public async Task<IMediaRecoveryObservation> ObserveAsync(CancellationToken cancellation = default)
    {
        var data = await _session.SnapshotAsync(cancellation).ConfigureAwait(false);
        try { return await Task.Run<IMediaRecoveryObservation>(() => {
            var observation = _scope.Observe(data);
            return new Observation(_session, observation.Scope, observation.State);
        }, cancellation).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(data); }
    }
    private sealed class Observation(VaultStorageSession session, VaultMediaScope scope, MediaRecoveryState state) : IMediaRecoveryObservation
    {
        public MediaRecoveryState State => state;
        public Task ClearAsync(CancellationToken cancellation = default) => session.UpdateAsync(snapshot => {
            using var patch = scope.Patch(snapshot, MediaRecoveryOperation.ClearObserved); return patch.Export();
        }, cancellation);
        public void Dispose() => scope.Dispose();
    }
    public Task BeginAsync(CancellationToken cancellation = default) => UpdateAsync(MediaRecoveryOperation.Begin, cancellation);
    public Task ClearAsync(CancellationToken cancellation = default) => UpdateAsync(MediaRecoveryOperation.Clear, cancellation);
    public Task ClearObservedAsync(CancellationToken cancellation = default) => UpdateAsync(MediaRecoveryOperation.ClearObserved, cancellation);
    public Task AcknowledgeAsync(CancellationToken cancellation = default) => UpdateAsync(MediaRecoveryOperation.Acknowledge, cancellation);
    private Task UpdateAsync(MediaRecoveryOperation operation, CancellationToken cancellation) => _session.UpdateAsync(snapshot => {
        using var patch = _scope.Patch(snapshot, operation); return patch.Export();
    }, cancellation);
}

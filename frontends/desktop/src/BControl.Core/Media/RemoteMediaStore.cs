using System.Security.Cryptography;
using BControl.Core.Storage;

namespace BControl.Core.Media;

public interface IRemoteMediaStore
{
    Task<RemoteMediaOperation?> RejectAsync(string uri, string expectedOperationId, CancellationToken cancellation = default);
    Task<RemoteMediaOperation> ObserveSourceAsync(string uri, string expectedOperationId, string? reportedSource,
        bool completed, CancellationToken cancellation = default, bool inserted = true);
    Task<IReadOnlyList<RemoteMediaOperation>> ReadAsync(CancellationToken cancellation = default);
    Task<RemoteMediaOperation?> UpdateAsync(string uri, string? expectedOperationId, RemoteMediaAction action,
        RemoteMediaPhase phase, byte[]? reference = null, CancellationToken cancellation = default, string? source = null);
}

public sealed class VaultRemoteMediaStore(VaultStorageSession session, string address, string username) : IRemoteMediaStore
{
    private readonly VaultMediaScope _scope = new(address, username);
    public async Task<RemoteMediaOperation?> RejectAsync(string uri, string expectedOperationId, CancellationToken cancellation = default)
    {
        RemoteMediaOperation? result = null;
        await session.UpdateAsync(snapshot => {
            using var patch = _scope.RejectRemote(snapshot, uri, expectedOperationId);
            var updated = patch.Export();
            try { result = _scope.ReadRemote(updated).SingleOrDefault(item => item.MediaUri == uri); return updated; }
            catch { CryptographicOperations.ZeroMemory(updated); throw; }
        }, cancellation).ConfigureAwait(false);
        return result;
    }
    public async Task<IReadOnlyList<RemoteMediaOperation>> ReadAsync(CancellationToken cancellation = default)
    {
        var data = await session.SnapshotAsync(cancellation).ConfigureAwait(false);
        try { return await Task.Run(() => _scope.ReadRemote(data), cancellation).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(data); }
    }
    public async Task<RemoteMediaOperation?> UpdateAsync(string uri, string? expectedOperationId, RemoteMediaAction action,
        RemoteMediaPhase phase, byte[]? reference = null, CancellationToken cancellation = default, string? source = null)
    {
        RemoteMediaOperation? result = null;
        await session.UpdateAsync(snapshot => {
            using var patch = _scope.PatchRemote(snapshot, uri, expectedOperationId, action, phase, reference, source);
            var updated = patch.Export();
            try { result = _scope.ReadRemote(updated).SingleOrDefault(item => item.MediaUri == uri); return updated; }
            catch { CryptographicOperations.ZeroMemory(updated); throw; }
        }, cancellation).ConfigureAwait(false);
        return result;
    }
    public async Task<RemoteMediaOperation> ObserveSourceAsync(string uri, string expectedOperationId, string? reportedSource,
        bool completed, CancellationToken cancellation = default, bool inserted = true)
    {
        RemoteMediaOperation? result = null;
        await session.UpdateAsync(snapshot => {
            using var patch = _scope.ObserveRemoteSource(snapshot, uri, expectedOperationId, reportedSource, completed, inserted);
            var updated = patch.Export();
            try { result = _scope.ReadRemote(updated).Single(item => item.MediaUri == uri); return updated; }
            catch { CryptographicOperations.ZeroMemory(updated); throw; }
        }, cancellation).ConfigureAwait(false);
        return result ?? throw new InvalidDataException();
    }

}

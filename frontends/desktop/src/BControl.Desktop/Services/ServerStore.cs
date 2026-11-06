using BControl.Core.Storage;

namespace BControl.Desktop.Services;

public sealed class ServerStore(VaultApplicationStore vault, string filePath)
{
    public string FilePath { get; } = filePath;
    public BControl.Core.Media.IRemoteMediaStore RemoteMediaFor(ServerRecord record) => vault.RemoteMediaFor(record);
    public BControl.Core.Media.IMediaRecoveryStore MediaRecoveryFor(ServerRecord record) => vault.MediaRecoveryFor(record);
    public Task ChangeMasterPasswordAsync(string password, CancellationToken cancellation = default) =>
        vault.ChangeMasterPasswordAsync(password, cancellation);
    public bool SupportsMasterPasswordChange => true;

    public Task<IReadOnlyList<string>> ListConflictsAsync(CancellationToken cancellation = default) => vault.ListConflictsAsync(cancellation);
    public Task<VaultConflictReview> OpenConflictAsync(string id, CancellationToken cancellation = default) => vault.OpenConflictAsync(id, cancellation);
    public Task<bool> ApplyConflictAsync(VaultConflictReview review, IReadOnlyDictionary<uint, VaultMergeChoice> choices, VaultMergeChoice? version, CancellationToken cancellation = default) => vault.ApplyConflictAsync(review, choices, version, cancellation);
    public Task ReloadCurrentAsync(CancellationToken cancellation = default) => vault.ReloadCurrentAsync(cancellation);

    public static string DefaultPath()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrEmpty(home))
            home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var dir = Path.Combine(home, "bControl");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "servers.json");
    }

    public Task<InventoryFile> LoadAsync(CancellationToken cancellation = default) => vault.LoadInventoryAsync(cancellation);
    public Task SaveAsync(InventoryFile inventory, CancellationToken cancellation = default) => vault.SaveInventoryAsync(inventory, cancellation);
}

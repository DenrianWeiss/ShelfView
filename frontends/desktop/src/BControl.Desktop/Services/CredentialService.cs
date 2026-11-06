using BControl.Core.Localization;
using System.Runtime.InteropServices;

namespace BControl.Desktop.Services;
public sealed record StoredCredential(string Username, string Password);
public enum CredentialPersistence
{
    SystemStore,
    EncryptedVault,
    ProcessOnly
}

public sealed record CredentialReadResult(StoredCredential? Credential, CredentialPersistence Persistence);
/// <summary>生产入口只注入已解锁的 Vault；持久化失败时保留进程副本。</summary>
public sealed class CredentialService
{
    private readonly ICredentialStore _store;
    private readonly ProcessCredentialStore _processStore = new();
    private bool _writesHealthy = true;
    public CredentialService(ICredentialStore store) => _store = store;
    internal static ICredentialStore CreateLegacyStore() => OperatingSystem.IsWindows() ? new WindowsCredentialStore()
        : OperatingSystem.IsLinux() ? new LibSecretCredentialStore() : new UnavailableCredentialStore();
    public bool PersistentStoreAvailable => _writesHealthy && _store.IsAvailable;

    public void StoreForProcess(string reference, StoredCredential credential) => _processStore.Store(reference, credential);
    public void ClearProcessCredentials() => _processStore.Clear();
    public async Task<CredentialPersistence> StoreAsync(string reference, StoredCredential credential, CancellationToken cancellation = default)
    {
        if (_writesHealthy && _store.IsAvailable)
        {
            try
            {
                await _store.StoreAsync(reference, credential.Username, credential.Password, cancellation).ConfigureAwait(false);
                _processStore.Remove(reference);
                return _store.Persistence;
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                _writesHealthy = false;
            }
        }

        _processStore.Store(reference, credential);
        return CredentialPersistence.ProcessOnly;
    }

    public async Task<CredentialReadResult> ReadAsync(string reference, string expectedUsername, CancellationToken cancellation = default)
    {
        var temporary = _processStore.Read(reference);
        if (temporary != null && temporary.Username == expectedUsername)
            return new CredentialReadResult(temporary, CredentialPersistence.ProcessOnly);
        if (_store.IsAvailable)
        {
            try
            {
                var credential = await _store.ReadCredentialAsync(reference, expectedUsername, cancellation).ConfigureAwait(false);
                if (credential != null)
                    return new CredentialReadResult(credential, _store.Persistence);
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        var process = _processStore.Read(reference);
        return new CredentialReadResult(process != null && process.Username == expectedUsername ? process : null, CredentialPersistence.ProcessOnly);
    }

    public async Task DeleteAsync(string reference, CancellationToken cancellation = default)
    {
        _processStore.Remove(reference);
        if (_store.IsAvailable) await _store.DeleteAsync(reference, cancellation).ConfigureAwait(false);
    }

}

public interface ICredentialStore
{
    bool IsAvailable { get; }
    CredentialPersistence Persistence => CredentialPersistence.SystemStore;
    async Task<StoredCredential?> ReadCredentialAsync(string reference, string expectedUsername, CancellationToken cancellation)
    {
        var password = await ReadPasswordAsync(reference, cancellation).ConfigureAwait(false);
        return password == null ? null : new(expectedUsername, password);
    }

    Task StoreAsync(string reference, string username, string password, CancellationToken cancellation);
    /// <summary>读取密码；系统库只保存密码，用户名以清单元数据为准。</summary>
    Task<string?> ReadPasswordAsync(string reference, CancellationToken cancellation);
    Task DeleteAsync(string reference, CancellationToken cancellation);
}

public sealed class UnavailableCredentialStore : ICredentialStore
{
    public bool IsAvailable => false;

    public Task StoreAsync(string reference, string username, string password, CancellationToken cancellation) => Task.FromException(new InvalidOperationException(Loc.T("error.credentialStoreUnavailable")));
    public Task<string?> ReadPasswordAsync(string reference, CancellationToken cancellation) => Task.FromResult<string?>(null);
    public Task DeleteAsync(string reference, CancellationToken cancellation) => Task.CompletedTask;
}

/// <summary>仅当前进程的凭据存储；进程退出即消失。</summary>
public sealed class ProcessCredentialStore
{
    private readonly object _lock = new();
    private readonly Dictionary<string, StoredCredential> _values = new();
    public void Clear()
    {
        lock (_lock)
            _values.Clear();
    }
    public void Store(string reference, StoredCredential credential)
    {
        lock (_lock)
            _values[reference] = credential;
    }

    public StoredCredential? Read(string reference)
    {
        lock (_lock)
            return _values.TryGetValue(reference, out var value) ? value : null;
    }

    public void Remove(string reference)
    {
        lock (_lock)
            _values.Remove(reference);
    }
}

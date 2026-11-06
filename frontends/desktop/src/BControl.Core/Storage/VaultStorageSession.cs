using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Storage;

public class VaultChangedException : IOException
{
    public VaultChangedException(string? message = null) : base(message ?? Loc.T("vault.changed")) { }
}

public sealed class VaultStorageSession : IAsyncDisposable
{
    private readonly object _conflictOwner = new();
    private readonly SemaphoreSlim _gate = new(1);
    private readonly string _path;
    private readonly IVaultKeyStore _keyStore;
    private VaultDocument _document;
    private byte[] _snapshot = [];
    private byte[] _sealed;
    private JsonDocument? _parsed;
    private bool _disposed;
    public bool SystemKeySaved { get; private set; }
    public bool KeyRoamingEligible { get; private set; }
    public string FilePath => _path;
    private VaultStorageSession(string path, VaultDocument document, byte[] file, IVaultKeyStore keyStore)
    {
        _keyStore = keyStore;
        _path = Path.GetFullPath(path); _document = document; _sealed = file;
        var data = document.ReadData();
        try {
            using var validated = new VaultRecordMerge(data, data, data);
            _snapshot = validated.Export();
            _parsed = JsonDocument.Parse((ReadOnlyMemory<byte>)_snapshot);
            if (_parsed.RootElement.GetProperty("vault_id").GetString() != document.Metadata.VaultId)
                throw new InvalidDataException(Loc.T("vault.invalid"));
        }
        catch { _parsed?.Dispose(); CryptographicOperations.ZeroMemory(_snapshot); document.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(data); }
    }
    public static Task<VaultStorageSession?> TryAutoOpenAsync(string path, CancellationToken cancellation = default, IVaultKeyStore? keyStore = null) => Task.Run(async () => {
        keyStore ??= new SystemVaultKeyStore();
        var file = await ReadFileAsync(path, cancellation).ConfigureAwait(false);
        var metadata = VaultDocument.ReadFileMetadata(file);
        VaultStoredKey? saved;
        try { saved = keyStore.Read(metadata); }
        catch (BcException) { return null; }
        if (saved == null) return null;
        try {
            cancellation.ThrowIfCancellationRequested();
            VaultDocument document;
            try { document = VaultDocument.OpenWithKey(file, saved.Key); }
            catch (BcException ex) when (ex.Status == Bc.AuthenticationFailed) { return null; }
            return new VaultStorageSession(path, document, file, keyStore) { SystemKeySaved = true, KeyRoamingEligible = saved.RoamingEligible };
        }
        finally { CryptographicOperations.ZeroMemory(saved.Key); }
    }, cancellation);

    public static Task<VaultStorageSession> OpenWithPasswordAsync(string path, string password, CancellationToken cancellation = default, IVaultKeyStore? keyStore = null) => Task.Run(async () => {
        var file = await ReadFileAsync(path, cancellation).ConfigureAwait(false);
        var document = VaultDocument.OpenWithPassword(file, password);
        VaultStorageSession session;
        try { cancellation.ThrowIfCancellationRequested(); session = new(path, document, file, keyStore ?? new SystemVaultKeyStore()); }
        catch { document.Dispose(); throw; }
        session.TrySaveSystemKey(); return session;
    }, cancellation);

    public static Task<VaultStorageSession> CreateAsync(string path, string password, Func<string, byte[]>? initialRecords = null,
        CancellationToken cancellation = default, IVaultKeyStore? keyStore = null) => Task.Run(async () => {
        var document = VaultDocument.Create([], password);
        byte[]? snapshot = null;
        VaultStorageSession? session = null;
        try {
            var id = document.Metadata.VaultId;
            snapshot = initialRecords?.Invoke(id) ?? Encoding.UTF8.GetBytes("{\"version\":1,\"vault_id\":\"" + id + "\",\"records\":{}}");
            document.Replace(snapshot);
            var file = document.Export();
            using (var reopened = VaultDocument.OpenWithPassword(file, password)) {
                var verified = reopened.ReadData();
                try { if (!verified.AsSpan().SequenceEqual(snapshot)) throw new InvalidDataException(Loc.T("vault.invalid")); }
                finally { CryptographicOperations.ZeroMemory(verified); }
            }
            session = new(path, document, file, keyStore ?? new SystemVaultKeyStore()); session.TrySaveSystemKey();
            cancellation.ThrowIfCancellationRequested();
            await WriteFileAsync(session._path, file, null, cancellation).ConfigureAwait(false);
            return session;
        }
        catch { if (session != null) await session.DisposeAsync(); else document.Dispose(); throw; }
        finally { if (snapshot != null) CryptographicOperations.ZeroMemory(snapshot); }
    }, cancellation);

    private void TrySaveSystemKey()
    {
        var key = _document.CopyDataKey();
        try { KeyRoamingEligible = _keyStore.Store(_document.Metadata, key, true); SystemKeySaved = true; }
        catch (BcException) { SystemKeySaved = false; KeyRoamingEligible = false; }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    public async Task<byte[]> SnapshotAsync(CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try { ObjectDisposedException.ThrowIf(_disposed, this); return _snapshot.ToArray(); }
        finally { _gate.Release(); }
    }
    // Readers return copied values; JsonElements borrowed here must not escape.
    public async Task<T> ReadAsync<T>(Func<JsonElement, T> read, CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return await Task.Run(() => read(_parsed!.RootElement), cancellation).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
    private async Task<VaultConflictException> PreserveConflictAsync(byte[] baseline, byte[] local, byte[] remote, byte[] key)
    {
        var expected = _document.Metadata;
        foreach (var version in new[] { baseline, local, remote }) {
            using var opened = VaultDocument.OpenWithKey(version, key);
            if (opened.Metadata.VaultId != expected.VaultId || opened.Metadata.KeyId != expected.KeyId) throw new VaultChangedException();
        }
        var id = await new VaultConflictArchive(_path).SaveAsync(baseline, local, remote).ConfigureAwait(false);
        return new(id);
    }
    private Task<VaultConflictException> PreserveEditAsync(byte[] next, byte[] remote, byte[] key)
    {
        using var local = VaultDocument.OpenWithKey(_sealed, key);
        local.Replace(next);
        return PreserveConflictAsync(_sealed, local.Export(), remote, key);
    }
    public async Task UpdateAsync(Func<byte[], byte[]> update, CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            ObjectDisposedException.ThrowIf(_disposed, this);
            await Task.Run(async () => {
                byte[]? next = null;
                JsonDocument? parsed = null;
                var working = _snapshot.ToArray();
                var key = _document.CopyDataKey();
                try {
                    next = update(working);
                    if (next.AsSpan().SequenceEqual(_snapshot)) {
                        if (!File.Exists(_path) || !SHA256.HashData(await ReadFileAsync(_path, cancellation).ConfigureAwait(false)).AsSpan().SequenceEqual(SHA256.HashData(_sealed)))
                            throw new VaultChangedException();
                        return;
                    }
                    using var validated = new VaultRecordMerge(next, next, next);
                    using (var localRoot = JsonDocument.Parse((ReadOnlyMemory<byte>)next))
                        if (localRoot.RootElement.GetProperty("vault_id").GetString() != _document.Metadata.VaultId) throw new InvalidDataException(Loc.T("vault.invalid"));
                    var current = await ReadFileAsync(_path, cancellation).ConfigureAwait(false);
                    var expected = _sealed;
                    if (!current.AsSpan().SequenceEqual(_sealed)) {
                        if (!VaultDocument.IsDirectChild(_sealed, current, key)) throw await PreserveEditAsync(next, current, key).ConfigureAwait(false);
                        using var remote = VaultDocument.OpenWithKey(current, key);
                        var remoteData = remote.ReadData();
                        try {
                            using var merge = new VaultRecordMerge(_snapshot, next, remoteData);
                            if (merge.Pending != 0) throw await PreserveEditAsync(next, current, key).ConfigureAwait(false);
                            var merged = merge.Export(); CryptographicOperations.ZeroMemory(next); next = merged;
                        }
                        finally { CryptographicOperations.ZeroMemory(remoteData); }
                        expected = current;
                    }
                    parsed = JsonDocument.Parse((ReadOnlyMemory<byte>)next);
                    if (parsed.RootElement.GetProperty("vault_id").GetString() != _document.Metadata.VaultId) throw new InvalidDataException(Loc.T("vault.invalid"));
                    using var candidate = VaultDocument.OpenWithKey(expected, key);
                    candidate.Replace(next); var file = candidate.Export();
                    try { await WriteFileAsync(_path, file, expected, cancellation).ConfigureAwait(false); }
                    catch (VaultChangedException) {
                        var latest = await ReadFileAsync(_path, CancellationToken.None).ConfigureAwait(false);
                        if (!latest.AsSpan().SequenceEqual(expected)) throw await PreserveConflictAsync(expected, file, latest, key).ConfigureAwait(false);
                        throw;
                    }
                    var replacement = VaultDocument.OpenWithKey(file, key);
                    _document.Dispose(); _document = replacement;
                    _parsed?.Dispose(); CryptographicOperations.ZeroMemory(_snapshot);
                    _snapshot = next; next = null; _parsed = parsed; parsed = null; _sealed = file;
                }
                finally {
                    parsed?.Dispose(); CryptographicOperations.ZeroMemory(key);
                    if (!ReferenceEquals(working, _snapshot)) CryptographicOperations.ZeroMemory(working);
                    if (next != null && !ReferenceEquals(next, _snapshot) && !ReferenceEquals(next, working)) CryptographicOperations.ZeroMemory(next);
                }
            }, cancellation).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
    public Task<IReadOnlyList<string>> ListConflictsAsync(CancellationToken cancellation = default) => Task.Run(() => new VaultConflictArchive(_path).List(), cancellation);
    public async Task<VaultConflictReview> OpenConflictAsync(string id, CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var key = _document.CopyDataKey();
            try {
                var files = await new VaultConflictArchive(_path).ReadAsync(id, cancellation).ConfigureAwait(false);
                var current = await ReadFileAsync(_path, cancellation).ConfigureAwait(false);
                var info = VaultDocument.ReadFileMetadata(files.Base);
                if (info.VaultId != _document.Metadata.VaultId || info.KeyId != _document.Metadata.KeyId) throw new VaultChangedException();
                return await Task.Run(() => VaultConflictReview.Create(_conflictOwner, id, files.Base, files.Local, current, key, VaultConflictArchive.Signature(files)), cancellation).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }
        finally { _gate.Release(); }
    }
    public async Task<VaultStorageSession> CopyEncryptedSnapshotAsync(string destination, CancellationToken cancellation = default)
    {
        destination = Path.GetFullPath(destination);
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (string.Equals(destination, _path, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new ArgumentException("The destination must differ from the current vault.", nameof(destination));
            if (!SHA256.HashData(await ReadFileAsync(_path, cancellation).ConfigureAwait(false)).AsSpan().SequenceEqual(SHA256.HashData(_sealed)))
                throw new VaultChangedException();
            if (File.Exists(destination)) throw new VaultChangedException();
            await new VaultConflictArchive(_path).CopyToAsync(new VaultConflictArchive(destination), cancellation).ConfigureAwait(false);
            await WriteFileAsync(destination, _sealed, null, cancellation).ConfigureAwait(false);
            if (!SHA256.HashData(await ReadFileAsync(destination, CancellationToken.None).ConfigureAwait(false)).AsSpan().SequenceEqual(SHA256.HashData(_sealed)))
                throw new VaultChangedException();
            var key = _document.CopyDataKey();
            try {
                var document = VaultDocument.OpenWithKey(_sealed, key);
                return new VaultStorageSession(destination, document, (byte[])_sealed.Clone(), _keyStore) {
                    SystemKeySaved = SystemKeySaved, KeyRoamingEligible = KeyRoamingEligible
                };
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }
        finally { _gate.Release(); }
    }
    public async Task ReloadCurrentAsync(CancellationToken cancellation = default, Action<JsonElement>? validate = null)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var key = _document.CopyDataKey();
            VaultDocument? candidate = null; byte[] data = []; JsonDocument? parsed = null;
            try {
                var file = await ReadFileAsync(_path, cancellation).ConfigureAwait(false);
                candidate = VaultDocument.OpenWithKey(file, key);
                if (candidate.Metadata.VaultId != _document.Metadata.VaultId || candidate.Metadata.KeyId != _document.Metadata.KeyId) throw new VaultChangedException();
                data = candidate.ReadData(); parsed = JsonDocument.Parse((ReadOnlyMemory<byte>)data);
                if (parsed.RootElement.GetProperty("vault_id").GetString() != candidate.Metadata.VaultId) throw new InvalidDataException(Loc.T("vault.invalid"));
                using var checkedData = new VaultRecordMerge(data, data, data); validate?.Invoke(parsed.RootElement);
                cancellation.ThrowIfCancellationRequested();
                _document.Dispose(); _document = candidate; candidate = null;
                _parsed?.Dispose(); _parsed = parsed; parsed = null;
                CryptographicOperations.ZeroMemory(_snapshot); _snapshot = data; data = []; _sealed = file;
            }
            finally { candidate?.Dispose(); parsed?.Dispose(); CryptographicOperations.ZeroMemory(data); CryptographicOperations.ZeroMemory(key); }
        }
        finally { _gate.Release(); }
    }
    public async Task<bool> ApplyConflictAsync(VaultConflictReview review, IReadOnlyDictionary<uint, VaultMergeChoice> choices,
        VaultMergeChoice? version = null, CancellationToken cancellation = default, Action<JsonElement>? validate = null)
    {
        var selected = choices.ToDictionary(item => item.Key, item => item.Value);
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!ReferenceEquals(review.Owner, _conflictOwner)) throw new ArgumentException(nameof(review));
            var key = _document.CopyDataKey();
            try {
                var file = await Task.Run(() => review.Export(selected, version), cancellation).ConfigureAwait(false);
                var verified = VaultDocument.OpenWithKey(file, key);
                var adopted = false;
                byte[] data = [];
                JsonDocument? parsed = null;
                try {
                    data = verified.ReadData();
                    parsed = JsonDocument.Parse((ReadOnlyMemory<byte>)data);
                    if (parsed.RootElement.GetProperty("vault_id").GetString() != _document.Metadata.VaultId) throw new InvalidDataException(Loc.T("vault.invalid"));
                    using var validated = new VaultRecordMerge(data, data, data);
                    validate?.Invoke(parsed.RootElement);
                    await WriteFileAsync(_path, file, review.Expected, cancellation).ConfigureAwait(false);
                    _document.Dispose(); _document = verified; adopted = true; _parsed?.Dispose(); _parsed = parsed; parsed = null;
                    CryptographicOperations.ZeroMemory(_snapshot); _snapshot = data; data = [];
                    _sealed = file;
                }
                finally { if (!adopted) verified.Dispose(); parsed?.Dispose(); CryptographicOperations.ZeroMemory(data); }
                return await new VaultConflictArchive(_path).CompleteAsync(review.ConflictId, review.ArchiveSignature).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }
        finally { _gate.Release(); }
    }
    public async Task ChangeMasterPasswordAsync(string password, CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            ObjectDisposedException.ThrowIf(_disposed, this);
            await Task.Run(async () => {
                var key = _document.CopyDataKey();
                try {
                    using var candidate = VaultDocument.OpenWithKey(_sealed, key);
                    candidate.ChangeMasterPassword(password); var file = candidate.Export();
                    using var verified = VaultDocument.OpenWithPassword(file, password);
                    try { await WriteFileAsync(_path, file, _sealed, cancellation).ConfigureAwait(false); }
                    catch (VaultChangedException) {
                        var latest = await ReadFileAsync(_path, CancellationToken.None).ConfigureAwait(false);
                        if (!latest.AsSpan().SequenceEqual(_sealed)) throw await PreserveConflictAsync(_sealed, file, latest, key).ConfigureAwait(false);
                        throw;
                    }
                    var replacement = VaultDocument.OpenWithKey(file, key);
                    _document.Dispose(); _document = replacement; _sealed = file;
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            }, cancellation).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
    internal static async Task<byte[]> ReadFileAsync(string path, CancellationToken cancellation)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, true);
        if (stream.Length is < 1 or > 67112960) throw new InvalidDataException(Loc.T("vault.invalid"));
        var file = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(file, cancellation).ConfigureAwait(false);
        if (stream.ReadByte() != -1) throw new VaultChangedException();
        return file;
    }
    private static async Task WriteFileAsync(string path, byte[] file, byte[]? expected, CancellationToken cancellation)
    {
        var directory = Path.GetDirectoryName(path)!; Directory.CreateDirectory(directory);
        var lockOptions = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) lockOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var writeLock = new FileStream(path + ".lock", lockOptions);
        if (expected != null) {
            if (!File.Exists(path) || !SHA256.HashData(await ReadFileAsync(path, cancellation)).AsSpan().SequenceEqual(SHA256.HashData(expected)))
                throw new VaultChangedException();
        } else if (File.Exists(path)) throw new VaultChangedException();
        var temp = Path.Combine(directory, ".vault-" + Guid.NewGuid().ToString("N") + ".tmp");
        var backup = Path.Combine(directory, ".vault-previous-" + Guid.NewGuid().ToString("N") + ".bcv");
        try {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            await using (var output = new FileStream(temp, options)) {
                await output.WriteAsync(file, cancellation).ConfigureAwait(false);
                await output.FlushAsync(cancellation).ConfigureAwait(false); output.Flush(true);
            }
            cancellation.ThrowIfCancellationRequested();
            if (expected == null) File.Move(temp, path, false);
            else {
                File.Replace(temp, path, backup, true);
                var previous = await ReadFileAsync(backup, CancellationToken.None).ConfigureAwait(false);
                if (!SHA256.HashData(previous).AsSpan().SequenceEqual(SHA256.HashData(expected))) throw new VaultChangedException();
                try { File.Delete(backup); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
        finally {
            try { if (File.Exists(temp)) File.Delete(temp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { if (_disposed) return; _disposed = true; _document.Dispose(); _parsed?.Dispose(); _parsed = null; CryptographicOperations.ZeroMemory(_snapshot); _snapshot = []; _sealed = []; }
        finally { _gate.Release(); }
    }
}

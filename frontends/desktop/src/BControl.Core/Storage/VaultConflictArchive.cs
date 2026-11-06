using BControl.Core.Localization;

namespace BControl.Core.Storage;

public sealed record VaultConflictFiles(byte[] Base, byte[] Local, byte[] Remote);

public sealed class VaultConflictException(string conflictId) : VaultChangedException(Loc.T("vault.conflictSaved"))
{
    public string ConflictId { get; } = conflictId;
}
public sealed class VaultConflictFullException() : IOException(Loc.T("vault.conflictFull"));

public sealed class VaultConflictArchive(string vaultPath)
{
    private readonly string _root = Path.GetFullPath(vaultPath) + ".conflicts-v1";
    private static readonly string[] Names = ["base.bcv", "local.bcv", "remote.bcv"];
    private const long MaximumBytes = 256L * 1024 * 1024;
    private static bool ValidId(string id) => id.Length == 32 && id.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    public IReadOnlyList<string> List() => !Directory.Exists(_root) ? [] : Directory.EnumerateDirectories(_root)
        .Select(Path.GetFileName).Where(id => id != null && ValidId(id)).Cast<string>().Order(StringComparer.Ordinal).ToArray();

    internal async Task CopyToAsync(VaultConflictArchive destination, CancellationToken cancellation)
    {
        var sourceIds = List(); var destinationIds = destination.List();
        if (sourceIds.Count > 64 || destinationIds.Count > 64) throw new VaultConflictFullException();
        var signatures = new HashSet<string>(StringComparer.Ordinal);
        long sourceBytes = 0, destinationBytes = 0;
        static void Account(VaultConflictFiles files, ref long total) {
            var size = (long)files.Base.Length + files.Local.Length + files.Remote.Length;
            if (size > MaximumBytes - total) throw new VaultConflictFullException();
            total += size;
        }
        foreach (var id in destinationIds) {
            var files = await destination.ReadAsync(id, cancellation).ConfigureAwait(false);
            Account(files, ref destinationBytes); signatures.Add(Convert.ToHexString(Signature(files)));
        }
        foreach (var id in sourceIds) {
            cancellation.ThrowIfCancellationRequested();
            var files = await ReadAsync(id, cancellation).ConfigureAwait(false);
            Account(files, ref sourceBytes);
            var signature = Convert.ToHexString(Signature(files));
            if (signatures.Contains(signature)) continue;
            await destination.SaveAsync(files.Base, files.Local, files.Remote).ConfigureAwait(false);
            signatures.Add(signature);
        }
    }
    internal async Task<string> SaveAsync(byte[] baseline, byte[] local, byte[] remote)
    {
        Directory.CreateDirectory(_root);
        var lockOptions = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) lockOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var writeLock = new FileStream(_root + ".lock", lockOptions);
        foreach (var directory in Directory.EnumerateDirectories(_root).Where(path => Path.GetExtension(path) == ".resolved" && ValidId(Path.GetFileNameWithoutExtension(path)))) {
            try { Directory.Delete(directory, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
        var directories = Directory.EnumerateDirectories(_root).Take(65).ToArray();
        long size = (long)baseline.Length + local.Length + remote.Length;
        if (directories.Length >= 64) throw new VaultConflictFullException();
        if (size > MaximumBytes) throw new VaultConflictFullException();
        foreach (var directory in directories)
            foreach (var name in Names) if (File.Exists(Path.Combine(directory, name))) {
                var existing = new FileInfo(Path.Combine(directory, name)).Length;
                if (existing > MaximumBytes - size) throw new VaultConflictFullException();
                size += existing;
            }
        var id = Guid.NewGuid().ToString("N");
        var pending = Path.Combine(_root, id + ".pending");
        Directory.CreateDirectory(pending);
        try {
            var versions = new[] { baseline, local, remote };
            for (var i = 0; i < Names.Length; ++i) {
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                await using var output = new FileStream(Path.Combine(pending, Names[i]), options);
                await output.WriteAsync(versions[i], CancellationToken.None).ConfigureAwait(false);
                await output.FlushAsync(CancellationToken.None).ConfigureAwait(false); output.Flush(true);
            }
            Directory.Move(pending, Path.Combine(_root, id));
            return id;
        }
        catch { try { if (Directory.Exists(pending)) Directory.Delete(pending, true); } catch (IOException) { } catch (UnauthorizedAccessException) { } throw; }
    }
    internal static byte[] Signature(VaultConflictFiles files)
    {
        var hashes = new byte[96];
        System.Security.Cryptography.SHA256.HashData(files.Base).CopyTo(hashes, 0);
        System.Security.Cryptography.SHA256.HashData(files.Local).CopyTo(hashes, 32);
        System.Security.Cryptography.SHA256.HashData(files.Remote).CopyTo(hashes, 64);
        return System.Security.Cryptography.SHA256.HashData(hashes);
    }
    internal async Task<bool> CompleteAsync(string id, byte[] signature)
    {
        if (!ValidId(id)) return false;
        try {
            using var writeLock = new FileStream(_root + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            var current = await ReadAsync(id).ConfigureAwait(false);
            if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(signature, Signature(current))) return false;
            var resolved = Path.Combine(_root, id + ".resolved");
            Directory.Move(Path.Combine(_root, id), resolved);
            Directory.Delete(resolved, true); return true;
        }
        catch (IOException) { return false; } catch (UnauthorizedAccessException) { return false; }
    }
    public async Task<VaultConflictFiles> ReadAsync(string id, CancellationToken cancellation = default)
    {
        if (!ValidId(id)) throw new ArgumentException(nameof(id));
        var folder = Path.Combine(_root, id);
        var baseline = await VaultStorageSession.ReadFileAsync(Path.Combine(folder, Names[0]), cancellation).ConfigureAwait(false);
        var local = await VaultStorageSession.ReadFileAsync(Path.Combine(folder, Names[1]), cancellation).ConfigureAwait(false);
        var remote = await VaultStorageSession.ReadFileAsync(Path.Combine(folder, Names[2]), cancellation).ConfigureAwait(false);
        return new(baseline, local, remote);
    }
}

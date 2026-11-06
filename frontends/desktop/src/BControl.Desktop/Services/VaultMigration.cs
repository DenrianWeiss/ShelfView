using System.Security.Cryptography;
using System.Text.Json;
using BControl.Core.Localization;

namespace BControl.Desktop.Services;

internal sealed record VaultMigration(InventoryFile Inventory, Dictionary<string, StoredCredential> Credentials,
    Dictionary<string, string> Pending, string LegacyHash)
{
    public static async Task<VaultMigration> PrepareAsync(string path, ICredentialStore legacy, CancellationToken cancellation)
    {
        var inventory = new InventoryFile(); var hash = "";
        if (!File.Exists(path) && File.Exists(path + ".migration")) path += ".migration";
        if (File.Exists(path)) {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, true);
            if (stream.Length > 16 * 1024 * 1024) throw new InvalidDataException(Loc.T("vault.invalid"));
            var bytes = new byte[checked((int)stream.Length)];
            try {
                await stream.ReadExactlyAsync(bytes, cancellation).ConfigureAwait(false);
                if (stream.ReadByte() != -1) throw new IOException(Loc.T("vault.changed"));
                hash = Convert.ToHexString(SHA256.HashData(bytes));
                inventory = JsonSerializer.Deserialize<InventoryFile>(bytes) ?? throw new InvalidDataException(Loc.T("vault.invalid"));
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        var endpoints = new Dictionary<string, string>(StringComparer.Ordinal);
        var pending = new Dictionary<string, string>(StringComparer.Ordinal);
        void Reference(string? reference, string username) {
            if (string.IsNullOrEmpty(reference)) return;
            _ = VaultApplicationStore.Reference(reference);
            if (pending.TryGetValue(reference, out var previous) && previous != username) throw new InvalidDataException(Loc.T("vault.invalid"));
            pending[reference] = username;
        }
        foreach (var record in inventory.Servers.Where(r => !string.IsNullOrEmpty(r.EndpointId))) endpoints.TryAdd(record.Address, record.EndpointId);
        foreach (var record in inventory.Servers) {
            if (string.IsNullOrEmpty(record.ServerId)) record.ServerId = Guid.NewGuid().ToString("N");
            if (string.IsNullOrEmpty(record.EndpointId)) {
                if (!endpoints.TryGetValue(record.Address, out var endpoint)) endpoints[record.Address] = endpoint = Guid.NewGuid().ToString("N");
                record.EndpointId = endpoint;
            }
            Reference(record.CredentialRef, record.Username);
            if (record.Proxy is { } proxy) Reference(proxy.CredentialRef, proxy.Username);
        }
        var credentials = new Dictionary<string, StoredCredential>(StringComparer.Ordinal);
        foreach (var (reference, username) in pending.ToArray()) {
            cancellation.ThrowIfCancellationRequested();
            if (!legacy.IsAvailable) break;
            try {
                var password = await legacy.ReadPasswordAsync(reference, cancellation).ConfigureAwait(false);
                if (password != null) { credentials[reference] = new(username, password); pending.Remove(reference); }
            }
            catch (OperationCanceledException) { throw; }
            catch { break; }
        }
        return new(inventory, credentials, pending, hash);
    }
}

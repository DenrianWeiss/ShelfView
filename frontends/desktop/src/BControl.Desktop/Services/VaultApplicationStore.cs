using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using BControl.Core.Inventory;
using BControl.Core.Localization;
using BControl.Core.Storage;
using BControl.Core.Media;

namespace BControl.Desktop.Services;

public sealed class VaultApplicationStore : ICredentialStore
{
    private sealed record PendingCredential([property: JsonPropertyName("reference")] string Reference,
        [property: JsonPropertyName("username")] string Username);
    private static JsonNode? PendingJson(IReadOnlyDictionary<string, string> pending) =>
        JsonSerializer.SerializeToNode(pending.Select(p => new PendingCredential(p.Key, p.Value)).ToArray());
    private readonly VaultStorageSession _session;
    private readonly SemaphoreSlim _inventoryGate = new(1, 1);
    private Dictionary<string, JsonObject> _inventoryBase = new(StringComparer.Ordinal);
    public VaultApplicationStore(VaultStorageSession session) => _session = session;
    public bool IsAvailable => true;
    public CredentialPersistence Persistence => CredentialPersistence.EncryptedVault;
    public IRemoteMediaStore RemoteMediaFor(ServerRecord record) => new VaultRemoteMediaStore(_session, record.Address, record.Username);
    public IMediaRecoveryStore MediaRecoveryFor(ServerRecord record) => new VaultMediaRecoveryStore(_session, record.Address, record.Username);
    public Task ChangeMasterPasswordAsync(string password, CancellationToken cancellation = default) =>
        _session.ChangeMasterPasswordAsync(password, cancellation);
    internal static string Reference(string reference)
    {
        if (Guid.TryParse(reference, out var id)) return id.ToString("N");
        if (reference.Length is < 1 or > 96 || reference.Any(c => c < 33 || c > 126)) throw new InvalidDataException(Loc.T("vault.invalid"));
        return reference;
    }
    private static string DeviceId(string reference) => "device:" + Reference(reference);
    private static string CredentialId(string reference) => "credential:" + Reference(reference);
    private static JsonObject Fields(JsonObject root, string id) => root["records"]?[id]?["deleted"]?.GetValue<bool>() == false
        ? root["records"]![id]!["fields"]!.AsObject() : new();
    private static byte[] Patch(byte[] current, string id, JsonObject fields, bool deleted = false)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(fields);
        try { using var update = VaultRecordMerge.Patch(current, id, bytes, deleted); return update.Export(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void Validate(InventoryFile inventory)
    {
        if (inventory.Version != 1 || inventory.Servers.Count > 1000 || inventory.Servers.Any(r => string.IsNullOrEmpty(r.ServerId)) ||
            inventory.Servers.Select(r => Reference(r.ServerId)).Distinct(StringComparer.Ordinal).Count() != inventory.Servers.Count)
            throw new InvalidDataException(Loc.T("vault.invalid"));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, servers = inventory.Servers.Select(r => new {
            name = r.Name, address = r.Address, username = r.Username,
            protocol = r.Protocol == 0 ? "auto" : r.Protocol == 1 ? "redfish" : r.Protocol == 2 ? "ipmi" : "invalid", system_uri = r.SystemUri }) });
        try { _ = InventoryParser.Parse(bytes, InventoryParser.FormatJson); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static Dictionary<string, JsonObject> InventoryFields(InventoryFile inventory) =>
        inventory.Servers.ToDictionary(r => DeviceId(r.ServerId), r => JsonSerializer.SerializeToNode(r)!.AsObject(), StringComparer.Ordinal);
    private static InventoryFile DecodeInventory(JsonElement root)
    {
        var result = new InventoryFile();
        foreach (var item in root.GetProperty("records").EnumerateObject()) {
            if (!item.Name.StartsWith("device:", StringComparison.Ordinal) || item.Value.GetProperty("deleted").GetBoolean()) continue;
            var record = item.Value.GetProperty("fields").Deserialize<ServerRecord>() ?? throw new InvalidDataException(Loc.T("vault.invalid"));
            if (string.IsNullOrEmpty(record.ServerId)) record.ServerId = item.Name[7..];
            if (DeviceId(record.ServerId) != item.Name) throw new InvalidDataException(Loc.T("vault.invalid"));
            result.Servers.Add(record);
        }
        Validate(result); return result;
    }
    public Task<IReadOnlyList<string>> ListConflictsAsync(CancellationToken cancellation = default) => _session.ListConflictsAsync(cancellation);
    public Task<VaultConflictReview> OpenConflictAsync(string id, CancellationToken cancellation = default) => _session.OpenConflictAsync(id, cancellation);
    public Task<bool> ApplyConflictAsync(VaultConflictReview review, IReadOnlyDictionary<uint, VaultMergeChoice> choices, VaultMergeChoice? version, CancellationToken cancellation = default) =>
        _session.ApplyConflictAsync(review, choices, version, cancellation, root => { _ = DecodeInventory(root); });
    public Task ReloadCurrentAsync(CancellationToken cancellation = default) => _session.ReloadCurrentAsync(cancellation, root => { _ = DecodeInventory(root); });
    public async Task<InventoryFile> LoadInventoryAsync(CancellationToken cancellation = default)
    {
        await _inventoryGate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            var inventory = await _session.ReadAsync(DecodeInventory, cancellation).ConfigureAwait(false);
            _inventoryBase = InventoryFields(inventory);
            return inventory;
        }
        finally { _inventoryGate.Release(); }
    }
    public async Task SaveInventoryAsync(InventoryFile inventory, CancellationToken cancellation = default)
    {
        Validate(inventory);
        var updates = InventoryFields(inventory);
        await _inventoryGate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            await _session.UpdateAsync(snapshot => {
                var patches = new JsonObject(); var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                JsonObject PatchRecord(JsonObject fields, bool deleted) => new() { ["fields"] = fields, ["deleted"] = deleted, ["modified_at_ms"] = timestamp };
                foreach (var id in _inventoryBase.Keys)
                    if (!updates.ContainsKey(id)) patches[id] = PatchRecord(new(), true);
                foreach (var (id, fields) in updates) {
                    if (!_inventoryBase.TryGetValue(id, out var prior)) patches[id] = PatchRecord(fields.DeepClone().AsObject(), false);
                    else {
                        var changed = new JsonObject();
                        foreach (var (name, value) in fields)
                            if (!prior.ContainsKey(name) || !JsonNode.DeepEquals(value, prior[name])) changed[name] = value?.DeepClone();
                        if (changed.Count != 0) patches[id] = PatchRecord(changed, false);
                    }
                }
                var bytes = JsonSerializer.SerializeToUtf8Bytes(patches);
                try { using var update = VaultRecordMerge.PatchBatch(snapshot, bytes); return update.Export(); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }, cancellation).ConfigureAwait(false);
            _inventoryBase = updates;
        }
        finally { _inventoryGate.Release(); }
    }
    public Task StoreAsync(string reference, string username, string password, CancellationToken cancellation) =>
        _session.UpdateAsync(snapshot => Patch(snapshot, CredentialId(reference), new() {
            ["credential"] = new JsonObject { ["username"] = username, ["password"] = password }
        }), cancellation);
    private static JsonElement Credential(JsonElement root, string reference)
    {
        if (root.GetProperty("records").TryGetProperty(CredentialId(reference), out var record) && !record.GetProperty("deleted").GetBoolean()
            && record.GetProperty("fields").TryGetProperty("credential", out var credential)) return credential;
        return default;
    }
    public Task<StoredCredential?> ReadCredentialAsync(string reference, string expectedUsername, CancellationToken cancellation) =>
        _session.ReadAsync<StoredCredential?>(root => {
            var credential = Credential(root, reference);
            if (credential.ValueKind != JsonValueKind.Object || credential.GetProperty("username").GetString() != expectedUsername) return null;
            var password = credential.GetProperty("password").GetString(); return password == null ? null : new(expectedUsername, password);
        }, cancellation);
    public Task<string?> ReadPasswordAsync(string reference, CancellationToken cancellation) => _session.ReadAsync(root => {
        var credential = Credential(root, reference);
        return credential.ValueKind == JsonValueKind.Object ? credential.GetProperty("password").GetString() : null;
    }, cancellation);
    public Task DeleteAsync(string reference, CancellationToken cancellation) =>
        _session.UpdateAsync(snapshot => Patch(snapshot, CredentialId(reference), new(), true), cancellation);

    public static byte[] BuildMigration(string vaultId, InventoryFile inventory, IReadOnlyDictionary<string, StoredCredential> credentials,
        IReadOnlyDictionary<string, string> pending, string legacyHash)
    {
        Validate(inventory);
        var root = new JsonObject { ["version"] = 1, ["vault_id"] = vaultId, ["records"] = new JsonObject() };
        var records = root["records"]!.AsObject(); var time = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        void Add(string id, JsonObject fields) => records[id] = new JsonObject { ["fields"] = fields, ["deleted"] = false, ["modified_at_ms"] = time };
        foreach (var device in inventory.Servers) Add(DeviceId(device.ServerId), JsonSerializer.SerializeToNode(device)!.AsObject());
        foreach (var (reference, credential) in credentials) Add(CredentialId(reference), new() {
            ["credential"] = new JsonObject { ["username"] = credential.Username, ["password"] = credential.Password }
        });
        Add("migration:desktop", new() { ["legacy_hash"] = legacyHash,
            ["pending"] = PendingJson(pending), ["cleanup"] = JsonSerializer.SerializeToNode(credentials.Keys.ToArray()) });
        return JsonSerializer.SerializeToUtf8Bytes(root);
    }
    public async Task FinishMigrationAsync(string legacyPath, ICredentialStore legacy, CancellationToken cancellation)
    {
        var bytes = await _session.SnapshotAsync(cancellation).ConfigureAwait(false);
        JsonObject fields;
        try { fields = Fields(JsonNode.Parse(bytes)!.AsObject(), "migration:desktop"); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        if (fields.Count == 0) return;
        var pending = (fields["pending"]?.Deserialize<List<PendingCredential>>() ?? new()).ToDictionary(p => p.Reference, p => p.Username, StringComparer.Ordinal);
        var cleanup = fields["cleanup"]?.Deserialize<List<string>>() ?? new();
        var legacyHealthy = legacy.IsAvailable;
        foreach (var (reference, username) in pending.ToArray()) {
            cancellation.ThrowIfCancellationRequested();
            var present = await _session.ReadAsync(root => root.GetProperty("records").TryGetProperty(CredentialId(reference), out _), cancellation).ConfigureAwait(false);
            if (!present) {
                if (!legacyHealthy) continue;
                string? password;
                try { password = await legacy.ReadPasswordAsync(reference, cancellation).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
                catch { legacyHealthy = false; continue; }
                if (password == null) continue;
                await StoreAsync(reference, username, password, cancellation).ConfigureAwait(false);
            }
            var nextPending = new Dictionary<string, string>(pending, StringComparer.Ordinal); nextPending.Remove(reference);
            var nextCleanup = cleanup.Append(reference).Distinct(StringComparer.Ordinal).ToList();
            var nextFields = fields.DeepClone().AsObject();
            nextFields["pending"] = PendingJson(nextPending); nextFields["cleanup"] = JsonSerializer.SerializeToNode(nextCleanup);
            await _session.UpdateAsync(snapshot => Patch(snapshot, "migration:desktop", nextFields), cancellation).ConfigureAwait(false);
            pending = nextPending; cleanup = nextCleanup; fields = nextFields;
        }
        // A stale cleanup journal safely retries already deleted legacy entries.
        var remainingCleanup = cleanup.ToList();
        foreach (var reference in cleanup) {
            if (!legacyHealthy) break;
            cancellation.ThrowIfCancellationRequested();
            try { await legacy.DeleteAsync(reference, cancellation).ConfigureAwait(false); remainingCleanup.Remove(reference); }
            catch (OperationCanceledException) { throw; }
            catch { legacyHealthy = false; break; }
        }
        if (remainingCleanup.Count != cleanup.Count) {
            var nextFields = fields.DeepClone().AsObject(); nextFields["cleanup"] = JsonSerializer.SerializeToNode(remainingCleanup);
            await _session.UpdateAsync(snapshot => Patch(snapshot, "migration:desktop", nextFields), cancellation).ConfigureAwait(false);
            cleanup = remainingCleanup; fields = nextFields;
        }
        var expected = fields["legacy_hash"]?.GetValue<string>();
        var retired = legacyPath + ".migration";
        async Task<bool> MatchesAsync(string path)
        {
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, true);
            return expected == Convert.ToHexString(await SHA256.HashDataAsync(input, cancellation).ConfigureAwait(false));
        }
        if (File.Exists(retired)) {
            if (await MatchesAsync(retired).ConfigureAwait(false)) File.Delete(retired);
            else {
                if (!File.Exists(legacyPath)) File.Move(retired, legacyPath, false);
                throw new VaultChangedException();
            }
        }
        if (File.Exists(legacyPath)) {
            File.Move(legacyPath, retired, false);
            try { if (!await MatchesAsync(retired).ConfigureAwait(false)) throw new VaultChangedException(); }
            catch { if (!File.Exists(legacyPath)) File.Move(retired, legacyPath, false); throw; }
            File.Delete(retired);
        }
    }
}

using System.Text.Json;
using BControl.Core.Storage;
using BControl.Core.Native;
using BControl.Desktop.Services;

namespace BControl.Desktop.Tests;
public sealed class VaultApplicationStoreTests
{
    private sealed class Keys : IVaultKeyStore
    {
        public VaultStoredKey? Read(VaultMetadata metadata) => null;
        public bool Store(VaultMetadata metadata, ReadOnlySpan<byte> key, bool roaming) => throw new BcException(Bc.Unsupported, "Fixture system store unavailable");
    }
    private static InventoryFile Inventory(string reference) => new() { Servers = [new() {
        ServerId = Guid.NewGuid().ToString("N"), EndpointId = Guid.NewGuid().ToString("N"),
        Address = "https://fixture.invalid", Name = "Fixture", Username = "fixture", CredentialRef = reference, Protocol = 1
    }] };
    [Fact]
    public async Task DirectChildMergePreservesRemoteFieldsAndNewDevicesAcrossLaterSaves()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-fields-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var path = Path.Combine(directory, "vault.bcv");
            await using var first = await VaultStorageSession.CreateAsync(path, "fixture master password", keyStore: new Keys());
            var initial = new VaultApplicationStore(first);
            await initial.SaveInventoryAsync(Inventory(Guid.NewGuid().ToString("N")));
            await using var second = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: new Keys());
            var other = new VaultApplicationStore(second);
            var a = await initial.LoadInventoryAsync(); var b = await other.LoadInventoryAsync();
            var id = b.Servers[0].ServerId;
            a.Servers[0].Name = "remote name";
            a.Servers.Add(new ServerRecord { ServerId = Guid.NewGuid().ToString("N"), EndpointId = Guid.NewGuid().ToString("N"), Address = "https://another.invalid", Username = "fixture" });
            await initial.SaveInventoryAsync(a);
            b.Servers[0].Timeout = new BControl.Core.HostTimeout(60);
            await other.SaveInventoryAsync(b);
            b.Servers[0].Username = "local user";
            await other.SaveInventoryAsync(b);
            var result = await other.LoadInventoryAsync();
            Assert.Equal(2, result.Servers.Count);
            var merged = Assert.Single(result.Servers, item => item.ServerId == id);
            Assert.Equal("remote name", merged.Name); Assert.Equal("local user", merged.Username);
            Assert.Equal(60u, merged.Timeout!.Seconds);
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public async Task ExistingVaultPreservesCredentialsAndMigrationMetadataAcrossSave()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-upgrade-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var path = Path.Combine(directory, "vault.bcv");
            var reference = Guid.NewGuid().ToString("N");
            var inventory = Inventory(reference);
            await using (var previous = await VaultStorageSession.CreateAsync(path, "fixture master password",
                id => JsonSerializer.SerializeToUtf8Bytes(new {
                    version = 1, vault_id = id, records = new Dictionary<string, object> {
                        ["device:" + inventory.Servers[0].ServerId] = new { fields = inventory.Servers[0], deleted = false, modified_at_ms = 1 },
                        ["credential:" + reference] = new { fields = new { credential = new { username = "fixture", password = "saved secret" } }, deleted = false, modified_at_ms = 1 },
                        ["migration:desktop"] = new { fields = new { legacy_hash = "", pending = new[] { new { reference = "pending", username = "fixture" } }, cleanup = new[] { reference } }, deleted = false, modified_at_ms = 1 }
                    }
                }), keyStore: new Keys())) { }
            await using var session = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: new Keys());
            var store = new VaultApplicationStore(session);
            var loaded = await store.LoadInventoryAsync();
            Assert.Equal(inventory.Servers[0].ServerId, Assert.Single(loaded.Servers).ServerId);
            Assert.Equal("saved secret", (await store.ReadCredentialAsync(reference, "fixture", default))!.Password);
            Assert.Null(await store.ReadCredentialAsync(reference, "another user", default));
            loaded.Servers[0].Name = "updated";
            await store.SaveInventoryAsync(loaded);
            await using var reopened = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: new Keys());
            var updated = new VaultApplicationStore(reopened);
            Assert.Equal("updated", Assert.Single((await updated.LoadInventoryAsync()).Servers).Name);
            Assert.Equal("saved secret", (await updated.ReadCredentialAsync(reference, "fixture", default))!.Password);
            Assert.Equal("pending", await reopened.ReadAsync(root => root.GetProperty("records").GetProperty("migration:desktop").GetProperty("fields").GetProperty("pending")[0].GetProperty("reference").GetString()));
        }
        finally { Directory.Delete(directory, true); }
    }
}

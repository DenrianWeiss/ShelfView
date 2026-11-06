using System.Security.Cryptography;
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
    private sealed class Legacy : ICredentialStore
    {
        public bool IsAvailable => true;
        public int Reads;
        public List<string> Deleted = [];
        public Task StoreAsync(string reference, string username, string password, CancellationToken cancellation) => throw new NotSupportedException();
        public Task<string?> ReadPasswordAsync(string reference, CancellationToken cancellation) { ++Reads; return Task.FromResult<string?>("legacy secret"); }
        public Task DeleteAsync(string reference, CancellationToken cancellation) { Deleted.Add(reference); return Task.CompletedTask; }
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
    public async Task ResumedMigrationKeepsNewCredentialsAndRetiresVerifiedLegacyMetadata()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-migration-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var legacyPath = Path.Combine(directory, "servers.json"); var path = Path.Combine(directory, "vault.bcv");
            var reference = Guid.NewGuid().ToString("N"); var inventory = Inventory(reference);
            var original = JsonSerializer.SerializeToUtf8Bytes(inventory); await File.WriteAllBytesAsync(legacyPath, original);
            var hash = Convert.ToHexString(SHA256.HashData(original)); var legacy = new Legacy();
            await using var session = await VaultStorageSession.CreateAsync(path, "fixture master password",
                id => VaultApplicationStore.BuildMigration(id, inventory, new Dictionary<string, StoredCredential>(), new Dictionary<string, string> { [reference] = "fixture" }, hash), keyStore: new Keys());
            var store = new VaultApplicationStore(session);
            await store.StoreAsync(reference, "fixture", "new secret", default);
            await store.FinishMigrationAsync(legacyPath, legacy, default);
            Assert.Equal(0, legacy.Reads);
            Assert.Contains(reference, legacy.Deleted);
            Assert.False(File.Exists(legacyPath)); Assert.False(File.Exists(legacyPath + ".migration"));
            Assert.Equal("new secret", (await store.ReadCredentialAsync(reference, "fixture", default))!.Password);
            Assert.Null(await store.ReadCredentialAsync(reference, "another user", default));
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public async Task ConcurrentVaultChangePreventsLegacyCredentialDeletion()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-migration-race-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var path = Path.Combine(directory, "vault.bcv"); var reference = Guid.NewGuid().ToString("N");
            var legacy = new Legacy(); var inventory = Inventory(reference);
            await using var first = await VaultStorageSession.CreateAsync(path, "fixture master password",
                id => VaultApplicationStore.BuildMigration(id, inventory, new Dictionary<string, StoredCredential>(), new Dictionary<string, string> { [reference] = "fixture" }, ""), keyStore: new Keys());
            await using var concurrent = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: new Keys());
            var other = new VaultApplicationStore(concurrent);
            await other.StoreAsync(reference, "fixture", "other session", default);
            var initial = new VaultApplicationStore(first);
            await Assert.ThrowsAnyAsync<VaultChangedException>(() => initial.FinishMigrationAsync(Path.Combine(directory, "servers.json"), legacy, default));
            Assert.Empty(legacy.Deleted);
            Assert.Equal("other session", (await other.ReadCredentialAsync(reference, "fixture", default))!.Password);
        }
        finally { Directory.Delete(directory, true); }
    }
}

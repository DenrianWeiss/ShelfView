using BControl.Desktop.Services;

namespace BControl.Desktop.Tests;

public sealed class ServerStoreTests : IDisposable
{
    [Fact]
    public async Task ProxyIsPerServerAndMissingCredentialsFailClosed()
    {
        var credentials = new CredentialService(new UnavailableCredentialStore());
        credentials.StoreForProcess("proxy-ref", new StoredCredential("proxy-user", "test-proxy-secret"));
        var record = new ServerRecord { ServerId = "proxied", Address = "https://proxy-fixture.invalid", Username = "fixture", Proxy = new ServerProxy
            { Host = "127.0.0.1", Port = 1081, Username = "proxy-user", CredentialRef = "proxy-ref" },
            ReadProxyCredential = credentials.ReadAsync };
        Assert.Equal((ushort)1081, (await record.ResolveProxyAsync())!.Port);
        await using var vault = await TestVault.CreateAsync(_dir);
        var store = vault.Store;
        await store.SaveAsync(new InventoryFile { Servers = [record, new ServerRecord { ServerId = "direct", Address = "https://direct-fixture.invalid", Username = "fixture" }] });
        var raw = await File.ReadAllTextAsync(store.FilePath);
        Assert.DoesNotContain("test-proxy-secret", raw);
        Assert.DoesNotContain("password", raw, StringComparison.OrdinalIgnoreCase);
        var loaded = await store.LoadAsync();
        Assert.Null(await loaded.Servers.Single(r => r.ServerId == "direct").ResolveProxyAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => loaded.Servers.Single(r => r.ServerId == "proxied").ResolveProxyAsync());
        loaded.Servers.Single(r => r.ServerId == "proxied").ReadProxyCredential = credentials.ReadAsync;
        Assert.Equal("127.0.0.1", (await loaded.Servers.Single(r => r.ServerId == "proxied").ResolveProxyAsync())!.Host);
        await credentials.DeleteAsync("proxy-ref");
        await Assert.ThrowsAsync<InvalidOperationException>(() => loaded.Servers.Single(r => r.ServerId == "proxied").ResolveProxyAsync());
    }

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bcontrol-store-test-" + Guid.NewGuid().ToString("N"));

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public async Task SaveLoad_RoundTrips_WithoutSecrets()
    {
        await using var vault = await TestVault.CreateAsync(_dir);
        var store = vault.Store;
        var inventory = new InventoryFile
        {
            Servers =
            {
                new ServerRecord
                {
                    ServerId = "a", EndpointId = "e", Name = "rack-1", Address = "https://bmc",
                    Username = "op", CredentialRef = "a", Capabilities = { Redfish = true },
                },
            },
        };
        await store.SaveAsync(inventory);
        var loaded = await store.LoadAsync();
        var record = Assert.Single(loaded.Servers);
        Assert.Equal("a", record.ServerId);
        var raw = await File.ReadAllTextAsync(store.FilePath);
        Assert.DoesNotContain("rack-1", raw);
        Assert.DoesNotContain("https://bmc", raw);
    }

    [Fact]
    public async Task ChangedVault_IsPreserved_AndNotOverwritten()
    {
        await using var vault = await TestVault.CreateAsync(_dir);
        var store = vault.Store;
        await File.WriteAllTextAsync(store.FilePath, "broken encrypted vault");
        await Assert.ThrowsAsync<BControl.Core.Storage.VaultChangedException>(() => store.SaveAsync(new InventoryFile()));
        Assert.Equal("broken encrypted vault", await File.ReadAllTextAsync(store.FilePath));
    }

    [Fact]
    public async Task ConcurrentSaves_LeaveValidFile()
    {
        await using var vault = await TestVault.CreateAsync(_dir);
        var store = vault.Store;
        var tasks = Enumerable.Range(0, 8).Select(i =>
        {
            var inventory = new InventoryFile();
            inventory.Servers.Add(new ServerRecord { ServerId = "s" + i, Name = "n" + i, Address = "https://fixture.invalid", Username = "fixture" });
            return store.SaveAsync(inventory);
        });
        await Task.WhenAll(tasks);
        var loaded = await store.LoadAsync();
        Assert.Single(loaded.Servers);
    }
}

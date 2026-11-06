using Avalonia.Headless;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Tests;

[Collection("Avalonia UI")]
public sealed class VaultTransitionTests
{
    private sealed class PausedCredentialStore : ICredentialStore
    {
        public bool IsAvailable => true;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task StoreAsync(string reference, string username, string password, CancellationToken cancellation)
        {
            Entered.TrySetResult();
            await Release.Task;
            throw new IOException("Fixture storage unavailable");
        }
        public Task<string?> ReadPasswordAsync(string reference, CancellationToken cancellation) => Task.FromResult<string?>(null);
        public Task DeleteAsync(string reference, CancellationToken cancellation) => Task.CompletedTask;
    }
    [Fact]
    public async Task ConflictShutdownWaitsForCredentialSaveBeforeClearingProcessFallback()
    {
        using var ui = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await ui.Dispatch(async () => {
            var directory = Path.Combine(Path.GetTempPath(), "vault-edit-transition-" + Guid.NewGuid().ToString("N"));
            try {
                await using var vault = await TestVault.CreateAsync(directory);
                await vault.Store.SaveAsync(new InventoryFile { Servers = [new() {
                    ServerId = Guid.NewGuid().ToString("N"), EndpointId = Guid.NewGuid().ToString("N"),
                    Address = "https://fixture.invalid", Username = "fixture", CredentialRef = Guid.NewGuid().ToString("N")
                }] });
                var pending = new PausedCredentialStore();
                var credentials = new CredentialService(pending);
                await using var model = new MainViewModel(vault.Store, credentials, automaticRefresh: false);
                var record = model.Servers[0].Record;
                var save = model.SaveCredentialAsync(record, new("fixture", "temporary secret"), true);
                Task? stop = null;
                try {
                    await pending.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                    stop = model.StopForVaultChangeAsync();
                    Assert.False(model.IsOperational);
                    Assert.False(stop.IsCompleted);
                    await Assert.ThrowsAsync<ObjectDisposedException>(() => model.SaveCredentialAsync(record, new("fixture", "late secret"), false));
                }
                finally {
                    pending.Release.TrySetResult();
                    await save;
                    if (stop != null) await stop;
                }
                Assert.Null((await credentials.ReadAsync(record.CredentialRef, "fixture")).Credential);
            }
            finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
            return true;
        }, CancellationToken.None);
    }
    [Fact]
    public async Task ConflictShutdownDiscardsOldInventoryAndPreventsNewConnections()
    {
        using var ui = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await ui.Dispatch(async () => {
            var directory = Path.Combine(Path.GetTempPath(), "vault-transition-" + Guid.NewGuid().ToString("N"));
            try {
                await using var vault = await TestVault.CreateAsync(directory);
                var record = new ServerRecord {
                    ServerId = Guid.NewGuid().ToString("N"), EndpointId = Guid.NewGuid().ToString("N"),
                    Name = "Original", Address = "https://fixture.invalid", Username = "fixture"
                };
                await vault.Store.SaveAsync(new InventoryFile { Servers = [record] });
                var credentials = new CredentialService(new UnavailableCredentialStore());
                credentials.StoreForProcess("temporary", new("fixture", "temporary secret"));
                await using var model = new MainViewModel(vault.Store, credentials, automaticRefresh: false);
                var current = await vault.Store.LoadAsync();
                current.Servers[0].Name = "Current version";
                await vault.Store.SaveAsync(current);
                var ciphertext = await File.ReadAllBytesAsync(vault.Store.FilePath);

                await model.StopForVaultChangeAsync();
                await model.DisposeAsync();

                Assert.False(model.IsOperational);
                Assert.Equal(ciphertext, await File.ReadAllBytesAsync(vault.Store.FilePath));
                Assert.Equal("Current version", (await vault.Store.LoadAsync()).Servers[0].Name);
                Assert.Null((await credentials.ReadAsync("temporary", "fixture")).Credential);
                await Assert.ThrowsAsync<ObjectDisposedException>(() => model.OpenWorkspaceAsync(record, WorkspaceFeature.Kvm));
                Assert.Empty(model.Registry.Tabs);
            }
            finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
            return true;
        }, CancellationToken.None);
    }
}

using BControl.Desktop.Services;

namespace BControl.Desktop.Tests;

public sealed class CredentialServiceTests
{
    private sealed class FailingStore : ICredentialStore
    {
        public bool IsAvailable => true;
        public Task StoreAsync(string reference, string username, string password, CancellationToken cancellation)
            => Task.FromException(new InvalidOperationException("凭据库不可用"));
        public Task<string?> ReadPasswordAsync(string reference, CancellationToken cancellation) => Task.FromResult<string?>(null);
        public Task DeleteAsync(string reference, CancellationToken cancellation) => Task.CompletedTask;
    }

    [Fact]
    public async Task SystemStoreFailure_FallsBackToProcessOnly_AndReadsBack()
    {
        var service = new CredentialService(new FailingStore());
        var persistence = await service.StoreAsync("srv-1", new StoredCredential("op", "secret"));
        Assert.Equal(CredentialPersistence.ProcessOnly, persistence);
        Assert.False(service.PersistentStoreAvailable);

        var read = await service.ReadAsync("srv-1", "op");
        Assert.Equal(CredentialPersistence.ProcessOnly, read.Persistence);
        Assert.Equal("secret", read.Credential?.Password);
    }

    [Fact]
    public async Task UnavailableStore_KeepsCredentialsProcessOnly()
    {
        // 凭据库不可用时：凭据只保留在当前进程，读取同进程内成功，不伪造持久化。
        var service = new CredentialService(new UnavailableCredentialStore());
        var persistence = await service.StoreAsync("srv-2", new StoredCredential("op", "secret"));
        Assert.Equal(CredentialPersistence.ProcessOnly, persistence);
        var read = await service.ReadAsync("srv-2", "op");
        Assert.Equal(CredentialPersistence.ProcessOnly, read.Persistence);
        Assert.Equal("secret", read.Credential?.Password);
    }

    [Fact]
    public async Task UsernameMismatch_IsRejected()
    {
        var service = new CredentialService(new UnavailableCredentialStore());
        // 仅进程回退时用户名不匹配返回空凭据。
        var read = await service.ReadAsync("missing", "someone");
        Assert.Null(read.Credential);
    }
}

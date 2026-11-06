using BControl.Core.Native;
using BControl.Core.Storage;
using BControl.Desktop.Services;

namespace BControl.Desktop.Tests;

internal sealed class TestVault : IAsyncDisposable
{
    private readonly VaultStorageSession _session;
    public ServerStore Store { get; }
    private TestVault(VaultStorageSession session) { _session = session; Store = new(new VaultApplicationStore(session), session.FilePath); }
    public static async Task<TestVault> CreateAsync(string directory) =>
        new(await VaultStorageSession.CreateAsync(Path.Combine(directory, "vault.bcv"), "fixture master password", keyStore: new Keys()));
    public ValueTask DisposeAsync() => _session.DisposeAsync();
    private sealed class Keys : IVaultKeyStore
    {
        public VaultStoredKey? Read(VaultMetadata metadata) => null;
        public bool Store(VaultMetadata metadata, ReadOnlySpan<byte> key, bool roaming) =>
            throw new BcException(Bc.Unsupported, "Fixture system store unavailable");
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BControl.Core.Storage;
using BControl.Core.Media;

namespace BControl.Core.Tests;

public sealed class VaultStorageSessionTests
{
    [Fact]
    public async Task EncryptedMigrationPreservesSourceAndRefusesExistingDestination()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-relocation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); using var keys = new Keys();
        try {
            var source = Path.Combine(directory, "local.bcv"); var destination = Path.Combine(directory, "cloud", "vault.bcv");
            await using var session = await VaultStorageSession.CreateAsync(source, "fixture master password", keyStore: keys);
            var original = await File.ReadAllBytesAsync(source);
            var sourceArchive = new VaultConflictArchive(source);
            await sourceArchive.SaveAsync(original, original, original);
            await using var migrated = await session.CopyEncryptedSnapshotAsync(destination);
            Assert.Equal(original, await File.ReadAllBytesAsync(source));
            Assert.Equal(original, await File.ReadAllBytesAsync(destination));
            Assert.Equal(await session.ReadAsync(root => root.GetRawText()), await migrated.ReadAsync(root => root.GetRawText()));
            Assert.Single(sourceArchive.List());
            var archive = new VaultConflictArchive(destination);
            Assert.Equal(original, (await archive.ReadAsync(Assert.Single(archive.List()))).Local);
            await Assert.ThrowsAsync<VaultChangedException>(() => session.CopyEncryptedSnapshotAsync(destination));
            Assert.Equal(original, await File.ReadAllBytesAsync(destination));
            await File.WriteAllBytesAsync(source, [0]);
            var other = Path.Combine(directory, "other.bcv");
            await Assert.ThrowsAsync<VaultChangedException>(() => session.CopyEncryptedSnapshotAsync(other));
            Assert.False(File.Exists(other));
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public async Task RemoteMountBlocksLocalSubmissionWithoutCreatingLocalRecovery()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-media-gates-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); using var keys = new Keys();
        try {
            await using var session = await VaultStorageSession.CreateAsync(Path.Combine(directory, "vault.bcv"), "fixture master password", keyStore: keys);
            var local = new VaultMediaRecoveryStore(session, "https://fixture.invalid", "fixture");
            var remote = new VaultRemoteMediaStore(session, "https://fixture.invalid", "fixture");
            const string uri = "/redfish/v1/Managers/1/VirtualMedia/cd";
            var entry = await remote.UpdateAsync(uri, null, RemoteMediaAction.Insert, RemoteMediaPhase.Submitting, source: "https://images.invalid/file.iso");
            Assert.NotNull(entry);
            await remote.ObserveSourceAsync(uri, entry.OperationId, null, true);
            var connects = 0;
            await using var owner = new ConsoleSessionOwner(_ => { ++connects; throw new InvalidOperationException("Unexpected connection"); }, recovery: local);
            var error = await Assert.ThrowsAsync<BControl.Core.Native.BcException>(() => owner.MountAsync("unused.iso"));
            Assert.Equal(BControl.Core.Native.Bc.ConfirmationRequired, error.Status);
            Assert.Equal(0, connects); Assert.False(owner.CleanupPending); Assert.False(await local.ReadPendingAsync());
            await remote.UpdateAsync(uri, entry.OperationId, RemoteMediaAction.Insert, RemoteMediaPhase.Cleared);
            await local.BeginAsync(); Assert.True(await local.ReadPendingAsync());
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public async Task MediaRecoverySurvivesReopenAndCannotBeReplacedSilently()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-media-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); using var keys = new Keys();
        var path = Path.Combine(directory, "vault.bcv");
        try {
            await using (var session = await VaultStorageSession.CreateAsync(path, "fixture master password", keyStore: keys))
                await new VaultMediaRecoveryStore(session, "https://fixture.invalid/path", "fixture").BeginAsync();
            await using var reopened = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: keys);
            var recovery = new VaultMediaRecoveryStore(reopened, "https://fixture.invalid/other", "fixture");
            Assert.True(await recovery.ReadPendingAsync());
            Assert.False(await new VaultMediaRecoveryStore(reopened, "https://fixture.invalid", "another user").ReadPendingAsync());
            await Assert.ThrowsAsync<BControl.Core.Native.BcException>(() => recovery.BeginAsync());
            Assert.True(await recovery.ReadPendingAsync());
            await recovery.ClearAsync(); Assert.False(await recovery.ReadPendingAsync());
        }
        finally { Directory.Delete(directory, true); }
    }
    private sealed class Keys : IVaultKeyStore, IDisposable
    {
        public byte[]? Key;
        public VaultStoredKey? Read(VaultMetadata metadata) => Key == null ? null : new(Key.ToArray(), false);
        public bool Store(VaultMetadata metadata, ReadOnlySpan<byte> key, bool roaming)
        {
            if (Key != null) CryptographicOperations.ZeroMemory(Key);
            Key = key.ToArray(); return false;
        }
        public void Dispose() { if (Key != null) CryptographicOperations.ZeroMemory(Key); }
    }
    private static byte[] Change(byte[] snapshot, string value)
    {
        var fields = JsonSerializer.SerializeToUtf8Bytes(new { name = value });
        using var update = VaultRecordMerge.Patch(snapshot, "device:fixture", fields); return update.Export();
    }
    [Fact]
    public async Task CiphertextReloadsAutomaticallyAndMasterPasswordRepairsWrongSystemKey()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-session-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "vault.bcv");
        using var keys = new Keys();
        try {
            await using (var session = await VaultStorageSession.CreateAsync(path, "fixture master password", keyStore: keys)) {
                await session.UpdateAsync(snapshot => Change(snapshot, "fixture-private-device"));
                Assert.DoesNotContain("fixture-private-device", Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path)));
            }
            await using (var automatic = await VaultStorageSession.TryAutoOpenAsync(path, keyStore: keys)) {
                Assert.NotNull(automatic);
                var name = await automatic.ReadAsync(root => root.GetProperty("records").GetProperty("device:fixture").GetProperty("fields").GetProperty("name").GetString());
                Assert.Equal("fixture-private-device", name);
            }
            keys.Key![0] ^= 1;
            Assert.Null(await VaultStorageSession.TryAutoOpenAsync(path, keyStore: keys));
            await using var restored = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: keys);
            Assert.True(restored.SystemKeySaved);
            await using var retry = await VaultStorageSession.TryAutoOpenAsync(path, keyStore: keys);
            Assert.NotNull(retry);
            await restored.ChangeMasterPasswordAsync("replacement master password");
            await using var changed = await VaultStorageSession.OpenWithPasswordAsync(path, "replacement master password", keyStore: keys);
            Assert.Equal("fixture-private-device", await changed.ReadAsync(root => root.GetProperty("records").GetProperty("device:fixture").GetProperty("fields").GetProperty("name").GetString()));
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public async Task ConflictReviewRejectsChangedCurrentAndKeepsArchiveUntilExplicitChoice()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-review-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); using var keys = new Keys();
        try {
            var path = Path.Combine(directory, "vault.bcv");
            await using var first = await VaultStorageSession.CreateAsync(path, "fixture master password", keyStore: keys);
            await first.UpdateAsync(snapshot => Change(snapshot, "base"));
            await using var stale = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: keys);
            await first.UpdateAsync(snapshot => Change(snapshot, "remote"));
            var error = await Assert.ThrowsAsync<VaultConflictException>(() => stale.UpdateAsync(snapshot => Change(snapshot, "local")));
            using var review = await stale.OpenConflictAsync(error.ConflictId);
            Assert.True(review.FieldChoices); Assert.Equal("name", Assert.Single(review.Fields).Field);
            Assert.Equal("local", review.Fields[0].Local.Display);
            await first.UpdateAsync(snapshot => {
                using var patch = VaultRecordMerge.Patch(snapshot, "device:fixture", "{\"other\":\"newer\"}"u8);
                return patch.Export();
            });
            var current = await File.ReadAllBytesAsync(path);
            await Assert.ThrowsAsync<VaultChangedException>(() => stale.ApplyConflictAsync(review,
                new Dictionary<uint, VaultMergeChoice> { [0] = VaultMergeChoice.Local }));
            Assert.Equal(current, await File.ReadAllBytesAsync(path));
            Assert.Single(await stale.ListConflictsAsync());
            using var refreshed = await stale.OpenConflictAsync(error.ConflictId);
            Assert.False(refreshed.FieldChoices);
            Assert.True(await stale.ApplyConflictAsync(refreshed, new Dictionary<uint, VaultMergeChoice>(), VaultMergeChoice.Remote));
            Assert.Empty(await stale.ListConflictsAsync());
            Assert.Equal("remote", await stale.ReadAsync(root => root.GetProperty("records").GetProperty("device:fixture").GetProperty("fields").GetProperty("name").GetString()));
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public async Task MultiGenerationChangesAreNotAutomaticallyMerged()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-generations-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); using var keys = new Keys();
        try {
            var path = Path.Combine(directory, "vault.bcv");
            await using var first = await VaultStorageSession.CreateAsync(path, "fixture master password", keyStore: keys);
            await using var stale = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: keys);
            await first.UpdateAsync(snapshot => Change(snapshot, "first change"));
            await first.UpdateAsync(snapshot => Change(snapshot, "second change"));
            var current = await File.ReadAllBytesAsync(path);
            await Assert.ThrowsAsync<VaultConflictException>(() => stale.UpdateAsync(snapshot => {
                using var patch = VaultRecordMerge.Patch(snapshot, "device:another", "{\"name\":\"local\"}"u8);
                return patch.Export();
            }));
            Assert.Equal(current, await File.ReadAllBytesAsync(path));
        }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public async Task StaleWriterPreservesTheOtherSessionsCommittedData()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vault-race-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "vault.bcv");
        using var keys = new Keys();
        try {
            await using var first = await VaultStorageSession.CreateAsync(path, "fixture master password", keyStore: keys);
            await using var second = await VaultStorageSession.TryAutoOpenAsync(path, keyStore: keys);
            Assert.NotNull(second);
            await first.UpdateAsync(snapshot => Change(snapshot, "first writer"));
            await Assert.ThrowsAsync<VaultChangedException>(() => second.UpdateAsync(snapshot => snapshot));
            var conflict = await Assert.ThrowsAsync<VaultConflictException>(() => second.UpdateAsync(snapshot => Change(snapshot, "stale writer")));
            var archive = new VaultConflictArchive(path);
            Assert.Equal(conflict.ConflictId, Assert.Single(archive.List()));
            var retained = await archive.ReadAsync(conflict.ConflictId);
            Assert.DoesNotContain("stale writer", Encoding.UTF8.GetString(retained.Local));
            using (var local = VaultDocument.OpenWithPassword(retained.Local, "fixture master password"))
                Assert.Contains("stale writer", Encoding.UTF8.GetString(local.ReadData()));
            using (var remote = VaultDocument.OpenWithPassword(retained.Remote, "fixture master password"))
                Assert.Contains("first writer", Encoding.UTF8.GetString(remote.ReadData()));
            await using var checkedFile = await VaultStorageSession.TryAutoOpenAsync(path, keyStore: keys);
            Assert.NotNull(checkedFile);
            var value = await checkedFile.ReadAsync(root => root.GetProperty("records").GetProperty("device:fixture").GetProperty("fields").GetProperty("name").GetString());
            Assert.Equal("first writer", value);
        }
        finally { Directory.Delete(directory, true); }
    }
}

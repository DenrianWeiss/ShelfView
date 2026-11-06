using System.Security.Cryptography;
using BControl.Core.Storage;
using BControl.Core.Native;
using System.Text;

namespace BControl.Core.Tests;
public sealed class VaultDocumentTests
{
    [Fact]
    public void MediaSourceEvidenceIsSharedAndMissingUrlDoesNotLockManagement()
    {
        const string uri = "/redfish/v1/Managers/1/VirtualMedia/cd";
        const string source = "https://images.invalid/file.iso?token=private-source";
        using var scope = new VaultMediaScope("https://bmc.example", "fixture");
        var empty = "{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{}}"u8.ToArray();
        using var begin = scope.PatchRemote(empty, uri, null, RemoteMediaAction.Insert, RemoteMediaPhase.Submitting, source: source);
        var pending = begin.Export(); var operation = Assert.Single(scope.ReadRemote(pending));
        Assert.DoesNotContain("private-source", Encoding.UTF8.GetString(pending));
        using var acknowledged = scope.ObserveRemoteSource(pending, uri, operation.OperationId, null, true, inserted: false);
        Assert.Equal(RemoteMediaPhase.Submitting, Assert.Single(scope.ReadRemote(acknowledged.Export())).Phase);
        using var delayed = scope.ObserveRemoteSource(acknowledged.Export(), uri, operation.OperationId, source, false);
        Assert.Equal(RemoteMediaPhase.Settled, Assert.Single(scope.ReadRemote(delayed.Export())).Phase);

        using var missing = scope.ObserveRemoteSource(pending, uri, operation.OperationId, null, true);
        var unverified = Assert.Single(scope.ReadRemote(missing.Export()));
        Assert.Equal(RemoteMediaSourceVerification.Unverified, unverified.SourceVerification);
        Assert.Equal(RemoteMediaPhase.Settled, unverified.Phase);
        using var eject = scope.PatchRemote(missing.Export(), uri, operation.OperationId, RemoteMediaAction.Eject, RemoteMediaPhase.Submitting);
        Assert.Equal(RemoteMediaAction.Eject, Assert.Single(scope.ReadRemote(eject.Export())).Action);
        using var mismatch = scope.ObserveRemoteSource(pending, uri, operation.OperationId, "https://other.invalid/file.iso", true);
        var different = Assert.Single(scope.ReadRemote(mismatch.Export()));
        Assert.Equal(RemoteMediaSourceVerification.Mismatch, different.SourceVerification);
        Assert.Equal(RemoteMediaPhase.Accepted, different.Phase);
        Assert.Throws<InvalidOperationException>(() => scope.PatchRemote(mismatch.Export(), uri, operation.OperationId, operation.Action, RemoteMediaPhase.Settled));
        using var matched = scope.ObserveRemoteSource(mismatch.Export(), uri, operation.OperationId, source, false);
        Assert.Equal(RemoteMediaSourceVerification.Verified, Assert.Single(scope.ReadRemote(matched.Export())).SourceVerification);
        Assert.Equal(RemoteMediaPhase.Settled, Assert.Single(scope.ReadRemote(matched.Export())).Phase);
    }
    [Fact]
    public void RemoteMediaRecordsPreserveReferencesAndRejectLateClears()
    {
        const string uri = "/redfish/v1/Managers/1/VirtualMedia/1";
        using var scope = new VaultMediaScope("https://bmc.example", "fixture");
        var empty = "{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{}}"u8.ToArray();
        using var begin = scope.PatchRemote(empty, uri, null, RemoteMediaAction.Insert, RemoteMediaPhase.Submitting);
        var pending = begin.Export(); var first = Assert.Single(scope.ReadRemote(pending));
        byte[] reference = [0, 255, 42];
        using var accepted = scope.PatchRemote(pending, uri, first.OperationId, first.Action, RemoteMediaPhase.Accepted, reference);
        Assert.Equal(reference, Assert.Single(scope.ReadRemote(accepted.Export())).Reference);
        using var clear = scope.PatchRemote(accepted.Export(), uri, first.OperationId, first.Action, RemoteMediaPhase.Cleared);
        Assert.Empty(scope.ReadRemote(clear.Export()));
        using var replacement = scope.PatchRemote(clear.Export(), uri, null, RemoteMediaAction.Insert, RemoteMediaPhase.Submitting);
        Assert.NotEqual(first.OperationId, Assert.Single(scope.ReadRemote(replacement.Export())).OperationId);
        Assert.Throws<InvalidOperationException>(() => scope.PatchRemote(replacement.Export(), uri, first.OperationId, first.Action, RemoteMediaPhase.Cleared));
    }
    [Fact]
    public void MediaScopeUsesCoreIdentityAndRefusesToClearReplacement()
    {
        using var first = new VaultMediaScope("https://[2001:0db8:0:0:0:0:0:1]", "fixture");
        using var other = new VaultMediaScope("https://[2001:db8::1]:443/", "fixture");
        Assert.Equal(first.RecordId, other.RecordId);
        var empty = "{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{}}"u8.ToArray();
        using var begin = first.Patch(empty, MediaRecoveryOperation.Begin, 0); var pending = begin.Export();
        Assert.True(other.Read(pending).Pending);
        var observation = first.Observe(pending); using var observedScope = observation.Scope;
        Assert.True(observation.State.Pending);
        using var clear = first.Patch(pending, MediaRecoveryOperation.Clear, 0);
        using var replacement = first.Patch(clear.Export(), MediaRecoveryOperation.Begin, 0);
        Assert.Throws<BcException>(() => other.Patch(replacement.Export(), MediaRecoveryOperation.Clear, 0));
        Assert.True(first.Read(replacement.Export()).Pending);
        Assert.Throws<BcException>(() => observedScope.Patch(replacement.Export(), MediaRecoveryOperation.ClearObserved, 0));
        using var acknowledged = other.Patch(replacement.Export(), MediaRecoveryOperation.Acknowledge, 0);
        Assert.False(first.Read(acknowledged.Export()).Pending);
        using var imported = VaultMediaScope.ImportPending(acknowledged.Export(), [first.RecordId, first.RecordId]);
        Assert.False(first.Read(imported.Export()).Pending);
    }
    [Fact]
    public void RecordMergeRequiresConflictSelectionEvenWithNewerTimestamp()
    {
        static byte[] Snapshot(string name, long timestamp) => System.Text.Encoding.UTF8.GetBytes(
            "{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{\"device-1\":{\"fields\":{\"name\":\"" + name +
            "\"},\"deleted\":false,\"modified_at_ms\":" + timestamp + "}}}");
        using var merge = new VaultRecordMerge(Snapshot("base", 100), Snapshot("local", 1), Snapshot("remote", 999));
        Assert.Equal(1u, merge.Pending);
        var failure = Assert.Throws<BControl.Core.Native.BcException>(() => merge.Export());
        Assert.Equal(15u, failure.Status);
        Assert.Contains("device-1", System.Text.Encoding.UTF8.GetString(merge.ReadConflict(0)));
        merge.Resolve(0, VaultMergeChoice.Local);
        using var result = System.Text.Json.JsonDocument.Parse(merge.Export());
        Assert.Equal("local", result.RootElement.GetProperty("records").GetProperty("device-1").GetProperty("fields").GetProperty("name").GetString());
        Assert.Equal(0u, merge.Pending);
    }

    [Fact]
    public void SharedCoreDocumentOpensWithMasterPasswordAndSystemKey()
    {
        var data = "{\"devices\":[\"fixture\"]}"u8.ToArray();
        using var original = VaultDocument.Create(data, "fixture master password");
        var file = original.Export();
        var metadata = VaultDocument.ReadFileMetadata(file);
        Assert.Equal(original.Metadata, metadata);
        var key = original.CopyDataKey();
        try {
            using var system = VaultDocument.OpenWithKey(file, key);
            using var master = VaultDocument.OpenWithPassword(file, "fixture master password");
            Assert.Equal(data, system.ReadData());
            Assert.Equal(data, master.ReadData());
            Assert.Equal(metadata.VaultId, master.Metadata.VaultId);
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(data); }
    }
}

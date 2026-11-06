using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using BControl.Core.Native;

namespace BControl.Core.Storage;

public enum RemoteMediaSourceVerification : uint { Unknown, Verified, Unverified, Mismatch }
public enum RemoteMediaAction : uint { Insert = 1, Eject }
public enum RemoteMediaPhase : uint { Submitting = 1, Accepted, Settled, Cleared }
public sealed record RemoteMediaOperation(
    [property: JsonPropertyName("operation_id")] string OperationId,
    [property: JsonPropertyName("media_uri")] string MediaUri,
    [property: JsonPropertyName("action")] RemoteMediaAction Action,
    [property: JsonPropertyName("phase")] RemoteMediaPhase Phase,
    [property: JsonPropertyName("reference")] byte[]? Reference,
    [property: JsonPropertyName("source_verification")] RemoteMediaSourceVerification SourceVerification = RemoteMediaSourceVerification.Unknown,
    [property: JsonPropertyName("write_complete")] bool WriteComplete = false);

public sealed partial class VaultMediaScope
{
    public unsafe VaultRecordMerge RejectRemote(ReadOnlySpan<byte> snapshot, string uri, string expectedOperationId)
    {
        using var media = BcStringPinned.Pin(uri); using var expected = BcStringPinned.Pin(expectedOperationId);
        lock (_gate) { fixed (byte* data = snapshot) {
            Bc.Check(RemoteReject(_handle, new() { Data = (IntPtr)data, Length = (ulong)snapshot.Length }, media.Value,
                expected.Value, (ulong)Math.Max(0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()), out var merge), "vault.operation");
            return new(merge);
        } }
    }
    public unsafe IReadOnlyList<RemoteMediaOperation> ReadRemote(ReadOnlySpan<byte> snapshot)
    {
        lock (_gate) { fixed (byte* data = snapshot) {
            var source = new BcBytes { Data = (IntPtr)data, Length = (ulong)snapshot.Length };
            var status = RemoteList(_handle, source, null, 0, out var size);
            if (status != Bc.LimitExceeded) Bc.Check(status, "vault.operation");
            var result = new byte[checked((int)size)];
            try {
                Bc.Check(RemoteList(_handle, source, result, size, out _), "vault.operation");
                return JsonSerializer.Deserialize<RemoteMediaOperation[]>(result) ?? throw new InvalidDataException();
            }
            finally { CryptographicOperations.ZeroMemory(result); }
        } }
    }

    public unsafe VaultRecordMerge PatchRemote(ReadOnlySpan<byte> snapshot, string uri, string? expectedOperationId,
        RemoteMediaAction action, RemoteMediaPhase phase, ReadOnlySpan<byte> reference = default, string? source = null)
    {
        if (phase == RemoteMediaPhase.Submitting && source != null && !reference.IsEmpty) throw new ArgumentException(nameof(reference));
        using var sourceUri = BcStringPinned.Pin(source ?? "");
        using var media = BcStringPinned.Pin(uri); using var expected = BcStringPinned.Pin(expectedOperationId ?? "");
        lock (_gate) { fixed (byte* data = snapshot, saved = reference) {
            IntPtr merge;
            var status = phase == RemoteMediaPhase.Submitting && source != null
                ? RemoteBegin(_handle, new() { Data = (IntPtr)data, Length = (ulong)snapshot.Length }, media.Value, expected.Value,
                    (uint)action, sourceUri.Value, (ulong)Math.Max(0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()), out merge)
                : RemotePatch(_handle, new() { Data = (IntPtr)data, Length = (ulong)snapshot.Length },
                media.Value, expected.Value, (uint)action, (uint)phase,
                new() { Data = (IntPtr)saved, Length = (ulong)reference.Length },
                (ulong)Math.Max(0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()), out merge);
            if (status == Bc.ConfirmationRequired) throw new InvalidOperationException(BControl.Core.Localization.Loc.T("media.operationUnconfirmed"));
            Bc.Check(status, "vault.operation"); return new(merge);
        } }
    }

    public unsafe VaultRecordMerge ObserveRemoteSource(ReadOnlySpan<byte> snapshot, string uri, string expectedOperationId,
        string? reportedSource, bool completed, bool inserted = true)
    {
        using var media = BcStringPinned.Pin(uri); using var expected = BcStringPinned.Pin(expectedOperationId);
        using var source = BcStringPinned.Pin(reportedSource ?? "");
        lock (_gate) { fixed (byte* data = snapshot) {
            Bc.Check(RemoteObserve(_handle, new() { Data = (IntPtr)data, Length = (ulong)snapshot.Length }, media.Value,
                expected.Value, source.Value, completed ? 1u : 0u, inserted ? 1u : 0u, (ulong)Math.Max(0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()), out var merge), "vault.operation");
            return new(merge);
        } }
    }
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_remote_begin", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint RemoteBegin(Handle scope, BcBytes snapshot, BcString uri, BcString expected,
        uint action, BcString source, ulong timestamp, out IntPtr merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_remote_reject", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint RemoteReject(Handle scope, BcBytes snapshot, BcString uri, BcString expected, ulong timestamp, out IntPtr merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_remote_observe_source", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint RemoteObserve(Handle scope, BcBytes snapshot, BcString uri, BcString expected,
        BcString source, uint completed, uint inserted, ulong timestamp, out IntPtr merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_remote_list", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint RemoteList(Handle scope, BcBytes snapshot, [Out] byte[]? output, uint capacity, out uint written);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_remote_patch", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint RemotePatch(Handle scope, BcBytes snapshot, BcString uri, BcString expected,
        uint action, uint phase, BcBytes reference, ulong timestamp, out IntPtr merge);
}

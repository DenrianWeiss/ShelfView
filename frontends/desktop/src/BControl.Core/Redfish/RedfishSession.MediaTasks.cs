using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BControl.Core.Native;
using BControl.Core.Storage;

namespace BControl.Core.Redfish;

public sealed record RedfishTaskPersistenceScope(Guid EndpointId, string AddressDigest);
public readonly record struct RedfishMediaTaskSnapshot(uint Flags, string RetryAfter = "")
{
    public bool Terminal => (Flags & RedfishAbi.TaskTerminal) != 0;
    public bool Failed => (Flags & (RedfishAbi.TaskFailed | RedfishAbi.TaskCancelled)) != 0;
}

public sealed partial class RedfishSession
{
    private async Task<IntPtr> RetainCompletedAsync(SubmitDelegate submit, CancellationToken cancellation)
    {
        IntPtr retained = IntPtr.Zero;
        try
        {
            await RunAsync(submit, (operation, result) => {
                Bc.Check(SnapshotResult(operation, result).Status, "core.readMedia");
                RedfishTaskNative.bc_redfish_retain(operation); retained = operation; return 0;
            }, NativeMethods.bc_redfish_cancel, cancellation, "core.readMedia").ConfigureAwait(false);
            return retained;
        }
        catch { await ReleaseCompletedAsync(retained).ConfigureAwait(false); throw; }
    }
    private Task<int> ReleaseCompletedAsync(IntPtr operation) => operation == IntPtr.Zero ? Task.FromResult(0) :
        _runtime.InvokeAsync(() => { NativeMethods.bc_redfish_release(operation); return 0; });

    private Task<IntPtr> DiscoverTasksAsync(OperationBudget budget, CancellationToken cancellation) =>
        RetainCompletedAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) => {
            var options = CollectionOptions(budget.RemainingMilliseconds());
            return RedfishTaskNative.bc_redfish_discover_tasks(_endpoint, ref options, completion, userdata, out operation);
        }, cancellation);

    private async Task<RedfishMediaWriteResult> MediaWriteAsync(SubmitDelegate submit, string what,
        OperationBudget budget, CancellationToken cancellation, RedfishTaskPersistenceScope? persistence)
    {
        IntPtr retained = IntPtr.Zero, discovery = IntPtr.Zero;
        try
        {
            var result = await RunAsync(submit, (operation, response) => {
                var value = SnapshotResult(operation, response);
                if (value.Status != Bc.Ok) throw new BcException(value.Status,
                    BControl.Core.Localization.Loc.F("error.context", ("what", BControl.Core.Localization.Loc.T(what)),
                        ("detail", Bc.StatusText(value.Status))), value.HttpStatus,
                    (value.Flags & RedfishAbi.CommandUnconfirmed) != 0);
                if (persistence != null && (value.Flags & RedfishAbi.TaskPending) != 0) {
                    RedfishTaskNative.bc_redfish_retain(operation); retained = operation;
                }
                var info = RedfishTaskNative.bc_redfish_task_info_get(operation);
                return new RedfishMediaWriteResult(value.Flags, RetryAfter: info == IntPtr.Zero ? "" : Text(Marshal.PtrToStructure<BcRedfishTaskInfo>(info).RetryAfter));
            }, NativeMethods.bc_redfish_cancel, cancellation, what).ConfigureAwait(false);
            if (retained == IntPtr.Zero || persistence == null) return result;
            try
            {
                discovery = await DiscoverTasksAsync(budget, cancellation).ConfigureAwait(false);
                var saved = await _runtime.InvokeAsync(() => {
                    using var endpoint = BcStringPinned.Pin(persistence.EndpointId.ToString("D"));
                    using var digest = BcStringPinned.Pin(persistence.AddressDigest);
                    var bytes = new byte[8192];
                    try {
                        Bc.Check(RedfishTaskNative.bc_redfish_task_reference_export_operation(retained, discovery,
                            endpoint.Value, digest.Value, bytes, (uint)bytes.Length, out var size), "core.readMedia");
                        return bytes.AsSpan(0, checked((int)size)).ToArray();
                    }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }).ConfigureAwait(false);
                return result with { Reference = saved };
            }
            catch (BcException) { return result; }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { return result; }
        }
        finally
        {
            try { await ReleaseCompletedAsync(discovery).ConfigureAwait(false); }
            finally { await ReleaseCompletedAsync(retained).ConfigureAwait(false); }
        }
    }

    public async Task<RedfishMediaTaskSnapshot> ResumeMediaTaskAsync(byte[] saved, string mediaUri,
        RemoteMediaAction action, RedfishTaskPersistenceScope persistence, uint timeoutMs,
        CancellationToken cancellation = default)
    {
        if (saved.Length is < 1 or > 8192) throw new ArgumentOutOfRangeException(nameof(saved));
        using var budget = new OperationBudget(timeoutMs);
        using var registration = cancellation.Register(budget.Cancel);
        IntPtr discovery = IntPtr.Zero, media = IntPtr.Zero;
        try
        {
            discovery = await DiscoverTasksAsync(budget, cancellation).ConfigureAwait(false);
            using var uri = BcStringPinned.Pin(mediaUri);
            media = await RetainCompletedAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) => {
                var options = Options(budget.RemainingMilliseconds());
                return NativeMethods.bc_redfish_get_virtual_media(_endpoint, uri.Value, ref options, completion, userdata, out operation);
            }, cancellation).ConfigureAwait(false);
            var reference = await _runtime.InvokeAsync(() => RestoreMediaReference(saved, media, discovery, action, persistence)).ConfigureAwait(false);
            using var task = BcStringPinned.Pin(reference.Uri);
            return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) => {
                var options = Options(budget.RemainingMilliseconds());
                return RedfishTaskNative.bc_redfish_get_task(_endpoint, task.Value, ref options, completion, userdata, out operation);
            }, (operation, response) => {
                Bc.Check(SnapshotResult(operation, response).Status, "core.readMedia");
                using var endpoint = BcStringPinned.Pin(persistence.EndpointId.ToString("D"));
                using var digest = BcStringPinned.Pin(persistence.AddressDigest);
                Bc.Check(RedfishTaskNative.bc_redfish_task_reference_match_operation(ref reference, operation,
                    discovery, endpoint.Value, digest.Value, out var flags), "core.readMedia");
                var info = RedfishTaskNative.bc_redfish_task_info_get(operation);
                if (info == IntPtr.Zero) throw new BcException(Bc.ProtocolError, BControl.Core.Localization.Loc.T("core.mediaSnapshotMissing"));
                return new RedfishMediaTaskSnapshot(flags, Text(Marshal.PtrToStructure<BcRedfishTaskInfo>(info).RetryAfter));
            }, NativeMethods.bc_redfish_cancel, cancellation, "core.readMedia").ConfigureAwait(false);
        }
        finally
        {
            try { await ReleaseCompletedAsync(media).ConfigureAwait(false); }
            finally { await ReleaseCompletedAsync(discovery).ConfigureAwait(false); }
        }
    }
    private static unsafe BcRedfishTaskReference RestoreMediaReference(byte[] saved, IntPtr media, IntPtr discovery,
        RemoteMediaAction action, RedfishTaskPersistenceScope persistence)
    {
        using var endpoint = BcStringPinned.Pin(persistence.EndpointId.ToString("D"));
        using var digest = BcStringPinned.Pin(persistence.AddressDigest);
        fixed (byte* bytes = saved) {
            Bc.Check(RedfishTaskNative.bc_redfish_task_reference_restore_operation(
                new() { Data = (IntPtr)bytes, Length = (ulong)saved.Length }, media, discovery,
                endpoint.Value, digest.Value, (uint)action, out var reference), "core.readMedia");
            return reference;
        }
    }
}

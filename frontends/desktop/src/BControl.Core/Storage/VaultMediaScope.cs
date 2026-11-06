using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Storage;
public readonly record struct MediaRecoveryState(bool Known, bool Pending);
public enum MediaRecoveryOperation : uint { Begin = 1, Clear, ImportPending, Acknowledge, ClearObserved }
public sealed partial class VaultMediaScope : IDisposable
{
    public static unsafe VaultRecordMerge ImportPending(ReadOnlySpan<byte> snapshot, IReadOnlyList<string> recordIds)
    {
        if (recordIds.Count > 8192) throw new ArgumentOutOfRangeException(nameof(recordIds));
        var pinned = new List<BcStringPinned>();
        try {
            foreach (var id in recordIds) pinned.Add(BcStringPinned.Pin(id));
            var ids = pinned.Select(value => value.Value).ToArray();
            fixed (byte* data = snapshot) {
                Bc.Check(ImportCore(new() { Data = (IntPtr)data, Length = (ulong)snapshot.Length }, ids, (uint)ids.Length,
                    (ulong)Math.Max(0, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()), out var merge), "vault.operation");
                return new(merge);
            }
        }
        finally { foreach (var id in pinned) id.Dispose(); }
    }
    private readonly object _gate = new();
    private readonly Handle _handle;
    private VaultMediaScope(IntPtr handle) => _handle = new(handle);
    public VaultMediaScope(string address, string username)
    {
        using var origin = BcStringPinned.Pin(address); using var user = BcStringPinned.Pin(username);
        Bc.Check(Create(origin.Value, user.Value, out var handle), "vault.operation"); _handle = new(handle);
    }
    public string RecordId {
        get { lock (_gate) {
            var id = Id(_handle); return Marshal.PtrToStringUTF8(id.Data, checked((int)id.Length)) ?? throw new InvalidDataException();
        } }
    }
    public unsafe MediaRecoveryState Read(ReadOnlySpan<byte> snapshot)
    {
        lock (_gate) { fixed (byte* data = snapshot) {
            Bc.Check(ReadCore(_handle, new() { Data = (IntPtr)data, Length = (ulong)snapshot.Length }, out var known, out var pending), "vault.operation");
            return new(known != 0, pending != 0);
        } }
    }
    public unsafe (VaultMediaScope Scope, MediaRecoveryState State) Observe(ReadOnlySpan<byte> snapshot)
    {
        lock (_gate) { fixed (byte* data = snapshot) {
            Bc.Check(ObserveCore(_handle, new() { Data = (IntPtr)data, Length = (ulong)snapshot.Length }, out var scope, out var known, out var pending), "vault.operation");
            return (new(scope), new(known != 0, pending != 0));
        } }
    }
    public unsafe VaultRecordMerge Patch(ReadOnlySpan<byte> snapshot, MediaRecoveryOperation operation, long? modifiedAtMs = null)
    {
        lock (_gate) { fixed (byte* data = snapshot) {
            var status = PatchCore(_handle, new() { Data = (IntPtr)data, Length = (ulong)snapshot.Length }, (uint)operation,
                checked((ulong)Math.Max(0, modifiedAtMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())), out var merge);
            if (status == Bc.ConfirmationRequired) throw new BcException(status, Loc.T(operation == MediaRecoveryOperation.Begin ? "media.removalUnconfirmed" : "media.operationUnconfirmed"));
            Bc.Check(status, "vault.operation"); return new(merge);
        } }
    }
    public void Dispose() { lock (_gate) _handle.Dispose(); }
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr handle) : base(true) => SetHandle(handle);
        protected override bool ReleaseHandle() { Destroy(handle); return true; }
    }
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_scope_create", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint Create(BcString address, BcString username, out IntPtr scope);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_import_pending", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint ImportCore(BcBytes snapshot, [In] BcString[] ids, uint count, ulong timestamp, out IntPtr merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_scope_id", CallingConvention = CallingConvention.Cdecl)]
    private static extern BcString Id(Handle scope);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_scope_read", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint ReadCore(Handle scope, BcBytes snapshot, out int known, out int pending);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_scope_observe", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint ObserveCore(Handle scope, BcBytes snapshot, out IntPtr observation, out int known, out int pending);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_scope_patch", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint PatchCore(Handle scope, BcBytes snapshot, uint operation, ulong timestamp, out IntPtr merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_media_scope_destroy", CallingConvention = CallingConvention.Cdecl)]
    private static extern void Destroy(IntPtr scope);
}

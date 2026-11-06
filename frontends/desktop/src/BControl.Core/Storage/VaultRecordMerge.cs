using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using BControl.Core.Native;

namespace BControl.Core.Storage;

public enum VaultMergeChoice : uint { Base = 1, Local, Remote }
public sealed class VaultRecordMerge : IDisposable
{
    private readonly object _gate = new();
    private readonly Handle _handle;
    internal VaultRecordMerge(IntPtr handle) => _handle = new(handle);
    public static unsafe VaultRecordMerge PatchBatch(ReadOnlySpan<byte> snapshot, ReadOnlySpan<byte> patches)
    {
        fixed (byte* a = snapshot, b = patches) {
            Bc.Check(PatchBatchCore(new() { Data = (IntPtr)a, Length = (ulong)snapshot.Length },
                new() { Data = (IntPtr)b, Length = (ulong)patches.Length }, out var handle), "vault.operation");
            return new(handle);
        }
    }
    public static unsafe VaultRecordMerge Patch(ReadOnlySpan<byte> snapshot, string id, ReadOnlySpan<byte> fields,
        bool deleted = false, long? modifiedAtMs = null)
    {
        using var reference = BcStringPinned.Pin(id);
        fixed (byte* a = snapshot, b = fields) {
            Bc.Check(PatchCore(new() { Data = (IntPtr)a, Length = (ulong)snapshot.Length }, reference.Value,
                new() { Data = (IntPtr)b, Length = (ulong)fields.Length }, deleted ? 1 : 0,
                checked((ulong)(modifiedAtMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())), out var handle), "vault.operation");
            return new(handle);
        }
    }
    public unsafe VaultRecordMerge(ReadOnlySpan<byte> baseline, ReadOnlySpan<byte> local, ReadOnlySpan<byte> remote)
    {
        fixed (byte* a = baseline, b = local, c = remote) {
            Bc.Check(Create(new() { Data = (IntPtr)a, Length = (ulong)baseline.Length },
                new() { Data = (IntPtr)b, Length = (ulong)local.Length },
                new() { Data = (IntPtr)c, Length = (ulong)remote.Length }, out var handle), "vault.operation");
            _handle = new(handle);
        }
    }
    public uint ConflictCount { get { lock (_gate) return Count(_handle); } }
    public uint Pending { get { lock (_gate) return Unresolved(_handle); } }
    public byte[] ReadConflict(uint index)
    {
        lock (_gate) {
            Bc.Check(Conflict(_handle, index, out var bytes), "vault.operation");
            var result = new byte[checked((int)bytes.Length)];
            if (result.Length != 0) Marshal.Copy(bytes.Data, result, 0, result.Length);
            return result;
        }
    }
    public void Resolve(uint index, VaultMergeChoice choice)
    {
        lock (_gate) Bc.Check(ResolveCore(_handle, index, (uint)choice), "vault.operation");
    }
    public byte[] Export()
    {
        lock (_gate) {
            var status = ExportCore(_handle, null, 0, out var size);
            if (status != Bc.LimitExceeded) Bc.Check(status, "vault.operation");
            var result = new byte[checked((int)size)];
            Bc.Check(ExportCore(_handle, result, size, out _), "vault.operation"); return result;
        }
    }
    public void Dispose() { lock (_gate) _handle.Dispose(); }
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr pointer) : base(true) => SetHandle(pointer);
        protected override bool ReleaseHandle() { Destroy(handle); return true; }
    }
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_records_patch", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint PatchBatchCore(BcBytes snapshot, BcBytes patches, out IntPtr merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_record_patch", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint PatchCore(BcBytes snapshot, BcString id, BcBytes fields, int deleted, ulong timestamp, out IntPtr merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_merge_create", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint Create(BcBytes baseline, BcBytes local, BcBytes remote, out IntPtr merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_merge_conflicts", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint Count(Handle merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_merge_pending", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint Unresolved(Handle merge);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_merge_conflict", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint Conflict(Handle merge, uint index, out BcBytes bytes);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_merge_resolve", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint ResolveCore(Handle merge, uint index, uint choice);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_merge_export", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint ExportCore(Handle merge, [Out] byte[]? bytes, uint capacity, out uint written);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_merge_destroy", CallingConvention = CallingConvention.Cdecl)]
    private static extern void Destroy(IntPtr merge);
}

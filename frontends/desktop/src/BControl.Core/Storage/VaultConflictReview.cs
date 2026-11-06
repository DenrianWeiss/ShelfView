using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using BControl.Core.Native;
using BControl.Core.Localization;

namespace BControl.Core.Storage;

public sealed record VaultConflictValue([property: JsonPropertyName("kind")] uint Kind, [property: JsonPropertyName("text")] string Text)
{
    public string Display => Kind switch { 0 => Loc.T("vault.valueAbsent"), 2 => "••••", 3 => Loc.T("vault.valueCompound"), 4 => Loc.T("vault.valueDeleted"), _ => Text };
}
public sealed record VaultConflictField([property: JsonPropertyName("record")] string Record, [property: JsonPropertyName("field")] string Field,
    [property: JsonPropertyName("base")] VaultConflictValue Base, [property: JsonPropertyName("local")] VaultConflictValue Local,
    [property: JsonPropertyName("remote")] VaultConflictValue Remote);

public sealed class VaultConflictReview : IDisposable
{
    private readonly Handle _handle;
    private readonly object _gate = new();
    internal object Owner { get; }
    internal byte[] Expected { get; }
    internal byte[] ArchiveSignature { get; }
    public string ConflictId { get; }
    public bool FieldChoices { get; }
    public IReadOnlyList<VaultConflictField> Fields { get; }
    private VaultConflictReview(Handle handle, object owner, string id, byte[] expected, byte[] signature)
    {
        _handle = handle; Owner = owner; ConflictId = id; Expected = expected; ArchiveSignature = signature;
        FieldChoices = IsFields(handle) != 0;
        var fields = new List<VaultConflictField>();
        for (uint i = 0, count = Count(handle); i < count; ++i) {
            Bc.Check(Field(handle, i, out var bytes), "vault.operation");
            var data = new byte[checked((int)bytes.Length)];
            try {
                Marshal.Copy(bytes.Data, data, 0, data.Length);
                fields.Add(JsonSerializer.Deserialize<VaultConflictField>(data) ?? throw new InvalidDataException());
            }
            finally { CryptographicOperations.ZeroMemory(data); }
        }
        Fields = fields.AsReadOnly();
    }
    internal static unsafe VaultConflictReview Create(object owner, string id, byte[] baseline, byte[] local, byte[] current, byte[] key, byte[] signature)
    {
        fixed (byte* a = baseline, b = local, c = current, k = key) {
            Bc.Check(CreateCore(new() { Data = (IntPtr)a, Length = (ulong)baseline.Length }, new() { Data = (IntPtr)b, Length = (ulong)local.Length },
                new() { Data = (IntPtr)c, Length = (ulong)current.Length }, new() { Data = (IntPtr)k, Length = (ulong)key.Length }, out var pointer), "vault.operation");
            var handle = new Handle(pointer);
            try { return new(handle, owner, id, current, signature); } catch { handle.Dispose(); throw; }
        }
    }
    internal byte[] Export(IReadOnlyDictionary<uint, VaultMergeChoice> choices, VaultMergeChoice? version)
    {
        lock (_gate) {
            if (FieldChoices) {
                if (choices.Count != Fields.Count || choices.Keys.Any(index => index >= Fields.Count) || choices.Values.Any(value => value is not (VaultMergeChoice.Local or VaultMergeChoice.Remote))) throw new ArgumentException(nameof(choices));
                for (uint i = 0; i < Fields.Count; ++i) Bc.Check(Resolve(_handle, i, (uint)choices[i]), "vault.operation");
            }
            else Bc.Check(Select(_handle, (uint)(version ?? 0)), "vault.operation");
            var status = ExportCore(_handle, null, 0, out var size);
            if (status != Bc.LimitExceeded) Bc.Check(status, "vault.operation");
            var data = new byte[checked((int)size)];
            Bc.Check(ExportCore(_handle, data, size, out _), "vault.operation"); return data;
        }
    }
    public void Dispose() { lock (_gate) _handle.Dispose(); }
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr pointer) : base(true) { SetHandle(pointer); }
        protected override bool ReleaseHandle() { Destroy(handle); return true; }
    }
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_conflict_create", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint CreateCore(BcBytes baseline, BcBytes local, BcBytes current, BcBytes key, out IntPtr handle);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_conflict_fields", CallingConvention = CallingConvention.Cdecl)] private static extern int IsFields(Handle handle);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_conflict_count", CallingConvention = CallingConvention.Cdecl)] private static extern uint Count(Handle handle);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_conflict_field", CallingConvention = CallingConvention.Cdecl)] private static extern uint Field(Handle handle, uint index, out BcBytes value);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_conflict_resolve", CallingConvention = CallingConvention.Cdecl)] private static extern uint Resolve(Handle handle, uint index, uint choice);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_conflict_select", CallingConvention = CallingConvention.Cdecl)] private static extern uint Select(Handle handle, uint choice);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_conflict_export", CallingConvention = CallingConvention.Cdecl)] private static extern uint ExportCore(Handle handle, [Out] byte[]? data, uint capacity, out uint written);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_conflict_destroy", CallingConvention = CallingConvention.Cdecl)] private static extern void Destroy(IntPtr handle);
}

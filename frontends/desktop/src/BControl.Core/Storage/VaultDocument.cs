using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using BControl.Core.Native;

namespace BControl.Core.Storage;

public sealed record VaultMetadata(string VaultId, string KeyId, string Revision, string ParentRevision, ulong DataSize);

public sealed class VaultDocument : IDisposable
{
    public static unsafe bool IsDirectChild(ReadOnlySpan<byte> parent, ReadOnlySpan<byte> child, ReadOnlySpan<byte> dataKey)
    {
        fixed (byte* a = parent, b = child, key = dataKey) {
            Bc.Check(DirectChild(new() { Data = (IntPtr)a, Length = (ulong)parent.Length },
                new() { Data = (IntPtr)b, Length = (ulong)child.Length },
                new() { Data = (IntPtr)key, Length = (ulong)dataKey.Length }, out var direct), "vault.operation");
            return direct != 0;
        }
    }
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_file_direct_child", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint DirectChild(BcBytes parent, BcBytes child, BcBytes key, out int direct);
    private readonly object _gate = new();
    private readonly Handle _handle;
    private VaultDocument(IntPtr handle) => _handle = new(handle);

    public static unsafe VaultDocument Create(ReadOnlySpan<byte> data, string masterPassword)
    {
        using var password = BcStringPinned.Pin(masterPassword);
        fixed (byte* bytes = data) {
            Bc.Check(Native.Create(new() { Data = (IntPtr)bytes, Length = (ulong)data.Length }, password.Value, out var handle), "vault.operation");
            return new(handle);
        }
    }
    public static unsafe VaultDocument OpenWithPassword(ReadOnlySpan<byte> file, string masterPassword)
    {
        using var password = BcStringPinned.Pin(masterPassword);
        fixed (byte* bytes = file) {
            Bc.Check(Native.OpenPassword(new() { Data = (IntPtr)bytes, Length = (ulong)file.Length }, password.Value, out var handle), "vault.operation");
            return new(handle);
        }
    }
    public static unsafe VaultDocument OpenWithKey(ReadOnlySpan<byte> file, ReadOnlySpan<byte> dataKey)
    {
        fixed (byte* bytes = file, key = dataKey) {
            Bc.Check(Native.OpenKey(new() { Data = (IntPtr)bytes, Length = (ulong)file.Length },
                new() { Data = (IntPtr)key, Length = (ulong)dataKey.Length }, out var handle), "vault.operation");
            return new(handle);
        }
    }
    public static unsafe VaultMetadata ReadFileMetadata(ReadOnlySpan<byte> file)
    {
        var info = Info.Create();
        fixed (byte* bytes = file)
            Bc.Check(Native.FileInfo(new() { Data = (IntPtr)bytes, Length = (ulong)file.Length }, ref info), "vault.operation");
        return info.Metadata;
    }
    public VaultMetadata Metadata {
        get {
            lock (_gate) {
                var info = Info.Create();
                Bc.Check(Native.GetInfo(_handle, ref info), "vault.operation");
                return info.Metadata;
            }
        }
    }
    public byte[] ReadData()
    {
        lock (_gate) {
            var data = Native.Data(_handle);
            var result = new byte[checked((int)data.Length)];
            if (result.Length != 0) Marshal.Copy(data.Data, result, 0, result.Length);
            return result;
        }
    }
    public byte[] CopyDataKey()
    {
        lock (_gate) {
            var key = new byte[32];
            Bc.Check(Native.CopyKey(_handle, key, (uint)key.Length), "vault.operation");
            return key;
        }
    }
    public unsafe void Replace(ReadOnlySpan<byte> data)
    {
        lock (_gate) fixed (byte* bytes = data)
            Bc.Check(Native.Replace(_handle, new() { Data = (IntPtr)bytes, Length = (ulong)data.Length }), "vault.operation");
    }
    public void ChangeMasterPassword(string masterPassword)
    {
        using var password = BcStringPinned.Pin(masterPassword);
        lock (_gate) Bc.Check(Native.ChangePassword(_handle, password.Value), "vault.operation");
    }
    public byte[] Export()
    {
        lock (_gate) {
            var status = Native.Export(_handle, null, 0, out var size);
            if (status != Bc.LimitExceeded) Bc.Check(status, "vault.operation");
            var result = new byte[checked((int)size)];
            Bc.Check(Native.Export(_handle, result, size, out _), "vault.operation");
            return result;
        }
    }
    public void Dispose() { lock (_gate) _handle.Dispose(); }

    [StructLayout(LayoutKind.Sequential)]
    private struct Info
    {
        internal uint StructSize, Version;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] VaultId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] KeyId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] Revision;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] ParentRevision;
        internal ulong DataSize;
        internal static Info Create() => new() { StructSize = (uint)Marshal.SizeOf<Info>(),
            VaultId = new byte[16], KeyId = new byte[16], Revision = new byte[16], ParentRevision = new byte[16] };
        internal readonly VaultMetadata Metadata => new(Convert.ToHexString(VaultId).ToLowerInvariant(),
            Convert.ToHexString(KeyId).ToLowerInvariant(), Convert.ToHexString(Revision).ToLowerInvariant(),
            Convert.ToHexString(ParentRevision).ToLowerInvariant(), DataSize);
    }
    private sealed class Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal Handle(IntPtr handle) : base(true) => SetHandle(handle);
        protected override bool ReleaseHandle() { Native.Destroy(handle); return true; }
    }
    private static class Native
    {
        private const string Library = "bcontrol_vault";
        [DllImport(Library, EntryPoint = "bc_vault_file_info", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint FileInfo(BcBytes file, ref Info info);
        [DllImport(Library, EntryPoint = "bc_vault_info_get", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint GetInfo(Handle handle, ref Info info);
        [DllImport(Library, EntryPoint = "bc_vault_create", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint Create(BcBytes data, BcString password, out IntPtr handle);
        [DllImport(Library, EntryPoint = "bc_vault_open_password", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint OpenPassword(BcBytes file, BcString password, out IntPtr handle);
        [DllImport(Library, EntryPoint = "bc_vault_open_key", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint OpenKey(BcBytes file, BcBytes key, out IntPtr handle);
        [DllImport(Library, EntryPoint = "bc_vault_data", CallingConvention = CallingConvention.Cdecl)]
        internal static extern BcBytes Data(Handle handle);
        [DllImport(Library, EntryPoint = "bc_vault_key_copy", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint CopyKey(Handle handle, [Out] byte[] key, uint capacity);
        [DllImport(Library, EntryPoint = "bc_vault_replace", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint Replace(Handle handle, BcBytes data);
        [DllImport(Library, EntryPoint = "bc_vault_change_password", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint ChangePassword(Handle handle, BcString password);
        [DllImport(Library, EntryPoint = "bc_vault_export", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint Export(Handle handle, [Out] byte[]? file, uint capacity, out uint written);
        [DllImport(Library, EntryPoint = "bc_vault_destroy", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void Destroy(IntPtr handle);
    }
}

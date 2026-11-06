using System.Runtime.InteropServices;
using BControl.Core.Localization;

namespace BControl.Desktop.Services;

// Retained for migration of the former per-device Secret Service entries.
public sealed class LibSecretCredentialStore : ICredentialStore
{
    private const string Library = "libsecret-1.so.0";
    private static IntPtr _glib;
    private static readonly bool Loadable = Load();
    private static readonly IntPtr Schema = TryCreateSchema();
    [DllImport("libglib-2.0.so.0")] private static extern IntPtr g_hash_table_new(IntPtr hash, IntPtr equal);
    [DllImport("libglib-2.0.so.0")] private static extern void g_hash_table_insert(IntPtr table, IntPtr key, IntPtr value);
    [DllImport("libglib-2.0.so.0")] private static extern void g_hash_table_unref(IntPtr table);
    [DllImport("libglib-2.0.so.0")] private static extern void g_clear_error(ref IntPtr error);
    [DllImport(Library)] private static extern IntPtr secret_schema_newv([MarshalAs(UnmanagedType.LPUTF8Str)] string name, int flags, IntPtr attributes);
    [DllImport(Library)] private static extern IntPtr secret_password_lookupv_sync(IntPtr schema, IntPtr attributes, IntPtr cancellation, out IntPtr error);
    [DllImport(Library)] private static extern bool secret_password_clearv_sync(IntPtr schema, IntPtr attributes, IntPtr cancellation, out IntPtr error);
    [DllImport(Library)] private static extern void secret_password_free(IntPtr password);
    private static bool Load()
    {
        if (!OperatingSystem.IsLinux()) return false;
        try { NativeLibrary.Load(Library); _glib = NativeLibrary.Load("libglib-2.0.so.0"); return true; }
        catch { return false; }
    }
    private static IntPtr NewTable() => g_hash_table_new(NativeLibrary.GetExport(_glib, "g_str_hash"), NativeLibrary.GetExport(_glib, "g_str_equal"));
    private static IntPtr TryCreateSchema()
    {
        try { return CreateSchema(); }
        catch (DllNotFoundException) { return IntPtr.Zero; }
        catch (EntryPointNotFoundException) { return IntPtr.Zero; }
    }
    private static IntPtr CreateSchema()
    {
        if (!Loadable) return IntPtr.Zero;
        var table = NewTable(); if (table == IntPtr.Zero) return IntPtr.Zero;
        var application = Marshal.StringToCoTaskMemUTF8("application"); var reference = Marshal.StringToCoTaskMemUTF8("server-id");
        try {
            g_hash_table_insert(table, application, IntPtr.Zero); g_hash_table_insert(table, reference, IntPtr.Zero);
            // SECRET_SCHEMA_DONT_MATCH_NAME lets the Vault migration find entries under the old schema.
            return secret_schema_newv("work.permutation.shelfview.Credential", 1, table);
        }
        finally { g_hash_table_unref(table); Marshal.FreeCoTaskMem(application); Marshal.FreeCoTaskMem(reference); }
    }
    private sealed class Attributes : IDisposable
    {
        internal readonly IntPtr Table;
        private readonly List<IntPtr> _strings = [];
        internal Attributes(string reference)
        {
            if (!Loadable || Schema == IntPtr.Zero) throw new InvalidOperationException(Loc.T("error.credentialStoreUnavailable"));
            if (reference.Contains('\0')) throw new ArgumentException(nameof(reference));
            Table = NewTable(); if (Table == IntPtr.Zero) throw new OutOfMemoryException();
            try { Insert("application", "bControl"); Insert("server-id", reference); }
            catch { Dispose(); throw; }
        }
        private void Insert(string name, string value)
        {
            var key = Marshal.StringToCoTaskMemUTF8(name); _strings.Add(key);
            var text = Marshal.StringToCoTaskMemUTF8(value); _strings.Add(text); g_hash_table_insert(Table, key, text);
        }
        public void Dispose() { g_hash_table_unref(Table); foreach (var pointer in _strings) Marshal.FreeCoTaskMem(pointer); _strings.Clear(); }
    }
    private static void Check(ref IntPtr error)
    {
        if (error == IntPtr.Zero) return;
        g_clear_error(ref error); throw new InvalidOperationException(Loc.T("error.credentialStoreUnavailable"));
    }
    public bool IsAvailable => Loadable && Schema != IntPtr.Zero;
    public Task StoreAsync(string reference, string username, string password, CancellationToken cancellation) =>
        Task.FromException(new NotSupportedException("Legacy credentials are read-only"));
    public Task<string?> ReadPasswordAsync(string reference, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested(); using var attributes = new Attributes(reference);
        var password = secret_password_lookupv_sync(Schema, attributes.Table, IntPtr.Zero, out var error);
        try { Check(ref error); return Task.FromResult(password == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(password)); }
        finally { if (password != IntPtr.Zero) secret_password_free(password); }
    }
    public Task DeleteAsync(string reference, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested(); using var attributes = new Attributes(reference);
        secret_password_clearv_sync(Schema, attributes.Table, IntPtr.Zero, out var error); Check(ref error); return Task.CompletedTask;
    }
}

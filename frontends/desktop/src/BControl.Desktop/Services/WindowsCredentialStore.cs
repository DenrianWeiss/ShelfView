using BControl.Core.Localization;
using System.Runtime.InteropServices;
using System.Text;

namespace BControl.Desktop.Services;

/// <summary>旧 Windows 设备凭据的读取与迁移清理；新密钥存取走核心 Vault 接口。</summary>
public sealed class WindowsCredentialStore : ICredentialStore
{
    private const uint CredentialTypeGeneric = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low, High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCredential
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public FileTime LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredReadW(string target, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredDeleteW(string target, uint type, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    public bool IsAvailable => OperatingSystem.IsWindows();

    public Task StoreAsync(string reference, string username, string password, CancellationToken cancellation) =>
        Task.FromException(new NotSupportedException("Legacy credentials are read-only"));

    public Task<string?> ReadPasswordAsync(string reference, CancellationToken cancellation)
    {
        var target = TargetName(reference);
        cancellation.ThrowIfCancellationRequested();
        if (!CredReadW(target, CredentialTypeGeneric, 0, out var pointer)) {
            var error = Marshal.GetLastWin32Error();
            if (error == 1168) return Task.FromResult<string?>(null);
            throw new System.ComponentModel.Win32Exception(error);
        }
        if (pointer == IntPtr.Zero) throw new InvalidDataException(Loc.T("vault.invalid"));
        try
        {
            var native = Marshal.PtrToStructure<NativeCredential>(pointer);
            if (native.CredentialBlobSize == 0) return Task.FromResult<string?>("");
            if (native.CredentialBlob == IntPtr.Zero || native.CredentialBlobSize > 131072) throw new InvalidDataException(Loc.T("vault.invalid"));
            var bytes = new byte[native.CredentialBlobSize];
            try { Marshal.Copy(native.CredentialBlob, bytes, 0, bytes.Length); return Task.FromResult<string?>(Encoding.UTF8.GetString(bytes)); }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
        }
        finally
        {
            CredFree(pointer);
        }
    }

    public Task DeleteAsync(string reference, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        if (!CredDeleteW(TargetName(reference), CredentialTypeGeneric, 0)) {
            var error = Marshal.GetLastWin32Error();
            if (error != 1168) throw new System.ComponentModel.Win32Exception(error);
        }
        return Task.CompletedTask;
    }

    private static string TargetName(string reference) => $"bControl/{reference}";
}

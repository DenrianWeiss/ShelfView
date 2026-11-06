using System.Globalization;
using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Security;
public sealed record TlsPeer(string Version, string Cipher, string Subject, string Issuer, string Sha256, DateTime NotBefore, DateTime NotAfter, bool Trusted);
public static class TlsDiagnostics
{
    public static async Task<TlsPeer?> ProbeAsync(string address, CancellationToken cancellation = default, Socks5Connection? proxy = null)
    {
        if (!Uri.TryCreate(address.Contains("://", StringComparison.Ordinal) ? address : "https://" + address, UriKind.Absolute, out var origin) ||
            origin.Scheme != "https" || origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0 || origin.AbsolutePath != "/") return null;
        cancellation.ThrowIfCancellationRequested();
        try
        {
            var peer = await Task.Run(() => {
                cancellation.ThrowIfCancellationRequested();
                using var url = BcStringPinned.Pin(new UriBuilder(origin) { Scheme = "tls", Port = origin.Port, Path = "" }.Uri.AbsoluteUri);
                var options = new BcKvmTransportOptions { StructSize = (uint)Marshal.SizeOf<BcKvmTransportOptions>(),
                    AbiVersion = Bc.AbiVersion, Url = url.Value, CertPolicy = Bc.CertSkipAll,
                    TlsMin = 10, TlsMax = 13, Flags = 2, TimeoutMs = 8000 };
                Bc.Check(NativeConnections.Connect(ref options, proxy, out var transport), "core.createEndpoint");
                try
                {
                    cancellation.ThrowIfCancellationRequested();
                    Bc.Check(bc_kvm_transport_peer_info(transport, out var info), "core.createEndpoint");
                    static string Text(byte[] bytes) => System.Text.Encoding.UTF8.GetString(bytes, 0, Array.IndexOf(bytes, (byte)0));
                    static DateTime Date(byte[] bytes) => DateTime.ParseExact(Text(bytes), "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
                    return new TlsPeer(Text(info.Version), Text(info.Cipher), Text(info.Subject), Text(info.Issuer), Text(info.Sha256),
                        Date(info.NotBefore), Date(info.NotAfter), info.Trusted != 0);
                }
                finally { NativeMethods.bc_kvm_transport_interrupt(transport); NativeMethods.bc_kvm_transport_destroy(transport); }
            }).ConfigureAwait(false);
            cancellation.ThrowIfCancellationRequested();
            return peer;
        }
        catch (BcException) { cancellation.ThrowIfCancellationRequested(); return null; }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PeerInfo
    {
        public uint StructSize, AbiVersion, Trusted, Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Version;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)] public byte[] Cipher;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)] public byte[] Subject;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)] public byte[] Issuer;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 65)] public byte[] Sha256;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 21)] public byte[] NotBefore;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 21)] public byte[] NotAfter;
    }
    [DllImport(NativeLibs.KvmNet, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_kvm_transport_peer_info(IntPtr transport, out PeerInfo info);
}

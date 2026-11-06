using System.Collections.Concurrent;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BControl.Core.Native;

namespace BControl.Core.Diagnostics;
public static class StartupAssets
{
    private sealed record Assets(byte[]? Startup, byte[]? Jar);
    private static readonly ConcurrentDictionary<string, Assets> Cache = new(StringComparer.Ordinal);
    [DllImport("bcontrol_client", CallingConvention = CallingConvention.Cdecl)]
    private static extern BcBytes bc_console_client_asset(IntPtr client, uint kind);
    [DllImport("bcontrol_discovery", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_diagnostic_jnlp_redact(byte[] input, uint length, IntPtr output, uint capacity, out uint written);
    internal static void Clear(string origin) => Cache.TryRemove(origin, out _);
    internal static void Capture(IntPtr client, string origin)
    {
        byte[]? Read(uint kind, ulong limit)
        {
            var body = bc_console_client_asset(client, kind);
            if (body.Length == 0 || body.Length > limit)
                return null;
            var data = new byte[(int)body.Length];
            Marshal.Copy(body.Data, data, 0, data.Length);
            return data;
        }

        try
        {
            var startup = Read(1, 65536);
            byte[]? redacted = null;
            if (startup != null && bc_diagnostic_jnlp_redact(startup, (uint)startup.Length, IntPtr.Zero, 0, out var size) == Bc.Ok && size <= 512 * 1024)
            {
                var buffer = Marshal.AllocHGlobal((int)size + 1);
                try
                {
                    if (bc_diagnostic_jnlp_redact(startup, (uint)startup.Length, buffer, size + 1, out size) == Bc.Ok)
                    {
                        redacted = new byte[size];
                        Marshal.Copy(buffer, redacted, 0, (int)size);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            if (Cache.Count >= 8 && !Cache.ContainsKey(origin))
                Cache.TryRemove(Cache.Keys.First(), out _);
            Cache[origin] = new(redacted, Read(2, 16 * 1024 * 1024));
        }
        catch
        {
        }
    }

    public static async Task WriteZipAsync(Stream destination, string origin, bool includeBinary)
    {
        Cache.TryGetValue(origin, out var assets);
        var files = new Dictionary<string, byte[]>
        {
            {
                "diagnostic.log",
                Encoding.UTF8.GetBytes(DiagnosticExport.Anonymize(CoreLog.Read()))
            }
        };
        if (assets?.Startup != null)
            files["startup.redacted.jnlp"] = assets.Startup;
        if (includeBinary && assets?.Jar != null)
            files["JViewer.jar"] = assets.Jar;
        var salt = RandomNumberGenerator.GetBytes(32);
        var fingerprint = Convert.ToHexString(SHA256.HashData(salt.Concat(Encoding.UTF8.GetBytes(origin)).ToArray()));
        var manifest = new
        {
            version = 1,
            coreAbi = Bc.AbiVersion,
            origin = fingerprint,
            binaryAssetsIncluded = includeBinary && assets?.Jar != null,
            assets = files.Select(pair => new { file = pair.Key, size = pair.Value.Length, sha256 = Convert.ToHexString(SHA256.HashData(pair.Value)) }).ToArray()
        };
        files["manifest.json"] = JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions { WriteIndented = true });
        using var zip = new ZipArchive(destination, ZipArchiveMode.Create, leaveOpen: true);
        foreach (var pair in files)
        {
            await using var stream = zip.CreateEntry(pair.Key, CompressionLevel.Optimal).Open();
            await stream.WriteAsync(pair.Value);
        }
    }
}

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using BControl.Core.Native;

namespace BControl.Core.Diagnostics;
public static class DiagnosticExport
{
    private static readonly HashSet<string> SafeFields = new(StringComparer.Ordinal)
    {
        "status",
        "http",
        "http_status",
        "method",
        "phase",
        "kind",
        "bytes",
        "len",
        "length",
        "count",
        "timeout_ms",
        "time_ms",
        "curl_code",
        "width",
        "height",
        "bpp",
        "flags",
        "state",
        "cert_policy",
        "tls_min",
        "tls_max"
    };
    public static string Anonymize(string log)
    {
        var salt = RandomNumberGenerator.GetBytes(32);
        string Hash(string value)
        {
            var text = Encoding.UTF8.GetBytes(value);
            var input = new byte[salt.Length + text.Length];
            salt.CopyTo(input, 0);
            text.CopyTo(input, salt.Length);
            return "<" + Convert.ToHexString(SHA256.HashData(input).AsSpan(0, 8)).ToLowerInvariant() + ">";
        }

        var output = new StringBuilder();
        output.AppendLine($"ShelfView {typeof(DiagnosticExport).Assembly.GetName().Version}; {RuntimeInformation.OSDescription}; ABI {Bc.AbiVersion}; level {CoreLog.Level}");
        foreach (var line in log.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Split('\t', 5);
            if (fields.Length != 5)
            {
                output.AppendLine(Hash(line));
                continue;
            }

            output.AppendJoin('\t', fields.Take(4));
            output.Append('\t');
            var details = fields[4].Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(token =>
            {
                var separator = token.IndexOf('=');
                if (separator < 1)
                    return Hash(token);
                var key = token[..separator];
                var value = token[(separator + 1)..];
                return SafeFields.Contains(key) && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.') ? token : key + "=" + Hash(value);
            });
            output.AppendJoin(' ', details);
            output.AppendLine();
        }

        return output.ToString();
    }
}

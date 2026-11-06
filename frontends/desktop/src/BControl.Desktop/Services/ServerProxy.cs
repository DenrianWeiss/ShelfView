using System.Text.Json.Serialization;
using BControl.Core;
using BControl.Core.Localization;

namespace BControl.Desktop.Services;

public sealed class ServerProxy
{
    private readonly PendingReadCache<(string Reference, string User), CredentialReadResult> _reads = new();
    [JsonPropertyName("host")] public string Host { get; init; } = "";
    [JsonPropertyName("port")] public ushort Port { get; init; } = 1080;
    [JsonPropertyName("username")] public string Username { get; init; } = "";
    [JsonPropertyName("credential_ref")] public string? CredentialRef { get; init; }

    internal async Task<Socks5Connection> ResolveAsync(Func<string, string, CancellationToken, Task<CredentialReadResult>>? read, CancellationToken cancellation)
    {
        if (CredentialRef == null && Username.Length == 0)
            return new Socks5Connection(Host, Port);
        if (string.IsNullOrEmpty(CredentialRef) || Username.Length == 0 || read == null)
            throw new InvalidOperationException(Loc.T("proxy.credentialUnavailable"));
        var result = await _reads.ReadAsync((CredentialRef, Username), token => read(CredentialRef, Username, token), cancellation).ConfigureAwait(false);
        if (result.Credential is not { } credential)
            throw new InvalidOperationException(Loc.T("proxy.credentialUnavailable"));
        return new Socks5Connection(Host, Port, credential.Username, credential.Password);
    }
}

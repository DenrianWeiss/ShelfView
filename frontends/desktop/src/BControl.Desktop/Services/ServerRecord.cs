using System.Text.Json.Serialization;

namespace BControl.Desktop.Services;
public sealed class ServerCapabilities
{
    [JsonPropertyName("redfish")]
    public bool Redfish { get; set; }

    [JsonPropertyName("ipmi")]
    public bool Ipmi { get; set; }

    [JsonPropertyName("graphical_console")]
    public bool? GraphicalConsole { get; set; }

    [JsonPropertyName("kvm")]
    public bool Kvm { get; set; }

    [JsonPropertyName("sol")]
    public bool Sol { get; set; }

    [JsonPropertyName("media_redfish")]
    public bool MediaRedfish { get; set; }
}

public sealed class CachedOverview
{
    [JsonPropertyName("observed_at")]
    public DateTimeOffset ObservedAt { get; set; }

    [JsonPropertyName("expired")]
    public bool Expired { get; set; }

    [JsonPropertyName("power_state")]
    public uint PowerState { get; set; }

    [JsonPropertyName("raw_power_state")]
    public string RawPowerState { get; set; } = "";

    [JsonPropertyName("manufacturer")]
    public string Manufacturer { get; set; } = "";

    [JsonPropertyName("model")]
    public string Model { get; set; } = "";

    [JsonPropertyName("system_name")]
    public string SystemName { get; set; } = "";

    [JsonPropertyName("cpu_name")]
    public string? CpuName { get; set; }

    [JsonPropertyName("cpu_celsius")]
    public double? CpuCelsius { get; set; }

    [JsonPropertyName("primary_temperature")]
    public BControl.Core.Redfish.TemperaturePoint? PrimaryTemperature { get; set; }

    [JsonPropertyName("normal_celsius")]
    public double? NormalCelsius { get; set; }

    [JsonPropertyName("alert_celsius")]
    public double? AlertCelsius { get; set; }

    [JsonPropertyName("temperature_status")]
    public uint TemperatureStatus { get; set; }

    [JsonPropertyName("logout_status")]
    public uint LogoutStatus { get; set; }
}

public sealed class ServerRecord
{
    [JsonIgnore]
    public BControl.Core.Kvm.ConsoleHttpConnection ConsoleHttpConnection { get; set; }
    [JsonIgnore]
    public BControl.Core.Kvm.ConsoleProtocolChoice? ConsoleProtocol { get; set; }

    [JsonPropertyName("timeout_seconds")]
    public BControl.Core.HostTimeout? Timeout { get; set; }

    [JsonPropertyName("proxy")]
    public ServerProxy? Proxy { get; set; }

    [JsonIgnore]
    public Func<string, string, CancellationToken, Task<CredentialReadResult>>? ReadProxyCredential { get; set; }

    public async Task<BControl.Core.Socks5Connection?> ResolveProxyAsync(CancellationToken cancellation = default)
    {
        var proxy = Proxy;
        return proxy == null ? null : await proxy.ResolveAsync(ReadProxyCredential, cancellation).ConfigureAwait(false);
    }

    [JsonPropertyName("server_id")]
    public string ServerId { get; set; } = "";

    [JsonPropertyName("endpoint_id")]
    public string EndpointId { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("address")]
    public string Address { get; set; } = "";

    [JsonPropertyName("protocol")]
    public uint Protocol { get; set; }

    [JsonIgnore]
    public Func<uint, CancellationToken, Task<bool>>? ConfirmPrivate { get; set; }

    [JsonPropertyName("system_uri")]
    public string SystemUri { get; set; } = "";

    [JsonPropertyName("username")]
    public string Username { get; set; } = "";

    [JsonPropertyName("credential_ref")]
    public string CredentialRef { get; set; } = "";

    [JsonPropertyName("verified")]
    public bool Verified { get; set; }

    [JsonPropertyName("verification_error")]
    public string? VerificationError { get; set; }

    [JsonPropertyName("verification_error_key")]
    public string? VerificationErrorKey { get; set; }

    [JsonPropertyName("capabilities")]
    public ServerCapabilities Capabilities { get; set; } = new();

    [JsonPropertyName("ca_file")]
    public string? CaFile { get; set; }

    [JsonPropertyName("tls_min")]
    public uint MinimumTls { get; set; } = 12;

    [JsonPropertyName("cert_policy")]
    public uint CertPolicy { get; set; }

    [JsonPropertyName("suite3_confirmed")]
    public bool Suite3Confirmed { get; set; }

    [JsonPropertyName("session_unconfirmed")]
    public bool SessionUnconfirmed { get; set; }

    [JsonPropertyName("last_overview")]
    public CachedOverview? LastOverview { get; set; }
}

public sealed class InventoryFile
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("servers")]
    public List<ServerRecord> Servers { get; set; } = new();
}

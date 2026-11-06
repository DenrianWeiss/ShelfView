using System.Text.Json;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Redfish;
public sealed record ManagementSwitch(string Name, string Uri, string? Attribute, bool Enabled);
public static class ManagementSwitches
{
    public static bool? Read(JsonElement json, string? attribute)
    {
        JsonElement value;
        if (attribute != null)
        {
            if (!json.TryGetProperty("@odata.type", out var type) || !type.GetString()!.StartsWith("#DellAttributes.", StringComparison.Ordinal))
                return null;
            if (!json.TryGetProperty("Attributes", out var attributes) || !attributes.TryGetProperty(attribute, out value) || value.ValueKind != JsonValueKind.String)
                return null;
            return value.GetString()?.ToLowerInvariant() switch
            {
                "enabled" or "true" or "1" => true,
                "disabled" or "false" or "0" => false,
                _ => null
            };
        }

        if (!json.TryGetProperty("IPMI", out var ipmi) || !ipmi.TryGetProperty("ProtocolEnabled", out value))
            return null;
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    public static byte[] Patch(ManagementSwitch item, bool enabled) => item.Attribute != null ? JsonSerializer.SerializeToUtf8Bytes(new { Attributes = new Dictionary<string, string> { { item.Attribute, enabled ? "Enabled" : "Disabled" } } }) : JsonSerializer.SerializeToUtf8Bytes(new { IPMI = new { ProtocolEnabled = enabled } });
    public static Task<string> ApplyAsync(string address, DeviceCredential credential, string ca, uint policy, ManagementSwitch item, bool enabled, CancellationToken cancellation, uint tlsMin = 12, Socks5Connection? proxy = null) => DiscoveryService.RunSessionAsync(address, credential, ca, policy, cancellation, 15000, null, async (session, remaining, ct) =>
    {
        uint Timeout()
        {
            ct.ThrowIfCancellationRequested();
            var value = remaining(null);
            if (value == 0)
                throw new BcException(Bc.Timeout, Bc.StatusText(Bc.Timeout));
            return Math.Min(value, 5000);
        }

        var before = Read(await session.GetResourceAsync(item.Uri, Timeout(), ct), item.Attribute);
        if (before == null)
            throw new BcException(Bc.Unsupported, Loc.T("manage.redfish.switchUnsupported"));
        if (before == enabled)
            return Loc.T("manage.redfish.switchVerified");
        var flags = await session.PatchResourceAsync(item.Uri, Patch(item, enabled), Timeout(), ct);
        try
        {
            var readback = Read(await session.GetResourceAsync(item.Uri, Timeout(), ct), item.Attribute);
            return readback == enabled ? Loc.T("manage.redfish.switchVerified") : readback.HasValue ? Loc.F("manage.redfish.switchRejected", ("value", Loc.T(readback.Value ? "manage.redfish.enabled" : "manage.redfish.disabled"))) : Loc.T("manage.redfish.switchPending");
        }
        catch (Exception ex)
        {
            return Loc.F("manage.redfish.switchReadBackFailed", ("detail", ex.Message));
        }
    }, tlsMin, proxy);
}

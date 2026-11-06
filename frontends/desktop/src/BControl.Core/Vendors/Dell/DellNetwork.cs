using System.Text.Json;
using BControl.Core.Localization;
using BControl.Core.Redfish;

namespace BControl.Core.Vendors.Dell;
internal static class DellNetwork
{
    public static bool Advertised(JsonElement manager) => manager.TryGetProperty("Oem", out var oem) && oem.ValueKind == JsonValueKind.Object && oem.TryGetProperty("Dell", out _);
    public static string AttributesUri(string manager) => manager + "/Oem/Dell/DellAttributes/" + manager.Split('/').Last();
    public static IReadOnlyList<ManagementSwitch> Switches(JsonElement resource, string uri)
    {
        var values = new List<ManagementSwitch>();
        foreach (var(attribute, key)in new[]
        {
            ("IPMILan.1.Enable", "manage.redfish.ipmi"),
            ("IPMISOL.1.Enable", "manage.redfish.sol")
        }

        )
            if (ManagementSwitches.Read(resource, attribute)is { } enabled)
                values.Add(new(Loc.T(key), uri, attribute, enabled));
        return values;
    }
}

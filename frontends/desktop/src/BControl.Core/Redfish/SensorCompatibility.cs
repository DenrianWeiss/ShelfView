using System.Text.Json;
using System.Text.Json.Nodes;

namespace BControl.Core.Redfish;
internal static class SensorCompatibility
{
    private static JsonElement Normalize(JsonElement root, out string[] links)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(root);
        var pin = System.Runtime.InteropServices.GCHandle.Alloc(bytes, System.Runtime.InteropServices.GCHandleType.Pinned);
        IntPtr view = IntPtr.Zero;
        try {
            Native.Bc.Check(Create(new Native.BcBytes { Data = pin.AddrOfPinnedObject(), Length = (ulong)bytes.Length }, out view), "core.readSensors");
            links = Enumerable.Range(1, 2).Select(kind => {
                var value = Link(view, (uint)kind);
                return value.Length == 0 ? "" : System.Runtime.InteropServices.Marshal.PtrToStringUTF8(value.Data, (int)value.Length)!;
            }).Where(value => value.Length != 0).ToArray();
            var data = Body(view); var copy = new byte[(int)data.Length];
            System.Runtime.InteropServices.Marshal.Copy(data.Data, copy, 0, copy.Length);
            using var document = JsonDocument.Parse(copy); return document.RootElement.Clone();
        }
        finally { Destroy(view); pin.Free(); }
    }
    public static IEnumerable<string> Links(JsonElement chassis) { Normalize(chassis, out var links); return links; }
    [System.Runtime.InteropServices.DllImport("bcontrol_redfish", EntryPoint = "bc_sensor_compat_create")]
    private static extern uint Create(Native.BcBytes body, out IntPtr view);
    [System.Runtime.InteropServices.DllImport("bcontrol_redfish", EntryPoint = "bc_sensor_compat_json")]
    private static extern Native.BcBytes Body(IntPtr view);
    [System.Runtime.InteropServices.DllImport("bcontrol_redfish", EntryPoint = "bc_sensor_compat_link")]
    private static extern Native.BcString Link(IntPtr view, uint kind);
    [System.Runtime.InteropServices.DllImport("bcontrol_redfish", EntryPoint = "bc_sensor_compat_destroy")]
    private static extern void Destroy(IntPtr view);
    public static IEnumerable<JsonElement> Map(JsonElement root, HashSet<int> known, bool hasPower, IReadOnlyList<string>? fans = null)
    {
        root = Normalize(root, out _);
        if (!root.TryGetProperty("Sensors", out var array) || array.ValueKind != JsonValueKind.Array)
            yield break;
        foreach (var sensor in array.EnumerateArray())
        {
            if (sensor.TryGetProperty("SensorNumber", out var id) && id.ValueKind == JsonValueKind.Number && id.TryGetInt32(out var number) && !known.Add(number))
                continue;
            var item = JsonNode.Parse(sensor.GetRawText())!.AsObject();
            var unit = item["ReadingUnits"]?.GetValue<string>();
            if (unit == "W" && hasPower)
                continue;
            var name = Normalize(item["Name"]?.GetValue<string>() ?? "");
            if (unit == "RPM" && fans?.Any(f => name.StartsWith(Normalize(f), StringComparison.Ordinal) || Normalize(f).StartsWith(name, StringComparison.Ordinal)) == true)
                continue;
            yield return JsonSerializer.SerializeToElement(item);
        }
    }

    [System.Runtime.InteropServices.DllImport("bcontrol_redfish", EntryPoint = "bc_redfish_logout_response_succeeded")]
    private static extern int LogoutSuccess(uint http, Native.BcBytes body);
    internal static bool AcceptsLogout(uint http, Native.BcBytes body) => LogoutSuccess(http, body) != 0;

    private static string Normalize(string name) => new(name.ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
}

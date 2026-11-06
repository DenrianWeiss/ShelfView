using System.Text.Json;
using BControl.Core.Native;
using BControl.Core.Redfish;
namespace BControl.Core.Redfish;

internal static class LegacySensors
{
    internal static readonly string[] ReadingFields =
        ["Reading", "ReadingCelsius", "ReadingVolts", "PowerConsumedWatts", "LastPowerOutputWatts", "PowerOutputWatts", "PowerInputWatts"];

    internal static string? ReadingKey(string name, string units)
    {
        name = name.Trim().ToLowerInvariant();
        units = units.Trim().ToLowerInvariant();
        if (name.Length == 0 || units.Length == 0) return null;
        return name + "\0" + (units is "c" or "°c" or "celsius" ? "cel" : units);
    }

    internal static string? ReadingUnits(JsonElement sensor)
    {
        if (sensor.TryGetProperty("ReadingUnits", out var units) && units.ValueKind == JsonValueKind.String)
            return units.GetString();
        if (sensor.TryGetProperty("ReadingCelsius", out _)) return "Cel";
        if (sensor.TryGetProperty("ReadingVolts", out _)) return "V";
        return ReadingFields.Skip(3).Any(key => sensor.TryGetProperty(key, out _)) ? "W" : null;
    }

    internal static bool HasReading(JsonElement sensor) =>
        ReadingFields.Any(key => sensor.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Number);

    internal static string? Link(JsonElement chassis, string relation)
    {
        if (!chassis.TryGetProperty(relation, out var link) || link.ValueKind == JsonValueKind.Null) return null;
        if (link.ValueKind != JsonValueKind.Object || !link.TryGetProperty("@odata.id", out var id) || id.ValueKind != JsonValueKind.String)
            throw new BcException(Bc.ProtocolError, "Invalid sensor relationship");
        var uri = id.GetString()!;
        if (!uri.StartsWith("/redfish/v1/", StringComparison.Ordinal) || uri.Length > 8192 || uri.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)) || uri.Contains('#'))
            throw new BcException(Bc.ProtocolError, "Invalid sensor relationship");
        return uri;
    }
    internal static bool Advertised(JsonElement chassis) => Link(chassis, "Thermal") != null || Link(chassis, "Power") != null || SensorCompatibility.Links(chassis).Any();
    internal static async Task<IReadOnlyList<RedfishSession.SensorReadingInfo>> TemperaturesAsync(JsonElement chassis, Func<string, Task<JsonElement>> read)
    {
        var result = new List<RedfishSession.SensorReadingInfo>();
        var known = new HashSet<int>();
        void Add(JsonElement item, string uri, string readingKey, string unit)
        {
            if (item.ValueKind != JsonValueKind.Object) return;
            if (!item.TryGetProperty(readingKey, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetDouble(out var reading) || !double.IsFinite(reading))
                return;
            if (item.TryGetProperty("SensorNumber", out var id) && id.ValueKind == JsonValueKind.Number && id.TryGetInt32(out var number))
                known.Add(number);
            string Text(string key) => item.TryGetProperty(key, out var text) && text.ValueKind == JsonValueKind.String ? text.GetString() ?? "" : "";
            var health = "";
            var state = "";
            if (item.TryGetProperty("Status", out var status) && status.ValueKind == JsonValueKind.Object)
            {
                health = status.TryGetProperty("Health", out var h) ? h.GetString() ?? "" : "";
                state = status.TryGetProperty("State", out var st) ? st.GetString() ?? "" : "";
            }

            uint flags = 1u | (state == "Enabled" ? 2u : 0u) | (health == "OK" ? 4u : health is "Warning" or "Critical" ? 8u : 0u);
            if (Text("PhysicalContext") == "CPU") flags |= 16u;
            if (item.TryGetProperty("MinReadingRangeTemp", out var minimum) && minimum.ValueKind == JsonValueKind.Number && minimum.TryGetDouble(out var min) && reading < min) return;
            if (item.TryGetProperty("MaxReadingRangeTemp", out var maximum) && maximum.ValueKind == JsonValueKind.Number && maximum.TryGetDouble(out var max) && reading > max) return;
            var related = item.TryGetProperty("RelatedItem", out var links) && links.ValueKind == JsonValueKind.Array
                ? links.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.Object && x.TryGetProperty("@odata.id", out var id) && id.ValueKind == JsonValueKind.String)
                    .Select(x => x.GetProperty("@odata.id").GetString()!).ToArray() : [];
            var sensorUri = Text("@odata.id");
            if (sensorUri.Length == 0) sensorUri = $"{uri}#/Temperatures/{result.Count}";
            result.Add(new(sensorUri, Text("Name"), unit, 1, health, state, "", reading, reading, flags, Text("PhysicalContext"), related, 0));
        }

        if (Link(chassis, "Thermal") is { } path)
        {
            var root = await read(path);
            if (root.TryGetProperty("Temperatures", out var malformed) && malformed.ValueKind != JsonValueKind.Array)
                throw new BcException(Bc.ProtocolError, "Invalid temperature collection");
            if (root.TryGetProperty("Temperatures", out var array) && array.ValueKind == JsonValueKind.Array)
                foreach (var item in array.EnumerateArray().Take(512))
                    Add(item, path, "ReadingCelsius", "Cel");
        }

        foreach (var oemPath in SensorCompatibility.Links(chassis))
        {
            var root = await read(oemPath);
            foreach (var item in SensorCompatibility.Map(root, known, false))
                if (item.TryGetProperty("ReadingUnits", out var units) && units.GetString() == "Cel")
                    Add(item, oemPath, "Reading", "Cel");
        }

        return result;
    }
}

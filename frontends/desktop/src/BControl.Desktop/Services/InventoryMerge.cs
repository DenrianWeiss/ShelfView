using System.Text.Json;
using BControl.Core.Inventory;
using BControl.Core.Localization;

namespace BControl.Desktop.Services;
public static class InventoryMerge
{
    public static List<ServerRecord> Apply(IReadOnlyList<ServerRecord> current, IReadOnlyList<InventoryEntry> entries, bool updateNames)
    {
        var merged = JsonSerializer.Deserialize<List<ServerRecord>>(JsonSerializer.Serialize(current))!;
        foreach (var entry in entries)
        {
            var duplicate = merged.FirstOrDefault(r => r.Address == entry.Address && r.SystemUri == entry.SystemUri);
            if (duplicate != null)
            {
                if (updateNames)
                    duplicate.Name = entry.Name;
                continue;
            }

            if (merged.Count >= 1000)
                throw new InvalidDataException(Loc.T("import.limit"));
            merged.Add(new ServerRecord { ServerId = Guid.NewGuid().ToString("N"), EndpointId = merged.FirstOrDefault(r => r.Address == entry.Address)?.EndpointId ?? Guid.NewGuid().ToString("N"), Name = entry.Name, Address = entry.Address, Username = entry.Username, Protocol = entry.Protocol, SystemUri = entry.SystemUri, });
        }

        return merged;
    }
}

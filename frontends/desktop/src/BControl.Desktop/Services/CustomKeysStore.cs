using System.Text.Json;
using BControl.Core.Input;

namespace BControl.Desktop.Services;
public sealed class CustomKeysStore
{
    private readonly string _path;
    public List<KeyCombination> Items { get; private set; } = [];

    public CustomKeysStore(bool sol)
    {
        _path = Path.Combine(Path.GetDirectoryName(ServerStore.DefaultPath())!, sol ? "sol-keys.json" : "kvm-keys.json");
        try
        {
            if (File.Exists(_path) && new FileInfo(_path).Length <= 16384)
            {
                var items = JsonSerializer.Deserialize<List<KeyCombination>>(File.ReadAllBytes(_path));
                if (items != null && items.Count <= 12 && items.All(Valid))
                    Items = items;
            }
        }
        catch
        {
        }
    }

    private static bool Valid(KeyCombination item) => item.Name.Length <= 48 && RemoteKeys.Order(item.Keys) != null;
    public void Save(IEnumerable<KeyCombination> items)
    {
        var next = items.ToList();
        if (next.Count > 12 || !next.All(Valid))
            throw new InvalidDataException();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(next);
        if (bytes.Length > 16384)
            throw new InvalidDataException();
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);
            File.Move(temporary, _path, true);
            Items = next;
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}

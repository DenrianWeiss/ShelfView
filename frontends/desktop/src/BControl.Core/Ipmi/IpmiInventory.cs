using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Ipmi;
public sealed record ManagementField(string Label, string Value);
public sealed record ManagementItem(string Name, IReadOnlyList<ManagementField> Fields);
public sealed record ManagementSnapshot(IReadOnlyList<ManagementItem> Items, uint Status = Bc.Ok, bool Truncated = false, string Summary = "")
{
    public IReadOnlyList<Redfish.ManagementSwitch> Switches { get; init; } = Array.Empty<Redfish.ManagementSwitch>();
    public uint LogoutStatus { get; init; }
}

public sealed partial class IpmiConnection
{
    private static string Text(byte[] value)
    {
        var length = Array.IndexOf(value, (byte)0);
        return Encoding.UTF8.GetString(value, 0, length < 0 ? value.Length : length);
    }

    private static ManagementField Field(string key, string value) => new(Loc.T(key), value);
    private static ManagementField FruField(string key, BcIpmiFruField field) => Field(key, field.Status == Bc.Ok ? Text(field.Text) : Bc.StatusText(field.Status));
    public Task<ManagementSnapshot> GetSelAsync(CancellationToken cancellation = default) => EnqueueWork(() =>
    {
        cancellation.ThrowIfCancellationRequested();
        var log = new BcIpmiSelLog
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiSelLog>(),
            AbiVersion = Bc.AbiVersion
        };
        var status = IpmiInventoryNative.bc_ipmi_sel_log_get(_session, ref log);
        if (log.Count == 0 && status != Bc.Ok)
            Bc.Check(status, "manage.ipmi.tab.sel");
        var items = log.Entries.Take((int)Math.Min(log.Count, 128)).Select(e => new ManagementItem($"0x{e.RecordId:X4}", new[] { Field("manage.sel.timestamp", (e.Flags & 1) != 0 ? new DateTimeOffset(1995, 1, 1, 0, 0, 0, TimeSpan.Zero).AddMinutes(e.Timestamp).ToLocalTime().ToString("g") : Loc.T("common.unknown")), Field("manage.sel.raw", Convert.ToHexString(e.Raw.AsSpan(0, Math.Min(e.RawLength, (byte)16)))), Field("sensor.state", Bc.StatusText(e.Status)), })).ToList();
        return new ManagementSnapshot(items, status, (log.Flags & 1) != 0, Loc.F("manage.ipmi.selSummary", ("used", log.Info.RecordCount), ("free", log.Info.FreeSpace)) + (log.Info.Overflow != 0 ? " " + Loc.T("manage.ipmi.selOverflow") : ""));
    });
    public Task<(string Manufacturer, string Model)> GetIdentityAsync(CancellationToken cancellation = default) => EnqueueWork(() =>
    {
        cancellation.ThrowIfCancellationRequested();
        var info = new BcIpmiFruInfo
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiFruInfo>(),
            AbiVersion = Bc.AbiVersion
        };
        var status = IpmiInventoryNative.bc_ipmi_fru_info_get(_session, 0, ref info);
        if (status != Bc.Ok && info.Product.Present == 0 && info.Board.Present == 0)
            Bc.Check(status, "manage.ipmi.tab.fru");
        string Value(BcIpmiFruField field) => field.Status == Bc.Ok ? Text(field.Text) : "";
        var manufacturer = info.Product.Present != 0 ? Value(info.Product.Manufacturer) : "";
        var model = info.Product.Present != 0 ? Value(info.Product.Name) : "";
        if (info.Board.Present != 0)
        {
            if (manufacturer.Length == 0)
                manufacturer = Value(info.Board.Manufacturer);
            if (model.Length == 0)
                model = Value(info.Board.Product);
        }

        return (manufacturer, model);
    });
    public Task<ManagementSnapshot> GetFruAsync(CancellationToken cancellation = default) => EnqueueWork(() =>
    {
        var inventory = new BcIpmiFruInventory
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiFruInventory>(),
            AbiVersion = Bc.AbiVersion
        };
        var status = IpmiInventoryNative.bc_ipmi_fru_inventory_get(_session, ref inventory);
        if (inventory.Count == 0 && status != Bc.Ok)
            Bc.Check(status, "manage.ipmi.tab.fru");
        var items = new List<ManagementItem>();
        for (byte id = 0; id < Math.Min(inventory.Count, 16); id++)
        {
            cancellation.ThrowIfCancellationRequested();
            var info = new BcIpmiFruInfo
            {
                StructSize = (uint)Marshal.SizeOf<BcIpmiFruInfo>(),
                AbiVersion = Bc.AbiVersion
            };
            var current = IpmiInventoryNative.bc_ipmi_fru_info_get(_session, id, ref info);
            if (status == Bc.Ok && current != Bc.Ok)
                status = current;
            var fields = new List<ManagementField>();
            if (info.Product.Present != 0)
            {
                fields.Add(FruField("manage.ipmi.fru.manufacturer", info.Product.Manufacturer));
                fields.Add(FruField("manage.ipmi.fru.name", info.Product.Name));
                fields.Add(FruField("manage.ipmi.fru.partNumber", info.Product.PartNumber));
                fields.Add(FruField("manage.ipmi.fru.version", info.Product.Version));
                fields.Add(FruField("manage.ipmi.fru.serial", info.Product.Serial));
                fields.Add(FruField("manage.ipmi.fru.assetTag", info.Product.AssetTag));
            }

            if (info.Board.Present != 0)
            {
                fields.Add(FruField("manage.ipmi.fru.board", info.Board.Product));
                fields.Add(FruField("manage.ipmi.fru.manufacturer", info.Board.Manufacturer));
                fields.Add(FruField("manage.ipmi.fru.partNumber", info.Board.PartNumber));
                fields.Add(FruField("manage.ipmi.fru.serial", info.Board.Serial));
                if (info.Board.MfgDate != 0)
                    fields.Add(Field("manage.ipmi.fru.date", new DateTimeOffset(1996, 1, 1, 0, 0, 0, TimeSpan.Zero).AddMinutes(info.Board.MfgDate).ToString("u")));
            }

            if (info.Chassis.Present != 0)
            {
                fields.Add(FruField("manage.ipmi.fru.partNumber", info.Chassis.PartNumber));
                fields.Add(FruField("manage.ipmi.fru.serial", info.Chassis.SerialNumber));
            }

            if (current != Bc.Ok)
                fields.Add(Field("sensor.state", Bc.StatusText(current)));
            items.Add(new(Loc.F("manage.ipmi.fruDevice", ("id", id)), fields));
        }

        return new ManagementSnapshot(items, status, (inventory.Flags & 1) != 0);
    });
    public Task<ManagementSnapshot> GetNetworkAsync(CancellationToken cancellation = default) => EnqueueWork(() =>
    {
        cancellation.ThrowIfCancellationRequested();
        var config = new BcIpmiLanConfig
        {
            StructSize = (uint)Marshal.SizeOf<BcIpmiLanConfig>(),
            AbiVersion = Bc.AbiVersion
        };
        var status = IpmiInventoryNative.bc_ipmi_lan_config_scan(_session, ref config);
        var items = new List<ManagementItem>();
        foreach (var channel in config.Channels.Take(Math.Min((int)config.ChannelCount, 14)))
        {
            cancellation.ThrowIfCancellationRequested();
            if (channel.IsLan == 0)
                continue;
            var fields = new List<ManagementField>();
            foreach (var(selector, key)in new[]
            {
                (3, "manage.ipmi.lan.ipAddress"),
                (4, "manage.ipmi.lan.ipSource"),
                (5, "manage.ipmi.lan.mac"),
                (6, "manage.ipmi.lan.subnet"),
                (8, "manage.ipmi.lan.port"),
                (12, "manage.ipmi.lan.gateway"),
                (20, "manage.ipmi.lan.vlan"),
                (23, "manage.ipmi.lan.cipherSuites")
            }

            )
            {
                var parameter = channel.Parameters[selector];
                var data = parameter.Data.AsSpan(0, (int)Math.Min(parameter.DataLength, 32));
                string value;
                if (parameter.Status != Bc.Ok)
                    value = Bc.StatusText(parameter.Status);
                else if (selector is 3 or 6 or 12 && data.Length >= 4)
                    value = new System.Net.IPAddress(data[..4]).ToString();
                else if (selector == 5 && data.Length >= 6)
                    value = string.Join(":", data[..6].ToArray().Select(b => b.ToString("X2")));
                else if (selector == 4 && data.Length > 0)
                    value = Loc.T("manage.ipmi.ipSource." + (data[0] switch
                    {
                        1 => "static",
                        2 => "dhcp",
                        3 => "bios",
                        4 => "other",
                        _ => "unknown"
                    }));
                else if (selector == 8 && data.Length >= 2)
                    value = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(data).ToString();
                else if (selector == 20 && data.Length >= 2)
                    value = (data[1] & 0x80) != 0 ? (System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(data) & 0xFFF).ToString() : Loc.T("manage.redfish.disabled");
                else
                    value = Convert.ToHexString(data);
                fields.Add(Field(key, value));
            }

            items.Add(new(Loc.F("manage.ipmi.lan.channel", ("channel", channel.Channel)), fields));
        }

        return new ManagementSnapshot(items, status);
    });
}

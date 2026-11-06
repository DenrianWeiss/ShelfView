using System.Text;
using BControl.Core.Inventory;

namespace BControl.Core.Tests;

public sealed class InventoryParserTests
{
    [Fact]
    public void ParseJson_ValidEntries()
    {
        var json = """{"version":1,"servers":[{"name":"rack-a-01","address":"https://bmc.example","username":"operator","protocol":"auto"}]}""";
        var result = InventoryParser.Parse(Encoding.UTF8.GetBytes(json), InventoryParser.FormatJson);
        var entry = Assert.Single(result.Entries);
        Assert.Equal("rack-a-01", entry.Name);
        Assert.Equal("https://bmc.example", entry.Address);
        Assert.Equal("operator", entry.Username);
    }

    [Fact]
    public void ParseCsv_ValidEntries()
    {
        var csv = "name,address,username,protocol\nrack-2,https://bmc2,op,redfish\n";
        var result = InventoryParser.Parse(Encoding.UTF8.GetBytes(csv), InventoryParser.FormatCsv);
        var entry = Assert.Single(result.Entries);
        Assert.Equal("rack-2", entry.Name);
        Assert.Equal(1u, entry.Protocol);
    }

    [Fact]
    public void ParseJson_RejectsBadVersion_WithPositionButNoSecretEcho()
    {
        var json = """{"version":99,"servers":[]}""";
        var ex = Assert.Throws<InventoryParseException>(() =>
            InventoryParser.Parse(Encoding.UTF8.GetBytes(json), InventoryParser.FormatJson));
        Assert.Equal(2u, ex.Code); // BC_INVENTORY_ERROR_VERSION
        Assert.DoesNotContain("99", ex.Message);
    }

    [Fact]
    public void ParseJson_RejectsPasswordField()
    {
        var json = """{"version":1,"servers":[{"address":"https://bmc","password":"x"}]}""";
        Assert.Throws<InventoryParseException>(() =>
            InventoryParser.Parse(Encoding.UTF8.GetBytes(json), InventoryParser.FormatJson));
    }

    [Fact]
    public void ParseCsv_Duplicates_ReportedNotResolved()
    {
        var csv = "address,system_uri\nhttps://bmc,/redfish/v1/Systems/1\nhttps://bmc,/redfish/v1/Systems/1\n";
        var result = InventoryParser.Parse(Encoding.UTF8.GetBytes(csv), InventoryParser.FormatCsv);
        Assert.Equal(2, result.Entries.Count);
        Assert.Equal(uint.MaxValue, result.Entries[0].DuplicateOf);
        Assert.Equal(0u, result.Entries[1].DuplicateOf);
    }
}

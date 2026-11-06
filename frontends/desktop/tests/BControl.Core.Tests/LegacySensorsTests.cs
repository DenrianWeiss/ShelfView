using System.Text.Json;
using BControl.Core.Redfish;
using BControl.Core.Native;
namespace BControl.Core.Tests;

public sealed class LegacySensorsTests
{
    [Fact]
    public async Task GenericThermalDiscoveryPreservesEmptyAndUnavailableReadings()
    {
        using var chassis = JsonDocument.Parse("""{"Thermal":{"@odata.id":"/redfish/v1/Chassis/A/Thermal"}}""");
        using var thermal = JsonDocument.Parse("""{"Temperatures":[{"Name":"Missing","ReadingCelsius":null},{"Name":"Disabled","ReadingCelsius":20,"Status":{"State":"Disabled"}},{"Name":"CPU0","ReadingCelsius":39,"PhysicalContext":"Intake","Status":{"State":"Enabled","Health":"OK"}}]}""");
        Assert.True(LegacySensors.Advertised(chassis.RootElement));
        var values = await LegacySensors.TemperaturesAsync(chassis.RootElement, _ => Task.FromResult(thermal.RootElement));
        Assert.Equal(2, values.Count);
        Assert.Equal(0u, values[0].TemperatureFlags & 2u);
        Assert.Equal(39, values[1].Reading);
        Assert.Equal(0u, values[1].TemperatureFlags & 16u);
        Assert.NotEqual(values[0].Uri, values[1].Uri);
        using var empty = JsonDocument.Parse("""{"Temperatures":[]}""");
        Assert.Empty(await LegacySensors.TemperaturesAsync(chassis.RootElement, _ => Task.FromResult(empty.RootElement)));
    }
    [Fact]
    public async Task FetchFailureAndInvalidLinksStayErrors()
    {
        using var chassis = JsonDocument.Parse("""{"Thermal":{"@odata.id":"/redfish/v1/Chassis/A/Thermal"}}""");
        await Assert.ThrowsAsync<IOException>(() => LegacySensors.TemperaturesAsync(chassis.RootElement, _ => throw new IOException("offline")));
        using var external = JsonDocument.Parse("""{"Thermal":{"@odata.id":"https://other.invalid/Thermal"}}""");
        Assert.Throws<BcException>(() => LegacySensors.Advertised(external.RootElement));
    }
}

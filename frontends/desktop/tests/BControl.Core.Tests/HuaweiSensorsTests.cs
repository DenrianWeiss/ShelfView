using System.Text.Json;
using BControl.Core.Redfish;

namespace BControl.Core.Tests;

public sealed class HuaweiSensorsTests
{
    [Fact]
    public async Task MissingTemperatureReadingsStayAbsent()
    {
        using var chassis = JsonDocument.Parse("""{"Oem":{"Huawei":{}},"Thermal":{"@odata.id":"/redfish/v1/Chassis/1/Thermal"}}""");
        using var thermal = JsonDocument.Parse("""{"Temperatures":[{"Name":"Unavailable","ReadingCelsius":null,"SensorNumber":null},{"Name":"Inlet","ReadingCelsius":22,"Status":{"Health":"OK","State":"Enabled"}}]}""");
        var readings = await BControl.Core.Redfish.LegacySensors.TemperaturesAsync(chassis.RootElement, _ => Task.FromResult(thermal.RootElement));
        Assert.Single(readings);
        Assert.Equal(22, readings[0].Reading);
        using var oem = JsonDocument.Parse("""{"Sensors":[{"SensorId":null,"Name":"Unavailable","Unit":"degrees C","ReadingValue":null}]}""");
        Assert.Single(SensorCompatibility.Map(oem.RootElement, new(), false));
    }
}

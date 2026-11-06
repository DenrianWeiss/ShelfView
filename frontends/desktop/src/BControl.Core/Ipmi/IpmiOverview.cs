using System.Runtime.InteropServices;
using BControl.Core.Native;
using BControl.Core.Redfish;

namespace BControl.Core.Ipmi;
public static class IpmiOverview
{
    public static TemperatureSummary Summarize(IReadOnlyList<IpmiSensor> sensors)
    {
        var usable = sensors.Where(s => s.Type == 1 && s.Reading.HasValue && s.Units is "Cel" or "[degF]" or "K").ToArray();
        var readings = usable.Select(s => new BcTemperatureReading { Value = s.Reading!.Value, Unit = s.Units switch
        {
            "Cel" => 1u,
            "[degF]" => 2u,
            _ => 3u
        }, Flags = 3u | (s.Health == 1 ? 4u : s.Health >= 2 ? 8u : 0u) | NativeMethods.bc_temperature_ipmi_role(s.EntityId), }).ToArray();
        var summary = new BcTemperatureSummary
        {
            StructSize = (uint)Marshal.SizeOf<BcTemperatureSummary>()
        };
        Bc.Check(NativeMethods.bc_temperature_summarize(readings, (uint)readings.Length, ref summary), "manage.ipmi.tab.sensors");
        TemperaturePoint? Point(uint index, double celsius) => index < usable.Length ? new("", usable[index].Name, usable[index].Units, usable[index].Reading!.Value, celsius, "", null, false) : null;
        return new(Point(summary.CpuIndex, summary.CpuCelsius), Point(summary.NormalIndex, summary.NormalCelsius), Point(summary.AlertIndex, summary.AlertCelsius))
        { Primary = TemperatureSummary.Select(readings, Point) };
    }
}

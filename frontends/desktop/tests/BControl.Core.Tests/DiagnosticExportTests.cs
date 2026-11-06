using BControl.Core.Diagnostics;

namespace BControl.Core.Tests;
public sealed class DiagnosticExportTests
{
    [Fact]
    public void ExportsCorrelateValuesOnlyWithinOneSaltedExport()
    {
        const string source = "now\t3\t2\thttp.done\tstatus=ok http=200 host=bmc.example user=alice path=/redfish/v1/Systems/secret token=fixture-token-value host=bmc.example\n";
        var first = DiagnosticExport.Anonymize(source);
        var second = DiagnosticExport.Anonymize(source);
        Assert.Contains("status=ok http=200", first);
        foreach (var sensitive in new[]
        {
            "bmc.example",
            "alice",
            "/redfish",
            "secret",
            "fixture-token-value"
        }

        )
            Assert.DoesNotContain(sensitive, first);
        Assert.NotEqual(first, second);
        var hosts = first.Split(' ').Where(value => value.StartsWith("host=")).Select(value => value.Trim()).ToArray();
        Assert.Equal(2, hosts.Length);
        Assert.Equal(hosts[0], hosts[1]);
    }
}

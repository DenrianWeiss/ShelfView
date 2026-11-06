using System.Text.Json;
using BControl.Core.Native;
using BControl.Core.Redfish;

namespace BControl.Core.Tests;

public sealed class HostTimeoutTests
{
    [Fact]
    public async Task DelayedDiscoveryHonorsHostOverride()
    {
        if (Environment.GetEnvironmentVariable("BC_TEST_HOST_TIMEOUT_URL") is not { } address) return;
        var credential = new DeviceCredential("user", "secret");
        var failure = await Assert.ThrowsAsync<BcException>(() => DiscoveryService.ProbeAsync(address, credential, certPolicy: Bc.CertSkipAll));
        Assert.Equal(Bc.Timeout, failure.Status);
        var result = await DiscoveryService.ProbeAsync(address, credential, certPolicy: Bc.CertSkipAll, timeout: new HostTimeout(10));
        Assert.Equal("Delayed host", Assert.Single(result.Systems).Name);
        Assert.Equal(Bc.Ok, result.LogoutStatus);
    }
    [Theory]
    [InlineData(1u)]
    [InlineData(60u)]
    [InlineData(3600u)]
    public void RoundTrip(uint seconds)
    {
        var timeout = new HostTimeout(seconds);
        Assert.Equal(seconds * 1000, timeout.Milliseconds);
        Assert.Equal(timeout, JsonSerializer.Deserialize<HostTimeout>(JsonSerializer.Serialize(timeout)));
    }
    [Theory]
    [InlineData("0")]
    [InlineData("3601")]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("\"60\"")]
    [InlineData("4294967295")]
    public void RejectInvalidStoredValue(string json) => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<HostTimeout>(json));
}

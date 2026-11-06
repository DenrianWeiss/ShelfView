using BControl.Core.Redfish;

namespace BControl.Core.Tests;

public sealed class RedfishTaskDelayTests
{
    [Theory]
    [InlineData("", 2000)]
    [InlineData("0", 2000)]
    [InlineData("5", 6000)]
    [InlineData("Wed, 04 Nov 2026 00:00:05 GMT", 6000)]
    [InlineData("-1", long.MaxValue)]
    [InlineData("18446744073709551615", long.MaxValue)]
    [InlineData("invalid", long.MaxValue)]
    public void RetryAfterDoesNotCauseEarlyOrUnboundedPolling(string value, long expected)
    {
        Assert.Equal(expected, RedfishTaskDelay.Due(value, 1000, new DateTimeOffset(2026, 11, 4, 0, 0, 0, TimeSpan.Zero)));
    }
}

using BControl.Core.Media;
using BControl.Core.Kvm;
using BControl.Core.Redfish;

namespace BControl.Core.Tests;
public sealed class IdracMediaFixtureTests
{
    [Fact]
    public async Task ConsoleTicketAndMediaUseSeparateChannels()
    {
        var address = Environment.GetEnvironmentVariable("BC_TEST_IDRAC_MEDIA_FIXTURE");
        if (string.IsNullOrEmpty(address))
            return;
        Assert.Equal("localhost", new Uri(address).Host);
        var mode = Environment.GetEnvironmentVariable("BC_TEST_IDRAC_MEDIA_MODE");
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, Enumerable.Repeat((byte)0x5a, 4096).ToArray());
            if (mode != "complete")
            {
                await Assert.ThrowsAnyAsync<Exception>(() => NativeConsoleClient.OpenMediaAsync(new ConsoleConnectionOptions(address, CertPolicy: 2), new("fixture", "fixture"), path));
                return;
            }

            await using var media = await NativeConsoleClient.OpenMediaAsync(new ConsoleConnectionOptions(address, CertPolicy: 2), new("fixture", "fixture"), path);
            Assert.True(media.IsActive);
            Assert.True(media.SourceAttached);
            Assert.True(media.MountConfirmed);
            Assert.True(await media.EjectAsync());
            Assert.False(media.RemovalUnconfirmed);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

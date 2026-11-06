using BControl.Core.Kvm;
using BControl.Core.Native;
using BControl.Desktop.Services;

namespace BControl.Desktop.Tests;

public sealed class IloConnectionFactoryTests
{
    [Fact]
    public async Task DiscoversIloAndConnectsThroughServerProxy()
    {
        if (Environment.GetEnvironmentVariable("BC_TEST_ILO_FACTORY") != "1") return;
        var port = ushort.Parse(Environment.GetEnvironmentVariable("BC_TEST_ILO_PROXY_PORT")!);
        var record = new ServerRecord
        {
            Address = "https://bmc.invalid/", CertPolicy = Bc.CertSkipAll,
            Proxy = new ServerProxy { Host = "127.0.0.1", Port = port, Username = "proxy-user", CredentialRef = "fixture" },
            ReadProxyCredential = (reference, username, _) =>
            {
                Assert.Equal("fixture", reference); Assert.Equal("proxy-user", username);
                return Task.FromResult(new CredentialReadResult(new("proxy-user", "proxy-secret"), CredentialPersistence.ProcessOnly));
            }
        };
        var session = Assert.IsType<NativeConsoleClient>(await ConsoleConnectionFactory.ConnectAsync(record, new("user", "secret")));
        try
        {
            Assert.Equal(16u, session.LatestFrame!.Width);
            Assert.Equal(new byte[] { 240, 240, 240, 255 }, session.LatestFrame.PixelsRgba[..4]);
            await session.SendKeyAsync(1, 'A'); await session.SendKeyAsync(0, 'A');
            await session.SendPointerAsync(1, 8, 4); await session.SendPointerAsync(0, 8, 4);
        }
        finally { await session.DisposeAsync(); }
        Assert.True(session.CleanupSucceeded);
    }
}

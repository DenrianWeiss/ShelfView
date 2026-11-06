using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using BControl.Core.Native;

namespace BControl.Core.Tests;

public sealed class Socks5Tests
{
    [Fact]
    public async Task NativeHandshakeTimeoutClosesSocket()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var proxy = new Socks5Connection("127.0.0.1", (ushort)((IPEndPoint)listener.LocalEndpoint).Port);
        var connecting = Task.Run(() => {
            using var url = BcStringPinned.Pin("tls://bmc.invalid:443");
            var options = new BcKvmTransportOptions { StructSize = (uint)Marshal.SizeOf<BcKvmTransportOptions>(),
                AbiVersion = Bc.AbiVersion, Url = url.Value, TimeoutMs = 1000 };
            var status = NativeConnections.Connect(ref options, proxy, out var link);
            Assert.Equal(IntPtr.Zero, link);
            return status;
        });
        using var client = await listener.AcceptTcpClientAsync(timeout.Token);
        var stream = client.GetStream();
        var greeting = new byte[3];
        await stream.ReadExactlyAsync(greeting, timeout.Token);
        Assert.NotEqual(Bc.Ok, await connecting);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], timeout.Token));
    }

    [Fact]
    public async Task NativeUdpAssociationClosesControlConnection()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Start();
        var proxy = new Socks5Connection("127.0.0.1", (ushort)((IPEndPoint)listener.LocalEndpoint).Port);
        var accepted = listener.AcceptTcpClientAsync(timeout.Token);
        var connected = Task.Run(() =>
        {
            using var pin = proxy.Pin();
            using var host = BcStringPinned.Pin("bmc.invalid");
            var status = NativeMethods.bc_ipmi_socks5_create(host.Value, 623, ref pin.Value, 3000, out var io);
            try { Assert.Equal(Bc.Ok, status); Assert.NotEqual(IntPtr.Zero, io); }
            finally { if (io != IntPtr.Zero) NativeMethods.bc_ipmi_socks5_destroy(io); }
        });
        using var client = await accepted;
        var stream = client.GetStream();
        var greeting = new byte[3];
        await stream.ReadExactlyAsync(greeting, timeout.Token);
        Assert.Equal(new byte[] { 5, 1, 0 }, greeting);
        await stream.WriteAsync(new byte[] { 5, 0 }, timeout.Token);
        var request = new byte[10];
        await stream.ReadExactlyAsync(request, timeout.Token);
        Assert.Equal(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, request);
        var port = ((IPEndPoint)relay.Client.LocalEndPoint!).Port;
        await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, (byte)(port >> 8), (byte)port }, timeout.Token);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], timeout.Token));
        await connected;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProxyUsesRemoteDnsAndRequestedAuthentication(bool authenticate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var proxy = new Socks5Connection("127.0.0.1", (ushort)((IPEndPoint)listener.LocalEndpoint).Port,
            authenticate ? "proxy-user" : "", authenticate ? "proxy-secret" : "");
        Assert.DoesNotContain("proxy-secret", JsonSerializer.Serialize(proxy));
        Assert.DoesNotContain("proxy-secret", proxy.ToString()!);
        var accepted = listener.AcceptTcpClientAsync(timeout.Token);
        var connected = Task.Run(() =>
        {
            using var url = BcStringPinned.Pin("wss://bmc.invalid:8443/wss/ircport");
            var options = new BcKvmTransportOptions { StructSize = (uint)Marshal.SizeOf<BcKvmTransportOptions>(),
                AbiVersion = Bc.AbiVersion, Url = url.Value, TimeoutMs = 3000 };
            var status = NativeConnections.Connect(ref options, proxy, out var link);
            Assert.Equal(IntPtr.Zero, link);
            Assert.NotEqual(Bc.Ok, status);
        });
        using var client = await accepted;
        var stream = client.GetStream();
        async Task<byte[]> Read(int length)
        {
            var bytes = new byte[length];
            await stream.ReadExactlyAsync(bytes, timeout.Token);
            return bytes;
        }
        var greeting = await Read(2);
        Assert.Equal(5, greeting[0]);
        Assert.Contains((byte)(authenticate ? 2 : 0), await Read(greeting[1]));
        await stream.WriteAsync(new byte[] { 5, (byte)(authenticate ? 2 : 0) }, timeout.Token);
        if (authenticate)
        {
            var auth = await Read(2);
            Assert.Equal(1, auth[0]);
            Assert.Equal("proxy-user", Encoding.UTF8.GetString(await Read(auth[1])));
            var passwordLength = (await Read(1))[0];
            Assert.Equal("proxy-secret", Encoding.UTF8.GetString(await Read(passwordLength)));
            await stream.WriteAsync(new byte[] { 1, 0 }, timeout.Token);
        }
        Assert.Equal(new byte[] { 5, 1, 0, 3 }, await Read(4));
        var hostLength = (await Read(1))[0];
        Assert.Equal("bmc.invalid", Encoding.ASCII.GetString(await Read(hostLength)));
        Assert.Equal(new byte[] { 0x20, 0xfb }, await Read(2));
        await stream.WriteAsync(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, timeout.Token);
        await connected;
    }
}

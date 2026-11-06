using System.Runtime.InteropServices;
using System.Text.Json;
using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Core.Kvm;
namespace BControl.Core.Tests;
public sealed class IloKvmTests
{
    [Fact]
    public async Task ProxyFrameInputAndLogout()
    {
        var value = Environment.GetEnvironmentVariable("BC_TEST_ILO_PROXY_PORT");
        if (string.IsNullOrEmpty(value)) return;
        var proxy = new Socks5Connection("127.0.0.1", ushort.Parse(value), "proxy-user", "proxy-secret");
        var session = await NativeConsoleClient.ConnectAsync(new ConsoleConnectionOptions("https://bmc.invalid/", CertPolicy: Bc.CertSkipAll, Proxy: proxy), new DeviceCredential("user", "secret"));
        try
        {
            var frame = Assert.IsType<KvmFrame>(session.LatestFrame);
            Assert.Equal(16u, frame.Width); Assert.Equal(16u, frame.Height);
            Assert.Equal(new byte[] { 240, 240, 240, 255 }, frame.PixelsRgba[..4]);
            Assert.Equal(new byte[] { 240, 240, 240, 255 }, frame.PixelsRgba[^4..]);
            await session.SendKeyAsync(1, 'A');
            await session.SendKeyAsync(0, 'A');
            await session.SendPointerAsync(1, 8, 4);
            await session.SendPointerAsync(0, 8, 4);
        }
        finally { await session.DisposeAsync(); }
        Assert.True(session.CleanupSucceeded);
    }

    [Theory]
    [InlineData("{\"Oem\":{\"Hpe\":{\"Manager\":[{\"ManagerType\":\"iLO 5\"}]}}}", true)]
    [InlineData("{\"Oem\":{\"Hpe\":{\"Manager\":[{\"ManagerType\":\"iLO 4\"}]}}}", false)]
    [InlineData("{\"Oem\":{\"Hpe\":{\"Manager\":[{\"ManagerType\":\"iLO 5\"},{}]}}}", false)]
    [InlineData("{\"Oem\":[]}", false)]
    public void GenerationGate(string json, bool supported) => Assert.Equal(supported, GenerationSupported(json));

    [DllImport("bcontrol_ilo", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_ilo_discover_generation(byte[] bytes, uint size, out uint generation);
    private static bool GenerationSupported(string json) {
        var bytes = System.Text.Encoding.UTF8.GetBytes(json);
        return bc_ilo_discover_generation(bytes, (uint)bytes.Length, out var generation) == Bc.Ok && generation == 5;
    }

    [Fact]
    public void NativeFrameAndInputAbi()
    {
        using var token = BcStringPinned.Pin("0123456789abcdef0123456789abcdef");
        IntPtr session = IntPtr.Zero;
        var packets = new List<byte[]>();
        ConsoleNative.Emit emit = (_, bytes, length) => {
            var packet = new byte[checked((int)length)];
            Marshal.Copy(bytes, packet, 0, packet.Length);
            packets.Add(packet);
            return Bc.Ok;
        };
        try
        {
            Assert.Equal(Bc.Ok, ConsoleNative.Create(2, new BcKvmOptions { MaxWidth = 1920, MaxHeight = 1200 }, token.Value, 5, emit, null, out session));
            var output = new byte[64];
            for (uint channel = 0; channel < 2; channel++)
            {
                Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_output(session, channel, output, 64, out var size));
                Assert.Equal(54u, size); Assert.Equal(channel, (uint)output[17]);
                Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_feed(session, channel, new byte[53], 53));
            }
            Assert.True((ConsoleNative.Info(session).Flags & 2) != 0);
            byte[] stream = [0x0d, 0x10, 0x08, 0xf0, 0xff, 0xbf, 0x05];
            Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_feed(session, 0, stream, (uint)stream.Length));
            var tile = new BcDisplayTile { StructSize = (uint)Marshal.SizeOf<BcDisplayTile>() };
            Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_tile(session, ref tile));
            Assert.Equal(16u, tile.Width); Assert.Equal(16u, tile.Height);
            Assert.Equal(240, Marshal.ReadByte(tile.Pixels.Data));
            ConsoleNative.bc_console_session_ack_display(session);
            Assert.Equal(Bc.Busy, ConsoleNative.bc_console_session_tile(session, ref tile));
            Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_output(session, 0, output, 64, out _));
            var key = new BcConsoleInput { StructSize = (uint)Marshal.SizeOf<BcConsoleInput>(), Type = 1, Keysym = 'A', Down = 1 };
            Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_input(session, ref key));
            Assert.Equal(2, packets[0][2]); Assert.Equal(4, packets[0][4]);
            var pointer = new BcConsoleInput { StructSize = key.StructSize, Type = 3, X = 8, Y = 4,
                Width = 16, Height = 16, Buttons = 2, Wheel = -1 };
            Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_input(session, ref pointer));
            Assert.Equal(new byte[] { 2, 0, 0xdc, 5, 0xee, 2, 8, 252, 2, 255 }, packets[1]);
            Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_output(session, 0, output, 64, out var pending));
            Assert.Equal(0u, pending);
        }
        finally
        {
            ConsoleNative.bc_console_session_destroy(session);
            GC.KeepAlive(emit);
        }
    }
}

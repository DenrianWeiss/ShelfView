using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Tests;

public sealed class KvmCodecTests
{
    private sealed class Codec : IDisposable
    {
        private readonly GCHandle _pixels;
        private readonly ConsoleNative.Emit _emit;
        internal readonly IntPtr Session;
        internal readonly List<byte[]> Input = [];
        internal Codec()
        {
            var pixels = new byte[1920 * 1200 * 4];
            _pixels = GCHandle.Alloc(pixels, GCHandleType.Pinned);
            _emit = (_, data, length) => {
                var packet = new byte[checked((int)length)];
                Marshal.Copy(data, packet, 0, packet.Length); Input.Add(packet); return Bc.Ok;
            };
            var options = new BcKvmOptions { StructSize = (uint)Marshal.SizeOf<BcKvmOptions>(),
                AbiVersion = Bc.AbiVersion, MaxWidth = 1920, MaxHeight = 1200,
                Framebuffer = _pixels.AddrOfPinnedObject(), FramebufferCapacity = (ulong)pixels.Length };
            try
            {
                Bc.Check(ConsoleNative.Create(1, options, default, 0, _emit, null, out Session), "wrap");
            }
            catch { Dispose(); throw; }
        }
        internal void Feed(byte[] bytes) => Bc.Check(ConsoleNative.bc_console_session_feed(Session, 0, bytes, (uint)bytes.Length), "feed");
        internal byte[] Drain()
        {
            var bytes = new byte[256];
            Bc.Check(ConsoleNative.bc_console_session_output(Session, 0, bytes, (uint)bytes.Length, out var written), "output");
            return bytes[..(int)written];
        }
        internal void Send(BcConsoleInput input)
        {
            input.StructSize = (uint)Marshal.SizeOf<BcConsoleInput>();
            Bc.Check(ConsoleNative.bc_console_session_input(Session, ref input), "input");
        }
        public void Dispose()
        {
            if (Session != IntPtr.Zero) ConsoleNative.bc_console_session_control(Session, ConsoleNative.Close);
            ConsoleNative.bc_console_session_destroy(Session);
            if (_pixels.IsAllocated) _pixels.Free();
            GC.KeepAlive(_emit);
        }
    }

    [Fact]
    public void Handshake_ProducesClientBytes_AndFrame()
    {
        using var codec = new Codec();
        codec.Feed("RFB 003.008\n"u8.ToArray());
        Assert.Equal("RFB 003.008\n"u8.ToArray(), codec.Drain());
        codec.Feed([1, 1]); Assert.Equal(new byte[] { 1 }, codec.Drain());
        codec.Feed([0, 0, 0, 0]); Assert.Equal(new byte[] { 1 }, codec.Drain());
        codec.Feed([0, 2, 0, 2, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0, 0, 0, 0, 3, 66, 77, 67]);
        Assert.True((ConsoleNative.Info(codec.Session).Flags & 2) != 0);
        Assert.Equal("BMC", ConsoleNative.Name(codec.Session));
        var tile = new BcDisplayTile { StructSize = (uint)Marshal.SizeOf<BcDisplayTile>() };
        Assert.Equal(Bc.Busy, ConsoleNative.bc_console_session_tile(codec.Session, ref tile));
        codec.Drain();
        codec.Feed([0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0,
            0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0]);
        Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_tile(codec.Session, ref tile));
        Assert.Equal(2u, tile.Width); Assert.Equal(2u, tile.Height);
        var pixel = new byte[4]; Marshal.Copy(tile.Pixels.Data, pixel, 0, pixel.Length);
        Assert.Equal(new byte[] { 255, 0, 0, 255 }, pixel);
        ConsoleNative.bc_console_session_ack_display(codec.Session);
        Assert.Equal(Bc.Busy, ConsoleNative.bc_console_session_tile(codec.Session, ref tile));
        codec.Drain();
        codec.Send(new BcConsoleInput { Type = 1, Down = 1, Keysym = 'a' });
        codec.Send(new BcConsoleInput { Type = 2, Buttons = 1, X = 1, Y = 1, Width = 2, Height = 2 });
        Assert.Equal(new byte[] { 4, 1, 0, 0, 0, 0, 0, 97 }, codec.Input[0]);
        Assert.Equal(new byte[] { 5, 1, 0, 1, 0, 1 }, codec.Input[1]);
        Assert.Empty(codec.Drain());
    }

    [Fact]
    public void CreateDestroy_CleansUp() { using var codec = new Codec(); }
}

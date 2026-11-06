using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Tests;

public sealed class IdracUnifiedSessionTests
{
    [Fact]
    public void UnifiedInputUsesPublishedLedSnapshotAndPreservesMessageBoundaries()
    {
        var pixels = GCHandle.Alloc(new byte[4], GCHandleType.Pinned);
        IntPtr session = IntPtr.Zero;
        var packets = new List<byte[]>();
        ConsoleNative.Emit emit = (_, bytes, length) =>
        {
            var copy = new byte[(int)length];
            Marshal.Copy(bytes, copy, 0, copy.Length);
            packets.Add(copy);
            return Bc.Ok;
        };
        ConsoleNative.LedSnapshot leds = _ => 2;
        try
        {
            var discovered = new BcIdracLaunch { StructSize = (uint)Marshal.SizeOf<BcIdracLaunch>(),
                PrimaryKey = new byte[257], SecondaryKey = new byte[257] };
            System.Text.Encoding.UTF8.GetBytes("fixture-key").CopyTo(discovered.SecondaryKey, 0);
            Assert.Equal(Bc.Ok, IdracNative.bc_console_launch_from_idrac(ref discovered, out var handle));
            using var launch = new ConsoleLaunchHandle(handle);
            Array.Clear(discovered.SecondaryKey);
            var options = new BcKvmOptions { StructSize = (uint)Marshal.SizeOf<BcKvmOptions>(),
                AbiVersion = Bc.AbiVersion, MaxWidth = 1, MaxHeight = 1,
                Framebuffer = pixels.AddrOfPinnedObject(), FramebufferCapacity = 4 };
            Assert.Equal(Bc.Ok, ConsoleNative.Create(launch, options, emit, leds, out session));
            launch.Dispose();
            var input = new BcConsoleInput { StructSize = (uint)Marshal.SizeOf<BcConsoleInput>(), Type = 1, Down = 1, Keysym = 'a' };
            Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_input(session, ref input));
            byte[] expected = [246, 1, 0, 2, 0, 0, 0, 97];
            Assert.Equal(expected, packets.Single());
            packets.Clear(); input.Type = 3; input.Width = input.Height = 1; input.Buttons = 2; input.Wheel = -1;
            Assert.Equal(Bc.Ok, ConsoleNative.bc_console_session_input(session, ref input));
            Assert.Equal(2, packets.Count);
            Assert.All(packets, packet => Assert.Equal(6, packet.Length));
            Assert.Equal(20, packets[0][1]); Assert.Equal(4, packets[1][1]);
        }
        finally
        {
            ConsoleNative.bc_console_session_destroy(session);
            GC.KeepAlive(emit); GC.KeepAlive(leds);
            pixels.Free();
        }
    }
}

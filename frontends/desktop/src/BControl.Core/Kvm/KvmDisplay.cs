using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Kvm;

public enum KvmDisplayMode { Tile = 1, MediaStream = 2 }
public sealed record KvmTile(uint CanvasWidth, uint CanvasHeight, uint X, uint Y,
    uint Width, uint Height, uint Stride, byte[] PixelsRgba)
{
    public static KvmTile FromFrame(KvmFrame frame) => new(frame.Width, frame.Height, 0, 0,
        frame.Width, frame.Height, frame.Stride, frame.PixelsRgba);
    public unsafe void Validate()
    {
        if (CanvasWidth > 8192 || CanvasHeight > 8192 || Stride > int.MaxValue || PixelsRgba == null)
            throw new ArgumentException("Invalid KVM tile");
        fixed (byte* pixels = PixelsRgba)
        {
            var tile = new BcDisplayTile { StructSize = (uint)Marshal.SizeOf<BcDisplayTile>(), PixelFormat = 1,
                CanvasWidth = CanvasWidth, CanvasHeight = CanvasHeight, X = X, Y = Y, Width = Width,
                Height = Height, Stride = Stride, Pixels = new BcBytes { Data = (IntPtr)pixels, Length = (ulong)PixelsRgba.Length } };
            Bc.Check(NativeMethods.bc_display_tile_validate(ref tile), "kvm.title");
        }
    }
}

public sealed record KvmMediaPacket(ulong StreamId, string Codec, uint Width, uint Height,
    uint TimebaseNumerator, uint TimebaseDenominator, long PresentationTime, long DecodeTime,
    uint Flags, ReadOnlyMemory<byte> Payload);

public interface IKvmDisplaySink
{
    IReadOnlyList<KvmDisplayMode> SupportedModes => new[] { KvmDisplayMode.Tile };
    void DrawTile(KvmTile tile);
    Task PresentMediaAsync(KvmMediaPacket packet) => Task.FromException(new NotSupportedException("Media stream rendering is reserved"));
}

internal static class ConsoleDisplay
{
    // Copy and acknowledge on the decode lane before invoking platform consumers.
    internal static KvmTile? ReadTile(IntPtr session)
    {
        var tile = new BcDisplayTile { StructSize = (uint)Marshal.SizeOf<BcDisplayTile>() };
        var status = ConsoleNative.bc_console_session_tile(session, ref tile);
        if (status == Bc.Busy) return null;
        Bc.Check(status, "core.kvmInput");
        try
        {
            var pixels = new byte[checked((int)tile.Pixels.Length)];
            Marshal.Copy(tile.Pixels.Data, pixels, 0, pixels.Length);
            return new(tile.CanvasWidth, tile.CanvasHeight, tile.X, tile.Y, tile.Width, tile.Height, tile.Stride, pixels);
        }
        finally { ConsoleNative.bc_console_session_ack_display(session); }
    }
    internal static KvmFrame? ReadFrame(IntPtr session, string fallbackName = "")
    {
        var tile = ReadTile(session);
        if (tile == null) return null;
        if (tile.X != 0 || tile.Y != 0 || tile.Width != tile.CanvasWidth || tile.Height != tile.CanvasHeight)
            throw new BcException(Bc.Unsupported, Bc.StatusText(Bc.Unsupported));
        var name = ConsoleNative.Name(session);
        return new(tile.CanvasWidth, tile.CanvasHeight, tile.Stride, name.Length == 0 ? fallbackName : name, tile.PixelsRgba);
    }
}

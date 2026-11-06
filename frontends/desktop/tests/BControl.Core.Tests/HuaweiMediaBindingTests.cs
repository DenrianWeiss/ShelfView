using System.Runtime.InteropServices;
using BControl.Core.Media;
using BControl.Core.Native;

namespace BControl.Core.Tests;
public sealed class HuaweiMediaBindingTests
{
    [DllImport("bcontrol_huawei", EntryPoint = "bc_huawei_media_offer_create", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint CreateOffer(ref BcHuaweiVmmInfo info, out IntPtr offer);
    [Fact]
    public void VmmHandshakeReadsIsoAndReportsRemovalFailure()
    {
        var path = Path.GetTempFileName();
        var offer = IntPtr.Zero;
        var incoming = new Queue<byte[]>();
        incoming.Enqueue(new byte[12]);
        var create = new byte[12];
        create[2] = 0x10;
        incoming.Enqueue(create);
        var read = new byte[28];
        read[0] = 4;
        read[3] = 1;
        read[7] = 16;
        read[12] = 0x28;
        read[20] = 1;
        incoming.Enqueue(read);
        var sent = new List<byte[]>();
        var failSend = false;
        BcConsoleSend send = (_, data, length) =>
        {
            if (failSend)
                return Bc.IoError;
            var bytes = new byte[length];
            Marshal.Copy(data, bytes, 0, bytes.Length);
            sent.Add(bytes);
            return Bc.Ok;
        };
        BcConsoleReceive receive = (IntPtr _, IntPtr data, uint capacity, out uint count, uint timeout) =>
        {
            count = 0;
            if (!incoming.TryDequeue(out var bytes))
                return Bc.Timeout;
            Assert.True(bytes.Length <= capacity);
            Marshal.Copy(bytes, 0, data, bytes.Length);
            count = (uint)bytes.Length;
            return Bc.Ok;
        };
        try
        {
            File.WriteAllBytes(path, Enumerable.Repeat((byte)0x6b, 4096).ToArray());
            using var source = new LocalIsoSource(path);
            var info = new BcHuaweiVmmInfo
            {
                StructSize = (uint)Marshal.SizeOf<BcHuaweiVmmInfo>(),
                State = 2,
                Port = 8208,
                Auth = Convert.FromHexString("33561efd36e49bd10d1909a2f9b6635ab28a3875e3b90c20"),
                Key = Convert.FromHexString("bd069a3a86daec744e88e7ac5bfe44c5"),
                Iv = Convert.FromHexString("42b55d37de6b9629d51b033042289648"),
            };
            Assert.Equal(Bc.Ok, CreateOffer(ref info, out offer));
            BcClock clock = _ => (ulong)Environment.TickCount64;
            using var media = MediaSessionHandle.Create(offer, source.Native, send, receive, clock, 1000);
            Assert.Equal(Bc.Ok, media.Control(MediaSessionHandle.Start));
            Assert.True(media.Snapshot().RemovalUnconfirmed);
            var before = sent.Count;
            Assert.Equal(Bc.Ok, media.Poll(10));
            var reply = sent.Skip(before).SelectMany(bytes => bytes).ToArray();
            Assert.True(reply.Length >= 2060);
            Assert.All(reply[12..2060], value => Assert.Equal((byte)0x6b, value));
            failSend = true;
            Assert.Equal(Bc.IoError, media.Control(MediaSessionHandle.CloseRequest));
            Assert.True(media.Snapshot().RemovalUnconfirmed);
            GC.KeepAlive(clock);

        }
        finally
        {
            MediaNative.bc_media_offer_destroy(offer);
            File.Delete(path);
            GC.KeepAlive(send);
            GC.KeepAlive(receive);
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcHuaweiVmmInfo
{
    public uint StructSize, State, Port, Flags;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
    public byte[] Auth;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Key;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Iv;
    public uint Reserved;
}

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using BControl.Core.Media;
using BControl.Core.Native;

namespace BControl.Core.Tests;
public sealed class LocalMediaTests
{
    [Fact]
    public void MegaRacReadsOnlyRequestedIsoBlocksAndRejectsWrites()
    {
        var path = Path.GetTempFileName();
        try
        {
            var image = Enumerable.Repeat((byte)0x21, 2048).Concat(Enumerable.Repeat((byte)0x5a, 2048)).ToArray();
            File.WriteAllBytes(path, image);
            using var source = new LocalIsoSource(path);
            var native = source.Native;
            Assert.Equal(Bc.Ok, MediaProtocolFixture.bc_megarac_cd_create(ref native, out var cd));
            try
            {
                var output = new byte[4096];
                byte[] Command(byte opcode, uint length)
                {
                    var request = new byte[61];
                    "IUSB    "u8.CopyTo(request);
                    request[8] = 1;
                    request[10] = 32;
                    request[12] = 29;
                    request[17] = 5;
                    request[18] = 1;
                    request[11] = unchecked((byte)-request.Take(32).Sum(value => value));
                    BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(32), length);
                    request[41] = opcode;
                    return request;
                }

                var sense = Command(3, 18);
                sense[45] = 18;
                Assert.Equal(Bc.Ok, MediaProtocolFixture.bc_megarac_cd_handle(cd, sense, 61, output, 4096, out _));
                var read = Command(0x28, 2048);
                read[46] = 1;
                read[49] = 1;
                Assert.Equal(Bc.Ok, MediaProtocolFixture.bc_megarac_cd_handle(cd, read, 61, output, 4096, out var written));
                Assert.Equal(2109u, written);
                Assert.All(output[61..(int)written], value => Assert.Equal((byte)0x5a, value));
                var write = Command(0x2a, 2048);
                Assert.Equal(Bc.Ok, MediaProtocolFixture.bc_megarac_cd_handle(cd, write, 61, output, 4096, out written));
                Assert.Equal(61u, written);
                Assert.Equal(7, output[54]);
                Assert.Equal(image, File.ReadAllBytes(path));
                Assert.Equal((1UL, 2048UL), source.Statistics);
            }
            finally
            {
                MediaProtocolFixture.bc_megarac_cd_destroy(cd);
            }

            var callback = Marshal.GetDelegateForFunctionPointer<BcMediaRead>(native.Read);
            Assert.Equal(Bc.InvalidArgument, callback(IntPtr.Zero, ulong.MaxValue, 2048, IntPtr.Zero));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2047)]
    [InlineData(2049)]
    public void InvalidImageSizesAreRejected(int size)
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, new byte[size]);
            Assert.Throws<InvalidDataException>(() => new LocalIsoSource(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}

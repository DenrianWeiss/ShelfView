using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using BControl.Core.Native;

namespace BControl.Core.Media;
public sealed class LocalIsoSource : IDisposable
{
    private readonly SafeFileHandle _file;
    private readonly BcMediaRead _read;
    private long _requests, _bytes;
    public (ulong Requests, ulong Bytes) Statistics => ((ulong)Interlocked.Read(ref _requests), (ulong)Interlocked.Read(ref _bytes));
    public ulong Size { get; }
    public string Name { get; }
    internal BcMediaSource Native { get; }

    public LocalIsoSource(string path)
    {
        _file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
        try
        {
            var size = RandomAccess.GetLength(_file);
            if (size <= 0 || size % 2048 != 0)
                throw new InvalidDataException(Localization.Loc.T("media.invalidSource"));
            Size = (ulong)size;
            Name = Path.GetFileName(path);
            _read = Read;
            Native = new()
            {
                StructSize = (uint)Marshal.SizeOf<BcMediaSource>(),
                Size = Size,
                Read = Marshal.GetFunctionPointerForDelegate(_read)
            };
        }
        catch
        {
            _file.Dispose();
            throw;
        }
    }

    private unsafe uint Read(IntPtr user, ulong offset, uint length, IntPtr output)
    {
        try
        {
            if (offset > Size || length > Size - offset || length > int.MaxValue)
                return Bc.InvalidArgument;
            var span = new Span<byte>(output.ToPointer(), (int)length);
            var read = 0;
            while (read < span.Length)
            {
                var count = RandomAccess.Read(_file, span[read..], checked((long)offset + read));
                if (count == 0)
                    return Bc.IoError;
                read += count;
            }

            Interlocked.Increment(ref _requests);
            Interlocked.Add(ref _bytes, read);
            return Bc.Ok;
        }
        catch
        {
            return Bc.IoError;
        }
    }

    public void Dispose()
    {
        _file.Dispose();
        GC.KeepAlive(_read);
    }
}

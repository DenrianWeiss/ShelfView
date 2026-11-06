using System.Runtime.InteropServices;
using BControl.Core.Native;
using BControl.Core.Redfish;

namespace BControl.Core.Diagnostics;
public static class CoreLog
{
    private static readonly LogSink Sink = Append;
    private static readonly object Gate = new();
    public static string DirectoryPath { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "bControl", "Logs");
    public static string FilePath => Path.Combine(DirectoryPath, "bcontrol.log");
    public static uint Level { get; private set; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Record
    {
        public uint StructSize, Level, Category;
        public BcString Event, Detail;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Options
    {
        public uint StructSize, AbiVersion, Level, Categories;
        public IntPtr Sink, User;
        public uint Reserved;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void LogSink(IntPtr user, IntPtr record);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_log_configure(ref Options options);
    public static void Configure(uint level)
    {
        if (level > 6)
            throw new ArgumentOutOfRangeException(nameof(level));
        var options = new Options
        {
            StructSize = (uint)Marshal.SizeOf<Options>(),
            AbiVersion = Bc.AbiVersion,
            Level = level,
            Categories = uint.MaxValue,
            Sink = Marshal.GetFunctionPointerForDelegate(Sink)
        };
        Bc.Check(bc_log_configure(ref options), "log.level");
        Level = level;
    }

    private static void Append(IntPtr user, IntPtr pointer)
    {
        try
        {
            var record = Marshal.PtrToStructure<Record>(pointer);
            var line = $"{DateTimeOffset.UtcNow:O}\t{record.Level}\t{record.Category}\t{RedfishSession.Text(record.Event)}\t{RedfishSession.Text(record.Detail)}\n";
            lock (Gate)
            {
                Directory.CreateDirectory(DirectoryPath);
                if (File.Exists(FilePath) && new FileInfo(FilePath).Length >= 8 * 1024 * 1024)
                    File.Move(FilePath, FilePath + ".1", overwrite: true);
                File.AppendAllText(FilePath, line);
            }
        }
        catch
        { /* Never unwind managed exceptions through a native logging callback. */
        }
    }

    public static void Clear()
    {
        lock (Gate)
        {
            if (File.Exists(FilePath))
                File.Delete(FilePath);
            if (File.Exists(FilePath + ".1"))
                File.Delete(FilePath + ".1");
        }
    }

    public static string Read()
    {
        lock (Gate)
        {
            return (File.Exists(FilePath + ".1") ? File.ReadAllText(FilePath + ".1") : "") + (File.Exists(FilePath) ? File.ReadAllText(FilePath) : "");
        }
    }
}

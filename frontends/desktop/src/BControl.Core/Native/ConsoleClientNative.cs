using System.Runtime.InteropServices;
namespace BControl.Core.Native;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int ClientCancelled(IntPtr user);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int ClientConfirm(IntPtr user, uint remaining);
[StructLayout(LayoutKind.Sequential)]
internal struct ConsoleClientOptions
{
    internal uint StructSize, AbiVersion, Service, TimeoutMs;
    internal BcString Address, Username, Password, CaFile;
    internal uint CertPolicy, TlsMin, TlsMax, HttpContract;
    internal IntPtr Proxy, Source, Submit, User, Cancelled, Confirm;
    internal BcServiceProfile Preferred;
}
[StructLayout(LayoutKind.Sequential)]
internal struct ConsoleClientInfo
{
    internal uint StructSize, State, Flags, Status, CleanupStatus;
    internal BcServiceProfile Profile;
    internal BcConsoleFailure Failure;
    internal ulong BytesRead;
}
[StructLayout(LayoutKind.Sequential)]
internal struct ConsoleModeInfo
{
    internal uint StructSize, Current, SupportedModes;
}
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct ConsoleClientChoice
{
    internal uint Id;
    internal BcServiceProfile Profile;
    internal fixed byte Title[64];
    internal string GetTitle()
    {
        fixed (byte* title = Title) {
            var length = 0;
            while (length < 64 && title[length] != 0) ++length;
            return System.Text.Encoding.UTF8.GetString(title, length);
        }
    }
}
internal static class ConsoleClientNative
{
    private const string Library = "bcontrol_client";
    internal const uint Console = 1, Media = 2, Prepare = 3;
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_mode(ref ConsoleClientOptions options, uint expected, uint target, ref ConsoleModeInfo info);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_recommended_mode(in BcConsoleFailure failure);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_detect_media(IntPtr context, IntPtr endpoint, uint timeout, ref FeatureDetection.Result result);
    [DllImport("bcontrol_discovery", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bc_console_entry_can_select_manually(uint status, uint http);
    internal const uint Created = 0, Opening = 1, Active = 2, Closed = 3, Failed = 4;
    internal const uint Scroll = 1, LocalMedia = 2, SourceAttached = 4, MountConfirmed = 8,
        RemovalUnconfirmed = 16, HttpChoice = 32, LayoutChoice = 64, Dependent = 128;
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_choices([Out] ConsoleClientChoice[] choices, uint capacity, out uint count);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_create(ref ConsoleClientOptions options, out IntPtr client);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_media_create(IntPtr parent, ref ConsoleClientOptions options, out IntPtr client);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_start(IntPtr client);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_poll(IntPtr client, uint timeout);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_input(IntPtr client, ref BcConsoleInput input);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_chord(IntPtr client, uint[] keys, uint count);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_tile(IntPtr client, ref BcDisplayTile tile);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_console_client_ack_display(IntPtr client);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_info_get(IntPtr client, ref ConsoleClientInfo info);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_eject(IntPtr client);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_client_close(IntPtr client);
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_console_client_destroy(IntPtr client);
}

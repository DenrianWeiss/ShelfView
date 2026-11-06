using System.Runtime.InteropServices;

namespace BControl.Core.Native;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct BcRedfishTaskReference
{
    public uint StructSize, Action, HttpMethod, Reserved;
    public fixed byte EndpointId[37];
    public fixed byte AddressDigest[65];
    public fixed byte CollectionUri[1024];
    public fixed byte MediaUri[1024];
    public fixed byte TargetUri[1024];
    public fixed byte TaskUri[1024];
    public fixed byte TaskId[129];
    public fixed byte StartTime[65];
    public string Uri { get { fixed (byte* p = TaskUri) return Marshal.PtrToStringUTF8((IntPtr)p) ?? ""; } }
}

internal static class RedfishTaskNative
{
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bc_redfish_task_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_redfish_retain(IntPtr operation);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_discover_tasks(IntPtr endpoint, ref BcRedfishCollectionOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_get_task(IntPtr endpoint, BcString uri, ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_task_reference_export_operation(IntPtr write, IntPtr discovery, BcString endpointId, BcString addressDigest, [Out] byte[] output, uint capacity, out uint written);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_task_reference_restore_operation(BcBytes saved, IntPtr media, IntPtr discovery, BcString endpointId, BcString addressDigest, uint action, out BcRedfishTaskReference reference);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_task_reference_match_operation(ref BcRedfishTaskReference reference, IntPtr read, IntPtr discovery, BcString endpointId, BcString addressDigest, out uint flags);
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishTaskInfo
{
    public uint StructSize, Flags;
    public BcString TaskUri, MonitorUri, State, Status, RetryAfter;
    public uint PercentComplete, Reserved;
    public BcBytes MessagesJson, FinalBody;
}

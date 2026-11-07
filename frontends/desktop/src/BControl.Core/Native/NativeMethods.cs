using System.Runtime.InteropServices;

namespace BControl.Core.Native;
internal static class NativeLibs
{
    public const string Bcontrol = "bcontrol";
    public const string Curl = "bcontrol_curl";
    public const string Redfish = "bcontrol_redfish";
    public const string Inventory = "bcontrol_inventory";
    public const string Kvm = "bcontrol_kvm";
    public const string KvmNet = "bcontrol_kvm_net";
    public const string Ipmi = "bcontrol_ipmi";
    public const string IpmiPlatform = "bcontrol_ipmi_platform";
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate void BcRedfishCompletion(IntPtr operation, IntPtr result, IntPtr userdata);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate void BcRedfishAuthCompletion(IntPtr operation, IntPtr result, IntPtr userdata);
internal static class NativeMethods
{
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_display_tile_validate(ref BcDisplayTile tile);
    [DllImport(NativeLibs.IpmiPlatform, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_ipmi_socks5_create(BcString host, ushort port, ref BcSocks5Proxy proxy, uint timeoutMs, out IntPtr io);
    [DllImport(NativeLibs.IpmiPlatform, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_ipmi_socks5_destroy(IntPtr io);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_endpoint_create_proxy(IntPtr context, ref BcEndpointOptions options, ref BcSocks5Proxy proxy, out IntPtr endpoint);
    [DllImport(NativeLibs.KvmNet, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_kvm_transport_connect_proxy(ref BcKvmTransportOptions options, ref BcSocks5Proxy proxy, out IntPtr transport);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_patch(IntPtr endpoint, BcString uri, BcBytes body, ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr user, out IntPtr operation);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_get_network_protocol(IntPtr endpoint, BcString managerUri, ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr user, out IntPtr operation);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_get_ethernet_interface(IntPtr endpoint, BcString uri, ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr user, out IntPtr operation);
    [DllImport(NativeLibs.Redfish, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_redfish_network_rows(IntPtr operation, BcRedfishNetworkRowCallback callback, IntPtr user);
    // ---- libbcontrol ----
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_abi_version();
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern IntPtr bc_status_string(uint status);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_context_create([In] ref BcContextOptions options, out IntPtr context);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_context_poll(IntPtr context, uint timeout_ms);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_context_shutdown(IntPtr context);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_context_destroy(IntPtr context);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_endpoint_create(IntPtr context, [In] ref BcEndpointOptions options, out IntPtr endpoint);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern void bc_endpoint_retain(IntPtr endpoint);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern void bc_endpoint_release(IntPtr endpoint);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_endpoint_set_cookie(IntPtr endpoint, BcString name, BcString value);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern ulong bc_endpoint_revision(IntPtr endpoint);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_temperature_summarize([In] BcTemperatureReading[] readings, uint count, ref BcTemperatureSummary summary);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_temperature_select([In] BcTemperatureReading[] readings, uint count, ref BcTemperatureSelection selection);
    [DllImport(NativeLibs.Bcontrol)]
    internal static extern uint bc_temperature_ipmi_role(uint entityId);
    // ---- libbcontrol_curl ----
    [DllImport(NativeLibs.Curl)]
    internal static extern uint bc_curl_transport_create(out IntPtr transport);
    [DllImport(NativeLibs.Curl)]
    internal static extern uint bc_curl_transport_destroy(IntPtr transport);
    // ---- libbcontrol_redfish ----
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_login(IntPtr endpoint, [In] ref BcRedfishLoginOptions options, BcRedfishAuthCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_logout(IntPtr connection, uint timeout_ms, BcRedfishAuthCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_auth_cancel(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern void bc_redfish_auth_retain(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern void bc_redfish_auth_release(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_auth_result_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern void bc_redfish_connection_retain(IntPtr connection);
    [DllImport(NativeLibs.Redfish)]
    internal static extern void bc_redfish_connection_release(IntPtr connection);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_connection_info_get(IntPtr connection);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_connection_endpoint(IntPtr connection);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_probe(IntPtr endpoint, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_discover(IntPtr endpoint, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_get_system(IntPtr endpoint, BcString uri, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_get_sensor(IntPtr endpoint, BcString uri, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_get_resource(IntPtr endpoint, BcString uri, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_get_collection(IntPtr endpoint, BcString uri, uint collection_kind, [In] ref BcRedfishCollectionOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_discover_managers(IntPtr endpoint, [In] ref BcRedfishCollectionOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_get_virtual_media(IntPtr endpoint, BcString uri, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_discover_virtual_media(IntPtr endpoint, BcString manager_uri, [In] ref BcRedfishCollectionOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_virtual_media_insert(IntPtr endpoint, BcString media_uri, [In] ref BcRedfishVirtualMediaInsertOptions insert, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_virtual_media_eject(IntPtr endpoint, BcString media_uri, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_get_graphical_console(IntPtr endpoint, BcString uri, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_get_reset_capabilities(IntPtr endpoint, BcString uri, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_reset(IntPtr endpoint, BcString uri, uint reset_type, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_get_boot(IntPtr endpoint, BcString uri, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_boot_set_once(IntPtr endpoint, BcString uri, uint target, uint mode, [In] ref BcRedfishOptions options, BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_sensor_temperature_reading(IntPtr operation, uint allow_cpu, ref BcTemperatureReading reading);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_result_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_system_identity_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_context_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_sensor_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_collection_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_resource_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_virtual_media_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_graphical_console_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_reset_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern IntPtr bc_redfish_boot_info_get(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern uint bc_redfish_cancel(IntPtr operation);
    [DllImport(NativeLibs.Redfish)]
    internal static extern void bc_redfish_release(IntPtr operation);
    // ---- libbcontrol_inventory ----
    [DllImport(NativeLibs.Inventory)]
    internal static extern uint bc_inventory_parse(BcBytes data, uint format, out IntPtr import, out BcInventoryError error);
    [DllImport(NativeLibs.Inventory)]
    internal static extern uint bc_inventory_count(IntPtr import);
    [DllImport(NativeLibs.Inventory)]
    internal static extern IntPtr bc_inventory_entry_get(IntPtr import, uint index);
    [DllImport(NativeLibs.Inventory)]
    internal static extern void bc_inventory_import_destroy(IntPtr import);
    [StructLayout(LayoutKind.Sequential)]
    internal struct BcInventoryError
    {
        public uint StructSize;
        public uint Record;
        public uint Line;
        public uint Field;
        public uint Code;
        public uint Reserved;
    }

    // ---- libbcontrol_kvm_net ----
    [DllImport(NativeLibs.KvmNet)]
    internal static extern uint bc_kvm_transport_connect([In] ref BcKvmTransportOptions options, out IntPtr transport);
    [DllImport(NativeLibs.KvmNet)]
    internal static extern uint bc_kvm_transport_recv(IntPtr transport, [Out] byte[] data, uint capacity, out uint received, uint timeout_ms);
    [DllImport(NativeLibs.KvmNet)]
    internal static extern uint bc_kvm_transport_send(IntPtr transport, [In] byte[] data, uint length);
    [DllImport(NativeLibs.KvmNet)]
    internal static extern uint bc_kvm_transport_local_address(IntPtr transport, IntPtr output, uint capacity);
    [DllImport(NativeLibs.KvmNet)]
    internal static extern uint bc_kvm_transport_kind(IntPtr transport);
    [DllImport(NativeLibs.KvmNet)]
    internal static extern void bc_kvm_transport_close(IntPtr transport);
    [DllImport(NativeLibs.KvmNet, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_kvm_transport_interrupt(IntPtr transport);
    [DllImport(NativeLibs.KvmNet)]
    internal static extern void bc_kvm_transport_destroy(IntPtr transport);
    // ---- libbcontrol_ipmi ----
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_session_create([In] ref BcIpmiSessionOptions options, out IntPtr session);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_session_open(IntPtr session);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_session_confirm_suite3(IntPtr session);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern IntPtr bc_ipmi_session_info_get(IntPtr session);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_session_probe(IntPtr session, ref BcIpmiCapabilities capabilities);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_chassis_status_get(IntPtr session, ref BcIpmiChassisStatus status);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_session_close(IntPtr session);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern void bc_ipmi_session_destroy(IntPtr session);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_sol_config_get(IntPtr session, ref BcIpmiSolConfig config, out byte completion_code);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_sol_open(IntPtr session, [In] ref BcIpmiSolOptions options, ulong now_ms, out IntPtr sol);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_sol_poll(IntPtr sol, ulong now_ms, uint timeout_ms);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_sol_write(IntPtr sol, BcBytes data, out uint accepted);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_sol_read(IntPtr sol, [Out] byte[] buffer, uint capacity, out uint length);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_sol_break(IntPtr sol);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_sol_info_get(IntPtr sol, ref BcIpmiSolInfo info);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern uint bc_ipmi_sol_close(IntPtr sol);
    [DllImport(NativeLibs.Ipmi)]
    internal static extern void bc_ipmi_sol_destroy(IntPtr sol);
    // ---- libbcontrol_ipmi_platform ----
    [DllImport(NativeLibs.IpmiPlatform)]
    internal static extern uint bc_ipmi_openssl_crypto_create(out IntPtr crypto);
    [DllImport(NativeLibs.IpmiPlatform)]
    internal static extern void bc_ipmi_openssl_crypto_destroy(IntPtr crypto);
    [DllImport(NativeLibs.IpmiPlatform)]
    internal static extern uint bc_ipmi_udp_create_timeout(BcString host, ushort port, uint timeout, out IntPtr io);
    [DllImport(NativeLibs.IpmiPlatform)]
    internal static extern void bc_ipmi_udp_destroy(IntPtr io);
}

#ifndef BCONTROL_REDFISH_H
#define BCONTROL_REDFISH_H
#include "bcontrol.h"
#include "temperature.h"
#include "boot.h"
#include "sensor.h"
#if defined(_WIN32)
# ifdef BC_REDFISH_BUILD
#  define BC_REDFISH_API __declspec(dllexport)
# else
#  define BC_REDFISH_API __declspec(dllimport)
# endif
#else
# define BC_REDFISH_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define BC_REDFISH_DISCOVERY 0u
#define BC_REDFISH_SYSTEM 1u
#define BC_REDFISH_RESET_CAPABILITIES 2u
#define BC_REDFISH_RESET 3u
#define BC_REDFISH_TASK 4u
#define BC_REDFISH_TASK_MONITOR 5u
#define BC_REDFISH_SENSOR 6u
#define BC_REDFISH_COLLECTION 7u
#define BC_REDFISH_SENSOR_DISCOVERY 8u
#define BC_REDFISH_CHASSIS_DISCOVERY 9u
#define BC_REDFISH_RESOURCE 10u
#define BC_REDFISH_ACTION 11u
#define BC_REDFISH_PATCH 12u
#define BC_REDFISH_PROBE 13u
#define BC_REDFISH_VIRTUAL_MEDIA 14u
#define BC_REDFISH_VIRTUAL_MEDIA_INSERT 15u
#define BC_REDFISH_VIRTUAL_MEDIA_EJECT 16u
#define BC_REDFISH_VIRTUAL_MEDIA_DISCOVERY 17u
#define BC_REDFISH_GRAPHICAL_CONSOLE 18u
#define BC_REDFISH_TASK_DISCOVERY 19u
#define BC_REDFISH_BOOT 20u
#define BC_REDFISH_BOOT_ONCE 21u
#define BC_REDFISH_SENSOR_DETAILS 22u
#define BC_REDFISH_MANAGER_DISCOVERY 23u
#define BC_REDFISH_NETWORK_PROTOCOL 24u
#define BC_REDFISH_ETHERNET_DISCOVERY 25u
#define BC_REDFISH_ETHERNET_INTERFACE 26u
#define BC_REDFISH_BOOT_VERIFIED 4u
#define BC_REDFISH_CONSOLE_SERVICE_ENABLED 1u
#define BC_REDFISH_CONSOLE_PORT_PRESENT 2u
#define BC_REDFISH_CONSOLE_SESSIONS_PRESENT 4u
#define BC_REDFISH_CONSOLE_TYPES_PRESENT 8u
#define BC_COLLECTION_VIRTUAL_MEDIA 4u
#define BC_REDFISH_VM_INSERTED 1u
#define BC_REDFISH_VM_WRITE_PROTECTED 2u
#define BC_REDFISH_VM_INSERT_ACTION 4u
#define BC_REDFISH_VM_EJECT_ACTION 8u
#define BC_REDFISH_VM_INSERTED_PRESENT 16u
#define BC_REDFISH_VM_WRITE_PROTECTED_SET 1u
#define BC_REDFISH_CAPABILITY_SYSTEMS 1u
#define BC_REDFISH_CAPABILITY_CHASSIS 2u
#define BC_REDFISH_CAPABILITY_MANAGERS 4u
#define BC_REDFISH_CAPABILITY_SESSION_SERVICE 8u
#define BC_REDFISH_CAPABILITY_TASK_SERVICE 16u
#define BC_REDFISH_MAX_BODY 65536u
#define BC_COLLECTION_SYSTEMS 0u
#define BC_COLLECTION_CHASSIS 1u
#define BC_COLLECTION_SENSORS 2u
#define BC_COLLECTION_TASKS 3u
#define BC_COLLECTION_MANAGERS 5u
#define BC_COLLECTION_ETHERNET_INTERFACES 6u
#define BC_REDFISH_COMMAND_ACCEPTED 1u
#define BC_REDFISH_TASK_PENDING 2u
#define BC_REDFISH_COMMAND_SUBMITTED 4u
#define BC_REDFISH_COMMAND_UNCONFIRMED 8u

#define BC_TASK_MONITOR_PENDING 1u
#define BC_TASK_MONITOR_COMPLETE 2u
#define BC_TASK_TERMINAL 4u
#define BC_TASK_FAILED 8u
#define BC_TASK_CANCELLED 16u
#define BC_TASK_PERCENT_PRESENT 32u

typedef struct {
    uint32_t struct_size;
    uint32_t reserved;
    bc_string manufacturer;
    bc_string model;
    bc_string serial_number;
    bc_string uuid;
    bc_string host_name;
} bc_redfish_system_identity;

typedef struct bc_redfish_operation bc_redfish_operation;
#define BC_REDFISH_MAX_CONTEXT_LINKS 256u
#define BC_REDFISH_CONTEXT_ENABLED_PRESENT 1u
#define BC_REDFISH_CONTEXT_BASIS_PRESENT 2u
/* One or more ComputerSystems links pointed inside the chassis itself. */
#define BC_REDFISH_CONTEXT_CHASSIS_SUBRESOURCE_LINK 4u
typedef struct {
    uint32_t struct_size;
    bc_status status;
    bc_string physical_context;
    bc_string reading_basis;
    bc_string sensor_collection_uri;
    bc_string thermal_uri;
    const bc_string *related_items;
    uint32_t related_count;
    uint32_t flags;
    const bc_string *chassis;
    uint32_t chassis_count;
    uint32_t enabled;
    const bc_string *systems;
    uint32_t system_count;
    uint32_t reserved;
} bc_redfish_context_info;
/* Additional topology/sensor metadata has its own status; unsupported metadata
 * does not invalidate an otherwise valid system or sensor reading. */
BC_REDFISH_API const bc_redfish_context_info *bc_redfish_context_info_get(const bc_redfish_operation *);
/* Map a completed Sensor to absolute temperature flags/units. UNSUPPORTED means
 * no valid dashboard temperature. allow_cpu is 1 only for an owned sensor. */
BC_REDFISH_API bc_status bc_redfish_sensor_temperature_reading(const bc_redfish_operation *, uint32_t allow_cpu, bc_temperature_reading *);

typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    bc_string task_uri;
    bc_string monitor_uri;
    bc_string state;
    bc_string status;
    bc_string retry_after;
    uint32_t percent_complete;
    uint32_t reserved;
    bc_bytes messages_json;
    bc_bytes final_body;
} bc_redfish_task_info;

#define BC_SENSOR_READING_PRESENT 1u
#define BC_SENSOR_RANGE_MIN_PRESENT 2u
#define BC_SENSOR_RANGE_MAX_PRESENT 4u
#define BC_SENSOR_LOWER_CAUTION 0u
#define BC_SENSOR_LOWER_CRITICAL 1u
#define BC_SENSOR_LOWER_FATAL 2u
#define BC_SENSOR_UPPER_CAUTION 3u
#define BC_SENSOR_UPPER_CRITICAL 4u
#define BC_SENSOR_UPPER_FATAL 5u
#define BC_SENSOR_THRESHOLD_COUNT 6u
typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    double reading;
    double range_min;
    double range_max;
    bc_string reading_type;
    bc_string units;
    bc_string health;
    bc_string state;
    bc_string reading_time;
    double thresholds[BC_SENSOR_THRESHOLD_COUNT];
    uint32_t threshold_mask;
    uint32_t reserved;
    bc_bytes thresholds_json;
} bc_redfish_sensor_info;

#define BC_RESET_ON 0u
#define BC_RESET_FORCE_OFF 1u
#define BC_RESET_GRACEFUL_SHUTDOWN 2u
#define BC_RESET_GRACEFUL_RESTART 3u
#define BC_RESET_FORCE_RESTART 4u
#define BC_RESET_NMI 5u
#define BC_RESET_FORCE_ON 6u
#define BC_RESET_PUSH_POWER_BUTTON 7u
#define BC_RESET_POWER_CYCLE 8u

typedef struct {
    uint32_t struct_size;
    uint32_t supported_reset_types;
    bc_string target;
} bc_redfish_reset_info;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t request_timeout_ms;
    uint32_t max_systems;
} bc_redfish_options;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t request_timeout_ms;
    uint32_t max_members;
} bc_redfish_collection_options;
typedef struct {
    uint32_t struct_size;
    uint32_t collection_kind;
    const bc_string *members;
    uint32_t member_count;
    uint32_t reserved;
} bc_redfish_collection_info;
typedef struct {
    uint32_t struct_size;
    bc_status status;
    uint32_t kind;
    uint32_t http_status;
    uint64_t endpoint_revision;
    bc_string resource_uri;
    bc_string redfish_version;
    bc_string id;
    bc_string name;
    bc_string raw_power_state;
    const bc_string *systems;
    uint32_t system_count;
    uint32_t power_state;
    uint32_t flags;
    uint32_t reserved;
    bc_bytes error_body;
} bc_redfish_result;
typedef void (*bc_redfish_completion)(bc_redfish_operation *, const bc_redfish_result *, void *);
typedef struct {
    uint32_t struct_size;
    uint32_t reserved;
    bc_string odata_type;
    bc_bytes json;
    bc_bytes oem_json;
} bc_redfish_resource_info;

typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    bc_string image;
    bc_string transfer_method;
    bc_string transfer_protocol_type;
    uint32_t write_protected;
    uint32_t reserved;
} bc_redfish_virtual_media_insert_options;

typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    uint32_t service_enabled;
    uint32_t port;
    uint32_t max_sessions;
    const bc_string *connect_types;
    uint32_t connect_type_count;
} bc_redfish_graphical_console_info;

/* Read-only ManagerNetworkProtocol (DSP2051). Protocol entries are indexed by
 * BC_REDFISH_PROTOCOL_*; flags say whether the entry exists and whether
 * Enabled/Port were reported. DMTF ManagerNetworkProtocol v1.9+ makes Port
 * and ProtocolEnabled nullable, and HostName/FQDN nullable strings: null_flags
 * records an explicit JSON null so missing, null, and a real value (including
 * an explicit 0) stay distinguishable per field. */
#define BC_REDFISH_PROTOCOL_NTP 0u
#define BC_REDFISH_PROTOCOL_SSH 1u
#define BC_REDFISH_PROTOCOL_SNMP 2u
#define BC_REDFISH_PROTOCOL_HTTP 3u
#define BC_REDFISH_PROTOCOL_HTTPS 4u
#define BC_REDFISH_PROTOCOL_IPMI 5u
#define BC_REDFISH_PROTOCOL_VIRTUAL_MEDIA 6u
#define BC_REDFISH_PROTOCOL_KVMIP 7u
#define BC_REDFISH_PROTOCOL_SSDP 8u
#define BC_REDFISH_PROTOCOL_TELNET 9u
#define BC_REDFISH_NETWORK_PROTOCOL_COUNT 10u
#define BC_REDFISH_NET_PROTOCOL_PRESENT 1u
#define BC_REDFISH_NET_PROTOCOL_ENABLED 2u
#define BC_REDFISH_NET_PROTOCOL_PORT 4u
#define BC_REDFISH_NET_PROTOCOL_ENABLED_NULL 8u
#define BC_REDFISH_NET_PROTOCOL_PORT_NULL 16u
#define BC_REDFISH_NET_PROTOCOL_SNMPV3 32u
#define BC_REDFISH_NETWORK_MAX_SERVERS 8u
#define BC_REDFISH_NETWORK_HOST_NAME_NULL 1u
#define BC_REDFISH_NETWORK_FQDN_NULL 2u
typedef struct {
    uint32_t flags;
    uint32_t null_flags;
    uint32_t enabled;
    uint32_t port;
} bc_redfish_network_protocol_entry;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    bc_redfish_network_protocol_entry protocols[BC_REDFISH_NETWORK_PROTOCOL_COUNT];
    bc_string ntp_servers[BC_REDFISH_NETWORK_MAX_SERVERS];
    uint32_t ntp_server_count;
    bc_string ntp_network_supplied[BC_REDFISH_NETWORK_MAX_SERVERS];
    uint32_t ntp_network_supplied_count;
    bc_string host_name;
    bc_string fqdn;
    uint32_t null_flags;
} bc_redfish_network_protocol_info;

/* Read-only EthernetInterface member parse. For every string/bool field the
 * flags bit reports presence in the payload and null_flags reports an
 * explicit JSON null, so missing and null stay distinguishable. */
#define BC_REDFISH_ETH_IPV4_COUNT 4u
#define BC_REDFISH_ETH_IPV6_COUNT 8u
#define BC_REDFISH_ETH_MAC 1u
#define BC_REDFISH_ETH_STATUS_STATE 2u
#define BC_REDFISH_ETH_STATUS_HEALTH 4u
#define BC_REDFISH_ETH_DHCP4_ENABLED 8u
#define BC_REDFISH_ETH_DHCP6_ENABLED 16u
#define BC_REDFISH_ETH_HOST_NAME 32u
#define BC_REDFISH_ETH_FQDN 64u
#define BC_REDFISH_ETH_INTERFACE_ENABLED 128u
#define BC_REDFISH_ETH_LINK_STATUS 256u
#define BC_REDFISH_ETH_MTU 512u
#define BC_REDFISH_ETH_SPEED 1024u
#define BC_REDFISH_ETH_VLAN_ENABLED 2048u
#define BC_REDFISH_ETH_VLAN_ID 4096u
#define BC_REDFISH_ETH_IPV6_GATEWAY 8192u
#define BC_REDFISH_ETH_MODE 16384u
#define BC_REDFISH_ETH_DHCP6_MODE 32768u
typedef struct {
    uint32_t flags;
    uint32_t null_flags;
    bc_string address;
    bc_string subnet_mask;
    bc_string gateway;
    bc_string address_origin;
} bc_redfish_ipv4_entry;
typedef struct {
    uint32_t flags;
    uint32_t null_flags;
    bc_string address;
    bc_string address_origin;
    bc_string address_state;
    uint32_t prefix_length;
} bc_redfish_ipv6_entry;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t flags;
    uint32_t null_flags;
    bc_string mac;
    bc_string state;
    bc_string health;
    bc_string host_name;
    bc_string fqdn;
    bc_string link_status;
    uint32_t dhcp4_enabled;
    uint32_t dhcp6_enabled;
    uint32_t interface_enabled;
    bc_redfish_ipv4_entry ipv4[BC_REDFISH_ETH_IPV4_COUNT];
    uint32_t ipv4_count;
    bc_redfish_ipv6_entry ipv6[BC_REDFISH_ETH_IPV6_COUNT];
    uint32_t ipv6_count;
    uint32_t mtu, speed_mbps, vlan_enabled, vlan_id;
    bc_string ipv6_gateway, interface_mode;
    bc_string name_servers[BC_REDFISH_NETWORK_MAX_SERVERS];
    uint32_t name_server_count;
    bc_string dhcp6_mode;
} bc_redfish_ethernet_info;
typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    bc_string id;
    bc_string name;
    bc_string image;
    bc_string image_name;
    bc_string connected_via;
    const bc_string *media_types;
    uint32_t media_type_count;
    uint32_t inserted;
    uint32_t write_protected;
    bc_string insert_target;
    bc_string eject_target;
} bc_redfish_virtual_media_info;
typedef struct {
    uint32_t struct_size, supported_modes;
    bc_boot_info boot;
} bc_redfish_boot_info;
BC_REDFISH_API bc_status bc_redfish_boot_parse(bc_bytes system_json, bc_redfish_boot_info *);
BC_REDFISH_API bc_status bc_redfish_boot_patch_build(const bc_redfish_boot_info *, uint32_t target, uint32_t mode,
    uint8_t *out, uint32_t capacity, uint32_t *written);
BC_REDFISH_API bc_status bc_redfish_get_boot(bc_endpoint *, bc_string system_uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
/* Preflights advertised targets, then PATCHes only the boot override fields.
 * Synchronous responses are read back; a 202 remains accepted until its task and state are checked. */
BC_REDFISH_API bc_status bc_redfish_boot_set_once(bc_endpoint *, bc_string system_uri, uint32_t target, uint32_t mode,
    const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_boot_info *bc_redfish_boot_info_get(const bc_redfish_operation *);

BC_REDFISH_API bc_status bc_redfish_get_resource(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
/* Vendor/OEM action and PATCH with a caller-supplied JSON body. The response
 * JSON is available through bc_redfish_resource_info_get. */
BC_REDFISH_API bc_status bc_redfish_action(bc_endpoint *, bc_string action_uri, bc_bytes body, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_patch(bc_endpoint *, bc_string uri, bc_bytes body, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
/* Read the service root and report advertised services; a recognized legacy
 * login profile may succeed without service flags until session authentication. */
BC_REDFISH_API bc_status bc_redfish_probe(bc_endpoint *, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_resource_info *bc_redfish_resource_info_get(const bc_redfish_operation *);
BC_REDFISH_API uint32_t bc_redfish_uri_supported(bc_string uri);
enum {
    BC_REDFISH_URI_NO_MATCH = 0,
    BC_REDFISH_URI_EXACT = 1,
    BC_REDFISH_URI_FIXED_CASE = 2
};
/* An empty pattern requires exact equality. Otherwise each '*' is one opaque,
 * case-sensitive instance segment; schema-defined literal segments allow ASCII
 * case differences. Invalid paths/patterns do not match. Never rewrites a URI. */
BC_REDFISH_API uint32_t bc_redfish_resource_uri_match(bc_string requested, bc_string returned, bc_string pattern);

BC_REDFISH_API bc_status bc_redfish_discover(bc_endpoint *, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_system_identity *bc_redfish_system_identity_get(const bc_redfish_operation *);
BC_REDFISH_API bc_status bc_redfish_get_system(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_get_reset_capabilities(bc_endpoint *, bc_string system_uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_reset(bc_endpoint *, bc_string system_uri, uint32_t reset_type, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_reset_info *bc_redfish_reset_info_get(const bc_redfish_operation *);
BC_REDFISH_API bc_status bc_redfish_get_task(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_get_task_monitor(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_task_info *bc_redfish_task_info_get(const bc_redfish_operation *);
BC_REDFISH_API bc_status bc_redfish_get_sensor(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_get_virtual_media(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_virtual_media_insert(bc_endpoint *, bc_string media_uri, const bc_redfish_virtual_media_insert_options *, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_virtual_media_eject(bc_endpoint *, bc_string media_uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_virtual_media_info *bc_redfish_virtual_media_info_get(const bc_redfish_operation *);
BC_REDFISH_API bc_status bc_redfish_discover_virtual_media(bc_endpoint *, bc_string manager_uri, const bc_redfish_collection_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_get_graphical_console(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_graphical_console_info *bc_redfish_graphical_console_info_get(const bc_redfish_operation *);
BC_REDFISH_API const bc_redfish_sensor_info *bc_redfish_sensor_info_get(const bc_redfish_operation *);
BC_REDFISH_API bc_status bc_redfish_get_sensor_details(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
/* Copies the snapshot; strings are borrowed until operation release. Available
 * after completion, including failure. Field errors do not erase other values. */
BC_REDFISH_API bc_status bc_redfish_sensor_details_get(const bc_redfish_operation *, bc_sensor_details *);
BC_REDFISH_API bc_status bc_redfish_discover_tasks(bc_endpoint *, const bc_redfish_collection_options *, bc_redfish_completion, void *, bc_redfish_operation **);
/* Managers collection from the ServiceRoot link, paged and deduplicated. */
BC_REDFISH_API bc_status bc_redfish_discover_managers(bc_endpoint *, const bc_redfish_collection_options *, bc_redfish_completion, void *, bc_redfish_operation **);
/* Reads a Manager, follows its NetworkProtocol link, and parses the
 * ManagerNetworkProtocol payload. No fixed resource IDs are assumed. */
BC_REDFISH_API bc_status bc_redfish_get_network_protocol(bc_endpoint *, bc_string manager_uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
/* Reads a Manager and follows its EthernetInterfaces collection link with the
 * usual paging/limits; members are interface resource URIs. */
BC_REDFISH_API bc_status bc_redfish_discover_ethernet(bc_endpoint *, bc_string manager_uri, const bc_redfish_collection_options *, bc_redfish_completion, void *, bc_redfish_operation **);
/* Reads one EthernetInterface member. */
BC_REDFISH_API bc_status bc_redfish_get_ethernet_interface(bc_endpoint *, bc_string uri, const bc_redfish_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_network_protocol_info *bc_redfish_network_protocol_info_get(const bc_redfish_operation *);
BC_REDFISH_API const bc_redfish_ethernet_info *bc_redfish_ethernet_info_get(const bc_redfish_operation *);

#define BC_REDFISH_NETWORK_ROW_HEADING 1u
#define BC_REDFISH_NETWORK_ROW_LABEL_KEY 2u
#define BC_REDFISH_NETWORK_ROW_VALUE_KEY 4u
#define BC_REDFISH_NETWORK_ROW_MISSING 8u
#define BC_REDFISH_NETWORK_ROW_NULL 16u
typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    bc_string label;
    bc_string value;
    bc_string suffix;
} bc_redfish_network_row;
/* Synchronous ordered presentation rows. Copy strings during the callback;
 * they are borrowed only until it returns. Keys use the shared i18n catalog. */
typedef void (*bc_redfish_network_row_callback)(const bc_redfish_network_row *, void *);
BC_REDFISH_API bc_status bc_redfish_network_rows(const bc_redfish_operation *, bc_redfish_network_row_callback, void *);

BC_REDFISH_API bc_status bc_redfish_discover_chassis(bc_endpoint *, const bc_redfish_collection_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_discover_sensors(bc_endpoint *, bc_string chassis_uri, const bc_redfish_collection_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API bc_status bc_redfish_get_collection(bc_endpoint *, bc_string uri, uint32_t collection_kind, const bc_redfish_collection_options *, bc_redfish_completion, void *, bc_redfish_operation **);
BC_REDFISH_API const bc_redfish_collection_info *bc_redfish_collection_info_get(const bc_redfish_operation *);
BC_REDFISH_API bc_status bc_redfish_cancel(bc_redfish_operation *);
BC_REDFISH_API void bc_redfish_retain(bc_redfish_operation *);
BC_REDFISH_API void bc_redfish_release(bc_redfish_operation *);
BC_REDFISH_API const bc_redfish_result *bc_redfish_result_get(const bc_redfish_operation *);
#ifdef __cplusplus
}
#endif
#endif

#include "redfish_json.h"
#include "sensor_json.h"
#include "network_json.h"
#include <inttypes.h>
#include <stdio.h>

static const char *const reset_names[] = {
    "On", "ForceOff", "GracefulShutdown", "GracefulRestart", "ForceRestart",
    "Nmi", "ForceOn", "PushPowerButton", "PowerCycle"
};
const char *bc_agent_reset_name(uint32_t type) { return type < sizeof(reset_names) / sizeof(reset_names[0]) ? reset_names[type] : NULL; }
static void string(yyjson_mut_doc *doc, yyjson_mut_val *out, const char *key, bc_string value) {
    yyjson_mut_obj_add_strncpy(doc, out, key, value.data ? value.data : "", (size_t)value.length);
}
static void json(yyjson_mut_doc *doc, yyjson_mut_val *out, const char *key, bc_bytes value) {
    if (!value.length) return;
    yyjson_doc *body = yyjson_read((const char *)value.data, (size_t)value.length, 0);
    if (body) { yyjson_mut_obj_add_val(doc, out, key, yyjson_val_mut_copy(doc, yyjson_doc_get_root(body))); yyjson_doc_free(body); }
}
void bc_agent_redfish_json(yyjson_mut_doc *doc, const bc_redfish_operation *op, const bc_redfish_result *r) {
    yyjson_mut_val *out = yyjson_mut_doc_get_root(doc);
    yyjson_mut_obj_add_uint(doc, out, "http_status", r->http_status);
    yyjson_mut_obj_add_uint(doc, out, "flags", r->flags);
    string(doc, out, "resource_uri", r->resource_uri);
    char revision[32]; snprintf(revision, sizeof(revision), "%" PRIu64, r->endpoint_revision);
    yyjson_mut_obj_add_strcpy(doc, out, "endpoint_revision", revision);
    if (r->kind == BC_REDFISH_SYSTEM && r->status == BC_OK) {
        string(doc, out, "id", r->id); string(doc, out, "name", r->name);
        string(doc, out, "raw_power_state", r->raw_power_state);
        const char *const states[] = {"Unknown", "On", "Off", "PoweringOn", "PoweringOff"};
        yyjson_mut_obj_add_str(doc, out, "power_state", r->power_state < 5 ? states[r->power_state] : "Unknown");
    }
    const bc_redfish_system_identity *identity = bc_redfish_system_identity_get(op);
    if (identity) {
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "identity", info);
        string(doc, info, "manufacturer", identity->manufacturer); string(doc, info, "model", identity->model);
        string(doc, info, "serial_number", identity->serial_number); string(doc, info, "uuid", identity->uuid);
        string(doc, info, "host_name", identity->host_name);
    }
    const bc_redfish_collection_info *collection = bc_redfish_collection_info_get(op);
    if (collection) {
        yyjson_mut_val *members = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, out, "members", members);
        for (uint32_t i = 0; i < collection->member_count; ++i)
            yyjson_mut_arr_add_strncpy(doc, members, collection->members[i].data, (size_t)collection->members[i].length);
    }
    if (r->redfish_version.length) string(doc, out, "redfish_version", r->redfish_version);
    const bc_redfish_reset_info *reset = bc_redfish_reset_info_get(op);
    if (reset) {
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "reset", info);
        string(doc, info, "target", reset->target);
        yyjson_mut_val *actions = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "supported_actions", actions);
        for (uint32_t i = 0; bc_agent_reset_name(i); ++i)
            if (reset->supported_reset_types & (UINT32_C(1) << i)) yyjson_mut_arr_add_str(doc, actions, bc_agent_reset_name(i));
    }
    const bc_redfish_boot_info *boot = bc_redfish_boot_info_get(op);
    if (boot) {
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "boot", info);
        yyjson_mut_obj_add_uint(doc, info, "target", boot->boot.target);
        yyjson_mut_obj_add_uint(doc, info, "mode", boot->boot.mode);
        yyjson_mut_obj_add_uint(doc, info, "flags", boot->boot.flags);
        yyjson_mut_obj_add_uint(doc, info, "supported_targets", boot->boot.supported_targets);
        yyjson_mut_obj_add_uint(doc, info, "supported_modes", boot->supported_modes);
    }
    const bc_redfish_graphical_console_info *console = bc_redfish_graphical_console_info_get(op);
    if (console) {
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "graphical_console", info);
        yyjson_mut_obj_add_uint(doc, info, "flags", console->flags);
        if (console->flags & BC_REDFISH_CONSOLE_SERVICE_ENABLED) yyjson_mut_obj_add_bool(doc, info, "service_enabled", console->service_enabled != 0);
        if (console->flags & BC_REDFISH_CONSOLE_PORT_PRESENT) yyjson_mut_obj_add_uint(doc, info, "port", console->port);
        if (console->flags & BC_REDFISH_CONSOLE_SESSIONS_PRESENT) yyjson_mut_obj_add_uint(doc, info, "max_sessions", console->max_sessions);
        yyjson_mut_val *types = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "connect_types", types);
        for (uint32_t i = 0; i < console->connect_type_count; ++i)
            yyjson_mut_arr_add_strncpy(doc, types, console->connect_types[i].data, (size_t)console->connect_types[i].length);
    }
    bc_agent_network_rows_json(doc, op);
    const bc_redfish_network_protocol_info *network = bc_redfish_network_protocol_info_get(op);
    if (network) {
        static const char *const protocol_names[] = {"NTP", "SSH", "SNMP", "HTTP", "HTTPS", "IPMI", "VirtualMedia", "KVMIP", "SSDP", "Telnet"};
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "network_protocol", info);
        yyjson_mut_val *rows = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "protocols", rows);
        for (uint32_t i = 0; i < BC_REDFISH_NETWORK_PROTOCOL_COUNT; ++i) {
            const bc_redfish_network_protocol_entry *entry = &network->protocols[i];
            yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(rows, row);
            yyjson_mut_obj_add_str(doc, row, "name", protocol_names[i]);
            if (entry->flags & BC_REDFISH_NET_PROTOCOL_SNMPV3) yyjson_mut_obj_add_bool(doc, row, "snmp_v3_only", true);
            if (entry->flags & BC_REDFISH_NET_PROTOCOL_ENABLED) {
                if (entry->null_flags & BC_REDFISH_NET_PROTOCOL_ENABLED_NULL) yyjson_mut_obj_add_null(doc, row, "enabled");
                else yyjson_mut_obj_add_bool(doc, row, "enabled", entry->enabled != 0);
            }
            if (entry->flags & BC_REDFISH_NET_PROTOCOL_PORT) {
                if (entry->null_flags & BC_REDFISH_NET_PROTOCOL_PORT_NULL) yyjson_mut_obj_add_null(doc, row, "port");
                else yyjson_mut_obj_add_uint(doc, row, "port", entry->port);
            }
        }
        yyjson_mut_val *servers = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "ntp_servers", servers);
        for (uint32_t i = 0; i < network->ntp_server_count; ++i)
            yyjson_mut_arr_add_strncpy(doc, servers, network->ntp_servers[i].data, (size_t)network->ntp_servers[i].length);
        yyjson_mut_val *supplied = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "ntp_network_supplied", supplied);
        for (uint32_t i = 0; i < network->ntp_network_supplied_count; ++i)
            yyjson_mut_arr_add_strncpy(doc, supplied, network->ntp_network_supplied[i].data, (size_t)network->ntp_network_supplied[i].length);
        if (network->null_flags & BC_REDFISH_NETWORK_HOST_NAME_NULL) yyjson_mut_obj_add_null(doc, info, "host_name");
        else if (network->host_name.length) string(doc, info, "host_name", network->host_name);
        if (network->null_flags & BC_REDFISH_NETWORK_FQDN_NULL) yyjson_mut_obj_add_null(doc, info, "fqdn");
        else if (network->fqdn.length) string(doc, info, "fqdn", network->fqdn);
    }
    const bc_redfish_ethernet_info *ethernet = bc_redfish_ethernet_info_get(op);
    if (ethernet) {
        static const struct { const char *key; uint32_t bit; } fields[] = {
            {"mac", BC_REDFISH_ETH_MAC},
            {"state", BC_REDFISH_ETH_STATUS_STATE},
            {"health", BC_REDFISH_ETH_STATUS_HEALTH},
            {"host_name", BC_REDFISH_ETH_HOST_NAME},
            {"fqdn", BC_REDFISH_ETH_FQDN},
            {"link_status", BC_REDFISH_ETH_LINK_STATUS},
            {"interface_mode", BC_REDFISH_ETH_MODE},
            {"ipv6_gateway", BC_REDFISH_ETH_IPV6_GATEWAY},
        };
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "ethernet_interface", info);
        string(doc, info, "id", r->id); string(doc, info, "name", r->name);
        for (uint32_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
            if (!(ethernet->flags & fields[i].bit)) continue;
            if (ethernet->null_flags & fields[i].bit) { yyjson_mut_obj_add_null(doc, info, fields[i].key); continue; }
            bc_string value = i == 0 ? ethernet->mac : i == 1 ? ethernet->state : i == 2 ? ethernet->health :
                i == 3 ? ethernet->host_name : i == 4 ? ethernet->fqdn : i == 5 ? ethernet->link_status :
                i == 6 ? ethernet->interface_mode : ethernet->ipv6_gateway;
            string(doc, info, fields[i].key, value);
        }
        static const struct { const char *key; uint32_t bit; } bool_fields[] = {
            {"dhcp4_enabled", BC_REDFISH_ETH_DHCP4_ENABLED},
            {"dhcp6_enabled", BC_REDFISH_ETH_DHCP6_ENABLED},
            {"interface_enabled", BC_REDFISH_ETH_INTERFACE_ENABLED},
            {"vlan_enabled", BC_REDFISH_ETH_VLAN_ENABLED},
        };
        for (uint32_t i = 0; i < sizeof(bool_fields) / sizeof(bool_fields[0]); ++i) {
            if (!(ethernet->flags & bool_fields[i].bit)) continue;
            if (ethernet->null_flags & bool_fields[i].bit) { yyjson_mut_obj_add_null(doc, info, bool_fields[i].key); continue; }
            uint32_t value = i == 0 ? ethernet->dhcp4_enabled : i == 1 ? ethernet->dhcp6_enabled :
                i == 2 ? ethernet->interface_enabled : ethernet->vlan_enabled;
            yyjson_mut_obj_add_bool(doc, info, bool_fields[i].key, value != 0);
        }
        const struct { const char *key; uint32_t bit, value; } numbers[] = {
            {"mtu", BC_REDFISH_ETH_MTU, ethernet->mtu},
            {"speed_mbps", BC_REDFISH_ETH_SPEED, ethernet->speed_mbps},
            {"vlan_id", BC_REDFISH_ETH_VLAN_ID, ethernet->vlan_id},
        };
        for (uint32_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); ++i) {
            if (!(ethernet->flags & numbers[i].bit)) continue;
            if (ethernet->null_flags & numbers[i].bit) yyjson_mut_obj_add_null(doc, info, numbers[i].key);
            else yyjson_mut_obj_add_uint(doc, info, numbers[i].key, numbers[i].value);
        }
        yyjson_mut_val *dns = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "name_servers", dns);
        for (uint32_t i = 0; i < ethernet->name_server_count; ++i)
            yyjson_mut_arr_add_strncpy(doc, dns, ethernet->name_servers[i].data, (size_t)ethernet->name_servers[i].length);
        yyjson_mut_val *ipv4 = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "ipv4_addresses", ipv4);
        for (uint32_t i = 0; i < ethernet->ipv4_count; ++i) {
            const bc_redfish_ipv4_entry *entry = &ethernet->ipv4[i];
            static const struct { const char *key; uint32_t bit; } ipv4_fields[] = {
                {"address", 1u}, {"subnet_mask", 2u}, {"gateway", 4u}, {"address_origin", 8u}
            };
            yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(ipv4, row);
            for (uint32_t n = 0; n < sizeof(ipv4_fields) / sizeof(ipv4_fields[0]); ++n) {
                if (!(entry->flags & ipv4_fields[n].bit)) continue;
                if (entry->null_flags & ipv4_fields[n].bit) { yyjson_mut_obj_add_null(doc, row, ipv4_fields[n].key); continue; }
                bc_string value = !n ? entry->address : n == 1 ? entry->subnet_mask : n == 2 ? entry->gateway : entry->address_origin;
                string(doc, row, ipv4_fields[n].key, value);
            }
        }
        yyjson_mut_val *ipv6 = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "ipv6_addresses", ipv6);
        for (uint32_t i = 0; i < ethernet->ipv6_count; ++i) {
            const bc_redfish_ipv6_entry *entry = &ethernet->ipv6[i];
            static const struct { const char *key; uint32_t bit; } ipv6_fields[] = {
                {"address", 1u}, {"address_origin", 4u}, {"address_state", 8u}
            };
            yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(ipv6, row);
            for (uint32_t n = 0; n < sizeof(ipv6_fields) / sizeof(ipv6_fields[0]); ++n) {
                if (!(entry->flags & ipv6_fields[n].bit)) continue;
                if (entry->null_flags & ipv6_fields[n].bit) { yyjson_mut_obj_add_null(doc, row, ipv6_fields[n].key); continue; }
                bc_string value = !n ? entry->address : n == 1 ? entry->address_origin : entry->address_state;
                string(doc, row, ipv6_fields[n].key, value);
            }
            if (entry->flags & 2u) yyjson_mut_obj_add_uint(doc, row, "prefix_length", entry->prefix_length);
        }
    }
    if (r->kind == BC_REDFISH_SENSOR_DETAILS) {
        bc_sensor_details details = {0}; details.struct_size = sizeof(details); details.abi_version = BC_ABI_VERSION;
        bc_redfish_sensor_details_get(op, &details);
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "sensor_details", info);
        bc_agent_sensor_details_json(doc, info, &details);
    }
    const bc_redfish_sensor_info *sensor = bc_redfish_sensor_info_get(op);
    if (sensor && r->status == BC_OK) {
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "sensor", info);
        string(doc, info, "id", r->id); string(doc, info, "name", r->name);
        yyjson_mut_obj_add_uint(doc, info, "flags", sensor->flags);
        if (sensor->flags & BC_SENSOR_READING_PRESENT) yyjson_mut_obj_add_real(doc, info, "reading", sensor->reading);
        else yyjson_mut_obj_add_null(doc, info, "reading");
        string(doc, info, "reading_type", sensor->reading_type); string(doc, info, "units", sensor->units);
        string(doc, info, "state", sensor->state); string(doc, info, "health", sensor->health);
        string(doc, info, "reading_time", sensor->reading_time);
        if (sensor->flags & BC_SENSOR_RANGE_MIN_PRESENT) yyjson_mut_obj_add_real(doc, info, "range_min", sensor->range_min);
        if (sensor->flags & BC_SENSOR_RANGE_MAX_PRESENT) yyjson_mut_obj_add_real(doc, info, "range_max", sensor->range_max);
        yyjson_mut_val *values = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "threshold_values", values);
        for (uint32_t i = 0; i < BC_SENSOR_THRESHOLD_COUNT; ++i) {
            if (sensor->threshold_mask & (UINT32_C(1) << i)) yyjson_mut_arr_add_real(doc, values, sensor->thresholds[i]);
            else yyjson_mut_arr_add_null(doc, values);
        }
        json(doc, info, "thresholds", sensor->thresholds_json);
    }
    const bc_redfish_task_info *task = bc_redfish_task_info_get(op);
    if (task && r->status == BC_OK) {
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "task", info);
        yyjson_mut_obj_add_uint(doc, info, "flags", task->flags);
        string(doc, info, "task_uri", task->task_uri); string(doc, info, "monitor_uri", task->monitor_uri);
        string(doc, info, "state", task->state); string(doc, info, "status", task->status);
        string(doc, info, "retry_after", task->retry_after);
        if (task->flags & BC_TASK_PERCENT_PRESENT) yyjson_mut_obj_add_uint(doc, info, "percent_complete", task->percent_complete);
        else yyjson_mut_obj_add_null(doc, info, "percent_complete");
        json(doc, info, "messages", task->messages_json); json(doc, info, "final_body", task->final_body);
        if (task->final_body.length) {
            char length[32]; snprintf(length, sizeof(length), "%" PRIu64, task->final_body.length);
            yyjson_mut_obj_add_strcpy(doc, info, "final_body_length", length);
        }
    }
    const bc_redfish_virtual_media_info *media = bc_redfish_virtual_media_info_get(op);
    if (media && r->status == BC_OK) {
        yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "media", info);
        yyjson_mut_obj_add_uint(doc, info, "flags", media->flags);
        string(doc, info, "id", media->id); string(doc, info, "name", media->name);
        string(doc, info, "image", media->image); string(doc, info, "image_name", media->image_name);
        string(doc, info, "connected_via", media->connected_via);
        if (media->flags & BC_REDFISH_VM_INSERTED_PRESENT)
            yyjson_mut_obj_add_bool(doc, info, "inserted", media->inserted != 0);
        else yyjson_mut_obj_add_null(doc, info, "inserted");
        yyjson_mut_obj_add_bool(doc, info, "write_protected", media->write_protected != 0);
        yyjson_mut_val *types = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "media_types", types);
        for (uint32_t i = 0; i < media->media_type_count; ++i)
            yyjson_mut_arr_add_strncpy(doc, types, media->media_types[i].data, (size_t)media->media_types[i].length);
    }
    json(doc, out, "device_error", r->error_body);
}

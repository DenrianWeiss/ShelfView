#include "bcontrol/redfish.h"
#include "bcontrol/transport.h"
#include "bcontrol/log.h"
#include "yyjson.h"
#include "sensor_json.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bc_string text(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
static int done;
static void completed(bc_redfish_operation *op, const bc_redfish_result *r, void *userdata) { (void)op; (void)r; (void)userdata; ++done; }
static void add(yyjson_mut_doc *doc, yyjson_mut_val *out, const char *key, bc_string value) {
    yyjson_mut_obj_add_strncpy(doc, out, key, value.data ? value.data : "", (size_t)value.length);
}
typedef struct { int done; uint32_t http; int token_ok; } auth_probe;
static void auth_completed(bc_request *request, const bc_response *response, void *userdata) {
    (void)request; auth_probe *probe = userdata; probe->http = response->http_status; probe->done = 1;
    bc_string token = bc_request_auth_token(request);
    probe->token_ok = token.length == 14 && !memcmp(token.data, "response-token", 14);
}
static int auth_isolation(bc_context *context, bc_endpoint *base) {
    bc_endpoint *endpoints[3] = {base, NULL, NULL}; bc_request *requests[3] = {NULL, NULL, NULL}; auth_probe probes[3] = {{0}};
    bc_auth_options auth = {0}; auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION;
    auth.mode = BC_AUTH_TOKEN; auth.token = text(getenv("BC_BMC_TOKEN"));
    bc_status status = bc_endpoint_with_auth(base, &auth, &endpoints[1]);
    auth.mode = BC_AUTH_NONE; auth.token = (bc_string){NULL, 0};
    if (status == BC_OK) status = bc_endpoint_with_auth(endpoints[1], &auth, &endpoints[2]);
    bc_http_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = text("/redfish/v1/"); options.timeout_ms = 3000;
    for (unsigned i = 0; status == BC_OK && i < 3; ++i)
        status = bc_http_submit(endpoints[i], &options, auth_completed, &probes[i], &requests[i]);
    int count = 0;
    while (status == BC_OK && count < 3) {
        status = bc_context_poll(context, 50); count = probes[0].done + probes[1].done + probes[2].done;
    }
    if (status != BC_OK) { bc_context_shutdown(context); bc_context_poll(context, 0); }
    printf("{\"completion_count\":%d,\"http_statuses\":[%u,%u,%u],\"isolated_revisions\":%s,\"response_tokens\":[%s,%s,%s]}\n", count,
        (unsigned)probes[0].http, (unsigned)probes[1].http, (unsigned)probes[2].http,
        bc_endpoint_revision(endpoints[0]) != bc_endpoint_revision(endpoints[1]) && bc_endpoint_revision(endpoints[1]) != bc_endpoint_revision(endpoints[2]) ? "true" : "false",
        probes[0].token_ok ? "true" : "false", probes[1].token_ok ? "true" : "false", probes[2].token_ok ? "true" : "false");
    for (unsigned i = 0; i < 3; ++i) bc_request_release(requests[i]);
    bc_endpoint_release(endpoints[1]); bc_endpoint_release(endpoints[2]);
    return status == BC_OK && count == 3 ? 0 : 2;
}
static void trace_transport(void *user, const bc_log_record *record) {
    (void)user;
    fprintf(stderr, "%.*s %.*s\n", (int)record->event.length, record->event.data,
        (int)record->detail.length, record->detail.data);
}
int main(int argc, char **argv) {
    if (argc < 4) return 2;
    if (getenv("BC_TEST_TRACE")) {
        bc_log_options options = {sizeof(options), BC_ABI_VERSION, BC_LOG_LEVEL_DEBUG,
            BC_LOG_CATEGORY_HTTP | BC_LOG_CATEGORY_TLS, trace_transport, NULL, 0};
        (void)bc_log_configure(&options);
    }
    bc_transport *transport = NULL; bc_context *context = NULL; bc_endpoint *endpoint = NULL; bc_redfish_operation *operation = NULL;
    bc_status status = bc_curl_transport_create(&transport);
    bc_context_options context_options = {sizeof(context_options), BC_ABI_VERSION, transport, 1024u * 1024u, 8, 0};
    if (status == BC_OK) status = bc_context_create(&context_options, &context);
    bc_endpoint_options endpoint_options = {0}; endpoint_options.struct_size = sizeof(endpoint_options); endpoint_options.abi_version = BC_ABI_VERSION;
    endpoint_options.device_id = text("test"); endpoint_options.endpoint_id = text("redfish"); endpoint_options.origin = text(argv[1]); endpoint_options.ca_file = text(argv[2]);
    endpoint_options.username = text(getenv("BC_BMC_USERNAME")); endpoint_options.password = text(getenv("BC_BMC_PASSWORD"));
    if (argc > 6) {
        if (!strcmp(argv[6], "skip-all")) endpoint_options.cert_policy = BC_CERT_SKIP_ALL;
        else if (!strcmp(argv[6], "skip-chain")) endpoint_options.cert_policy = BC_CERT_SKIP_CHAIN;
        else if (strcmp(argv[6], "strict")) { bc_context_destroy(context); bc_curl_transport_destroy(transport); return 2; }
    }
    if (status == BC_OK) status = bc_endpoint_create(context, &endpoint_options, &endpoint);
    if (status == BC_OK && !strcmp(argv[3], "auth-isolation")) {
        int result = auth_isolation(context, endpoint);
        bc_endpoint_release(endpoint); bc_context_destroy(context); bc_curl_transport_destroy(transport); return result;
    }
    bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, 3000, 0};
    if (argc > 5) options.max_systems = (uint32_t)strtoul(argv[5], NULL, 10);
    if (argc > 7) {
        char *end = NULL; errno = 0;
        unsigned long timeout = strtoul(argv[7], &end, 10);
        if (errno || !*argv[7] || *end || timeout == 0 || timeout > INT32_MAX) status = BC_INVALID_ARGUMENT;
        else options.request_timeout_ms = (uint32_t)timeout;
    }
    bc_redfish_collection_options collection_options = {sizeof(collection_options), BC_ABI_VERSION, options.request_timeout_ms, options.max_systems};
    if (status == BC_OK) {
        if (!strcmp(argv[3], "discover") || !strcmp(argv[3], "cancel")) status = bc_redfish_discover(endpoint, &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "tasks")) status = bc_redfish_discover_tasks(endpoint, &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "managers")) status = bc_redfish_discover_managers(endpoint, &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "network-protocol")) status = bc_redfish_get_network_protocol(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "ethernet")) status = bc_redfish_discover_ethernet(endpoint, text(argv[4]), &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "ethernet-interface")) status = bc_redfish_get_ethernet_interface(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "chassis")) status = bc_redfish_discover_chassis(endpoint, &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "sensors") || !strcmp(argv[3], "sensors-cancel")) status = bc_redfish_discover_sensors(endpoint, text(argv[4]), &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "collection-sensors")) status = bc_redfish_get_collection(endpoint, text(argv[4]), BC_COLLECTION_SENSORS, &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "collection-chassis")) status = bc_redfish_get_collection(endpoint, text(argv[4]), BC_COLLECTION_CHASSIS, &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "collection-tasks")) status = bc_redfish_get_collection(endpoint, text(argv[4]), BC_COLLECTION_TASKS, &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "collection-systems")) status = bc_redfish_get_collection(endpoint, text(argv[4]), BC_COLLECTION_SYSTEMS, &collection_options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "boot")) status = bc_redfish_get_boot(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "boot-cd")) status = bc_redfish_boot_set_once(endpoint, text(argv[4]), BC_BOOT_CD, BC_BOOT_MODE_PRESERVE, &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "boot-disable")) status = bc_redfish_boot_set_once(endpoint, text(argv[4]), BC_BOOT_NONE, BC_BOOT_MODE_PRESERVE, &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "capabilities")) status = bc_redfish_get_reset_capabilities(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "reset")) status = bc_redfish_reset(endpoint, text(argv[4]), BC_RESET_ON, &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "reset-off")) status = bc_redfish_reset(endpoint, text(argv[4]), BC_RESET_FORCE_OFF, &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "task")) status = bc_redfish_get_task(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "sensor")) status = bc_redfish_get_sensor(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "sensor-details")) status = bc_redfish_get_sensor_details(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "resource")) status = bc_redfish_get_resource(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "virtual-media")) status = bc_redfish_get_virtual_media(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "graphical-console")) status = bc_redfish_get_graphical_console(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "virtual-media-discover")) {
            bc_redfish_collection_options collections = {sizeof(collections), BC_ABI_VERSION, options.request_timeout_ms, options.max_systems};
            status = bc_redfish_discover_virtual_media(endpoint, text(argv[4]), &collections, completed, NULL, &operation);
        }
        else if (!strcmp(argv[3], "vm-insert")) {
            bc_redfish_virtual_media_insert_options insert = {0};
            insert.struct_size = sizeof(insert);
            insert.image = text("http://fixture.invalid/image.iso");
            insert.flags = BC_REDFISH_VM_WRITE_PROTECTED_SET;
            insert.write_protected = 1;
            status = bc_redfish_virtual_media_insert(endpoint, text(argv[4]), &insert, &options, completed, NULL, &operation);
        }
        else if (!strcmp(argv[3], "vm-eject")) status = bc_redfish_virtual_media_eject(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else if (!strcmp(argv[3], "monitor") || !strcmp(argv[3], "monitor-cancel")) status = bc_redfish_get_task_monitor(endpoint, text(argv[4]), &options, completed, NULL, &operation);
        else status = bc_redfish_get_system(endpoint, text(argc > 4 ? argv[4] : "/redfish/v1/Systems/host-A"), &options, completed, NULL, &operation);
    }
    if (status == BC_OK && (!strcmp(argv[3], "cancel") || !strcmp(argv[3], "monitor-cancel") || !strcmp(argv[3], "sensors-cancel"))) bc_redfish_cancel(operation);
    while (status == BC_OK && !done) status = bc_context_poll(context, 50);
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *out = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, out);
    const bc_redfish_result *r = bc_redfish_result_get(operation);
    yyjson_mut_obj_add_str(doc, out, "status", bc_status_string(r ? r->status : status));
    yyjson_mut_obj_add_uint(doc, out, "completion_count", (uint64_t)done);
    if (r) {
        yyjson_mut_obj_add_uint(doc, out, "http_status", r->http_status);
        yyjson_mut_obj_add_uint(doc, out, "power_state", r->power_state);
        yyjson_mut_obj_add_uint(doc, out, "flags", r->flags);
        const bc_redfish_boot_info *boot = bc_redfish_boot_info_get(operation);
        if (boot) {
            yyjson_mut_obj_add_uint(doc, out, "boot_target", boot->boot.target);
            yyjson_mut_obj_add_uint(doc, out, "boot_flags", boot->boot.flags);
            yyjson_mut_obj_add_uint(doc, out, "boot_targets", boot->boot.supported_targets);
        }
        const bc_redfish_resource_info *resource = bc_redfish_resource_info_get(operation);
        if (resource) {
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "resource", info);
            add(doc, info, "odata_type", resource->odata_type);
            add(doc, info, "json", (bc_string){(const char *)resource->json.data, resource->json.length});
            add(doc, info, "oem_json", (bc_string){(const char *)resource->oem_json.data, resource->oem_json.length});
        }
        const bc_redfish_collection_info *collection = bc_redfish_collection_info_get(operation);
        if (collection) {
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "collection", info);
            yyjson_mut_obj_add_uint(doc, info, "kind", collection->collection_kind);
            yyjson_mut_val *members = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "members", members);
            for (uint32_t i = 0; i < collection->member_count; ++i) yyjson_mut_arr_add_strncpy(doc, members, collection->members[i].data, (size_t)collection->members[i].length);
        }
        const bc_redfish_graphical_console_info *console = bc_redfish_graphical_console_info_get(operation);
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
        const bc_redfish_network_protocol_info *network = bc_redfish_network_protocol_info_get(operation);
        if (network) {
            static const char *const protocol_names[] = {"NTP", "SSH", "SNMP", "HTTP", "HTTPS", "IPMI", "VirtualMedia", "KVMIP", "SSDP", "Telnet"};
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "network_protocol", info);
            yyjson_mut_val *rows = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "protocols", rows);
            for (uint32_t i = 0; i < BC_REDFISH_NETWORK_PROTOCOL_COUNT; ++i) {
                const bc_redfish_network_protocol_entry *entry = &network->protocols[i];
                yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(rows, row);
                yyjson_mut_obj_add_str(doc, row, "name", protocol_names[i]);
                yyjson_mut_obj_add_uint(doc, row, "flags", entry->flags);
                yyjson_mut_obj_add_uint(doc, row, "null_flags", entry->null_flags);
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
            else add(doc, info, "host_name", network->host_name);
            if (network->null_flags & BC_REDFISH_NETWORK_FQDN_NULL) yyjson_mut_obj_add_null(doc, info, "fqdn");
            else add(doc, info, "fqdn", network->fqdn);
        }
        const bc_redfish_ethernet_info *ethernet = bc_redfish_ethernet_info_get(operation);
        if (ethernet) {
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "ethernet_interface", info);
            yyjson_mut_obj_add_uint(doc, info, "flags", ethernet->flags);
            yyjson_mut_obj_add_uint(doc, info, "null_flags", ethernet->null_flags);
            yyjson_mut_val *ipv4 = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "ipv4", ipv4);
            for (uint32_t i = 0; i < ethernet->ipv4_count; ++i) {
                const bc_redfish_ipv4_entry *entry = &ethernet->ipv4[i];
                yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(ipv4, row);
                yyjson_mut_obj_add_uint(doc, row, "flags", entry->flags);
                yyjson_mut_obj_add_uint(doc, row, "null_flags", entry->null_flags);
                add(doc, row, "address", entry->address); add(doc, row, "subnet_mask", entry->subnet_mask);
                add(doc, row, "gateway", entry->gateway); add(doc, row, "address_origin", entry->address_origin);
            }
            yyjson_mut_val *ipv6 = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "ipv6", ipv6);
            for (uint32_t i = 0; i < ethernet->ipv6_count; ++i) {
                const bc_redfish_ipv6_entry *entry = &ethernet->ipv6[i];
                yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(ipv6, row);
                yyjson_mut_obj_add_uint(doc, row, "flags", entry->flags);
                yyjson_mut_obj_add_uint(doc, row, "null_flags", entry->null_flags);
                add(doc, row, "address", entry->address); add(doc, row, "address_origin", entry->address_origin);
                add(doc, row, "address_state", entry->address_state);
                if (entry->flags & 2u) yyjson_mut_obj_add_uint(doc, row, "prefix_length", entry->prefix_length);
            }
            yyjson_mut_obj_add_uint(doc, info, "dhcp4_enabled", ethernet->dhcp4_enabled);
            yyjson_mut_obj_add_uint(doc, info, "dhcp6_enabled", ethernet->dhcp6_enabled);
            yyjson_mut_obj_add_uint(doc, info, "interface_enabled", ethernet->interface_enabled);
            add(doc, info, "mac", ethernet->mac); add(doc, info, "state", ethernet->state); add(doc, info, "health", ethernet->health);
            add(doc, info, "host_name", ethernet->host_name); add(doc, info, "fqdn", ethernet->fqdn); add(doc, info, "link_status", ethernet->link_status);
        }
        const bc_redfish_reset_info *reset = bc_redfish_reset_info_get(operation);
        if (reset) {
            yyjson_mut_obj_add_uint(doc, out, "supported_reset_types", reset->supported_reset_types);
            add(doc, out, "reset_target", reset->target);
        }
        const bc_redfish_task_info *task = bc_redfish_task_info_get(operation);
        if (task) {
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "task", info);
            yyjson_mut_obj_add_uint(doc, info, "flags", task->flags);
            yyjson_mut_obj_add_uint(doc, info, "percent_complete", task->percent_complete);
            yyjson_mut_obj_add_uint(doc, info, "final_body_length", task->final_body.length);
            add(doc, info, "task_uri", task->task_uri); add(doc, info, "monitor_uri", task->monitor_uri);
            add(doc, info, "state", task->state); add(doc, info, "status", task->status); add(doc, info, "retry_after", task->retry_after);
            add(doc, info, "messages_json", (bc_string){(const char *)task->messages_json.data, task->messages_json.length});
        }
        const bc_redfish_virtual_media_info *media = bc_redfish_virtual_media_info_get(operation);
        if (media) {
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "virtual_media", info);
            yyjson_mut_obj_add_uint(doc, info, "flags", media->flags);
            yyjson_mut_obj_add_uint(doc, info, "inserted", media->inserted);
            yyjson_mut_obj_add_uint(doc, info, "write_protected", media->write_protected);
            add(doc, info, "id", media->id); add(doc, info, "name", media->name);
            add(doc, info, "image", media->image); add(doc, info, "image_name", media->image_name);
            add(doc, info, "connected_via", media->connected_via);
            add(doc, info, "insert_target", media->insert_target); add(doc, info, "eject_target", media->eject_target);
        }
        const bc_redfish_context_info *context_info = bc_redfish_context_info_get(operation);
        if (context_info) {
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "context", info);
            yyjson_mut_obj_add_str(doc, info, "status", bc_status_string(context_info->status));
            yyjson_mut_obj_add_uint(doc, info, "flags", context_info->flags);
            yyjson_mut_obj_add_uint(doc, info, "enabled", context_info->enabled);
            add(doc, info, "sensor_collection_uri", context_info->sensor_collection_uri); add(doc, info, "thermal_uri", context_info->thermal_uri);
            add(doc, info, "physical_context", context_info->physical_context); add(doc, info, "reading_basis", context_info->reading_basis);
            const bc_string *lists[] = {context_info->related_items, context_info->chassis, context_info->systems};
            uint32_t counts[] = {context_info->related_count, context_info->chassis_count, context_info->system_count};
            const char *names[] = {"related_items", "chassis", "systems"};
            for (unsigned n = 0; n < 3; ++n) {
                yyjson_mut_val *array = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, names[n], array);
                for (uint32_t j = 0; j < counts[n]; ++j) yyjson_mut_arr_add_strncpy(doc, array, lists[n][j].data, (size_t)lists[n][j].length);
            }
        }
        if (r->kind == BC_REDFISH_SENSOR_DETAILS) {
            bc_sensor_details details = {0}; details.struct_size = sizeof(details); details.abi_version = BC_ABI_VERSION;
            bc_redfish_sensor_details_get(operation, &details);
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "sensor_details", info);
            bc_agent_sensor_details_json(doc, info, &details);
        }
        const bc_redfish_sensor_info *sensor = bc_redfish_sensor_info_get(operation);
        if (sensor) {
            yyjson_mut_val *info = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "sensor", info);
            bc_temperature_reading temperature = {0};
            bc_status temperature_status = bc_redfish_sensor_temperature_reading(operation, 1, &temperature);
            yyjson_mut_val *converted = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "temperature", converted);
            yyjson_mut_obj_add_str(doc, converted, "status", bc_status_string(temperature_status));
            yyjson_mut_obj_add_uint(doc, converted, "flags", temperature.flags); yyjson_mut_obj_add_uint(doc, converted, "unit", temperature.unit);
            yyjson_mut_obj_add_uint(doc, info, "flags", sensor->flags);
            if (sensor->flags & BC_SENSOR_READING_PRESENT) yyjson_mut_obj_add_real(doc, info, "reading", sensor->reading);
            else yyjson_mut_obj_add_null(doc, info, "reading");
            if (sensor->flags & BC_SENSOR_RANGE_MIN_PRESENT) yyjson_mut_obj_add_real(doc, info, "range_min", sensor->range_min);
            if (sensor->flags & BC_SENSOR_RANGE_MAX_PRESENT) yyjson_mut_obj_add_real(doc, info, "range_max", sensor->range_max);
            add(doc, info, "reading_type", sensor->reading_type); add(doc, info, "units", sensor->units);
            add(doc, info, "health", sensor->health); add(doc, info, "state", sensor->state); add(doc, info, "reading_time", sensor->reading_time);
            yyjson_mut_obj_add_uint(doc, info, "threshold_mask", sensor->threshold_mask);
            yyjson_mut_val *thresholds = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, info, "thresholds", thresholds);
            for (uint32_t i = 0; i < BC_SENSOR_THRESHOLD_COUNT; ++i) {
                if (sensor->threshold_mask & (UINT32_C(1) << i)) yyjson_mut_arr_add_real(doc, thresholds, sensor->thresholds[i]);
                else yyjson_mut_arr_add_null(doc, thresholds);
            }
            add(doc, info, "thresholds_json", (bc_string){(const char *)sensor->thresholds_json.data, sensor->thresholds_json.length});
        }
        const bc_redfish_system_identity *identity = bc_redfish_system_identity_get(operation);
        if (identity) {
            add(doc, out, "manufacturer", identity->manufacturer); add(doc, out, "model", identity->model);
            add(doc, out, "serial_number", identity->serial_number); add(doc, out, "uuid", identity->uuid);
            add(doc, out, "host_name", identity->host_name);
        }
        add(doc, out, "raw_power_state", r->raw_power_state); add(doc, out, "resource_uri", r->resource_uri);
        add(doc, out, "redfish_version", r->redfish_version); add(doc, out, "id", r->id);
        yyjson_mut_val *systems = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, out, "systems", systems);
        for (uint32_t i = 0; i < r->system_count; ++i) yyjson_mut_arr_add_strncpy(doc, systems, r->systems[i].data, (size_t)r->systems[i].length);
        if (r->error_body.length) yyjson_mut_obj_add_uint(doc, out, "error_body_length", r->error_body.length);
    }
    char *json = yyjson_mut_write(doc, 0, NULL); if (json) { puts(json); free(json); }
    yyjson_mut_doc_free(doc);
    if (operation) bc_redfish_release(operation);
    if (endpoint) bc_endpoint_release(endpoint);
    if (context) bc_context_destroy(context);
    if (transport) bc_curl_transport_destroy(transport);
    return status == BC_OK && done == 1 ? 0 : 2;
}

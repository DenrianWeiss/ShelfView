#include "../adapters/irmc/remote_media.h"
#include "bcontrol/redfish.h"
#include "bcontrol/inspur.h"
#include "bcontrol/redfish_task_reference.h"
#include "redfish_internal.h"
#include "endpoint_internal.h"
#include "../adapters/inspur/redfish.h"
#include "sensor_internal.h"
#include "log_internal.h"
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct bc_redfish_operation {
    bc_endpoint *endpoint;
    bc_request *request;
    bc_redfish_options options;
    bc_redfish_completion callback;
    void *userdata;
    bc_redfish_result result;
    bc_redfish_system_identity identity;
    bc_string *members;
    char *pages[64];
    bc_redfish_reset_info reset;
    bc_redfish_boot_info boot;
    uint32_t boot_target, boot_mode;
    bc_redfish_task_info task;
    bc_bytes task_identity;
    uint32_t submitted_method;
    bc_redfish_sensor_info sensor;
    bc_sensor_details sensor_details;
    bc_redfish_context_info context;
    bc_redfish_collection_info collection;
    bc_redfish_resource_info resource;
    bc_redfish_virtual_media_info media;
    bc_string *media_types;
    bc_redfish_graphical_console_info console;
    bc_string *console_types;
    bc_redfish_virtual_media_insert_options insert;
    bc_redfish_network_protocol_info network;
    bc_redfish_ethernet_info ethernet;
    uint32_t reset_type;
    char irmc_media_system[1025];
    bc_string irmc_media_etag;
    int irmc_media_active;
    uint32_t refs, page_count, phase;
    int done;
};
#define PHASE_ROOT 0u
#define PHASE_COLLECTION 1u
#define PHASE_SYSTEM 2u
#define PHASE_RESET_SYSTEM 3u
#define PHASE_ACTION_INFO 4u
#define PHASE_RESET_POST 5u
#define PHASE_TASK 6u
#define PHASE_TASK_MONITOR 7u
#define PHASE_SENSOR 8u
#define PHASE_CHASSIS 9u
#define PHASE_RESOURCE 10u
#define PHASE_ACTION_POST 11u
#define PHASE_PATCH 12u
#define PHASE_PROBE 13u
#define PHASE_VM_READ 14u
#define PHASE_VM_POST 15u
#define PHASE_VM_MANAGER 16u
#define PHASE_GRAPHICAL_CONSOLE 17u
#define PHASE_TASK_SERVICE 18u
#define PHASE_BOOT_READ 19u
#define PHASE_BOOT_VERIFY 20u
#define PHASE_MANAGER_LINK 21u
#define PHASE_NETWORK_PROTOCOL 22u
#define PHASE_ETHERNET 23u
#define PHASE_INSPUR_PAGE 24u
#define PHASE_INSPUR_SCRIPT 25u
#define PHASE_IRMC_VM_DISCOVERY 26u
#define PHASE_IRMC_VM_SYSTEM 27u
#define PHASE_IRMC_VM_PATCH 28u
#define PHASE_IRMC_VM_CONNECT 29u
#define PHASE_VM_INSERT_INFO 30u

#define VM_PARAM_INSERTED 1u
#define VM_PARAM_WRITE_PROTECTED 2u
#define VM_PARAM_TRANSFER_METHOD 4u
#define VM_PARAM_TRANSFER_PROTOCOL 8u
#define VM_PARAM_DEFAULTS (VM_PARAM_INSERTED | VM_PARAM_WRITE_PROTECTED | VM_PARAM_TRANSFER_METHOD | VM_PARAM_TRANSFER_PROTOCOL)

static const char *const reset_names[] = {
    "On", "ForceOff", "GracefulShutdown", "GracefulRestart", "ForceRestart",
    "Nmi", "ForceOn", "PushPowerButton", "PowerCycle"
};
static const char *const collection_names[] = {
    "ComputerSystemCollection", "ChassisCollection", "SensorCollection", "TaskCollection", "VirtualMediaCollection",
    "ManagerCollection", "EthernetInterfaceCollection"
};

static bc_string str(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
static bc_string copy(bc_string value) {
    char *p = malloc((size_t)value.length + 1);
    if (!p) return (bc_string){NULL, 0};
    if (value.length) memcpy(p, value.data, (size_t)value.length);
    p[value.length] = 0; return (bc_string){p, value.length};
}
static const char *json_string(yyjson_val *v, size_t max) {
    const char *s = yyjson_get_str(v);
    return s && yyjson_get_len(v) <= max && strlen(s) == yyjson_get_len(v) ? s : NULL;
}
int bc_redfish_uri_valid(bc_string uri) {
    if (!uri.data || uri.length < 12 || uri.length > 8192 || memcmp(uri.data, "/redfish/v1/", 12) || memchr(uri.data, 0, (size_t)uri.length)) return 0;
    for (uint64_t i = 0; i < uri.length; ++i) {
        unsigned char c = (unsigned char)uri.data[i];
        if (c <= 32 || c == 127 || c == '\\' || c == '#') return 0;
    }
    uint64_t start = 0;
    for (uint64_t i = 0; i <= uri.length; ++i) {
        if (i == uri.length || uri.data[i] == '/' || uri.data[i] == '?') {
            uint64_t n = i - start;
            if ((n == 1 && uri.data[start] == '.') || (n == 2 && !memcmp(uri.data + start, "..", 2))) return 0;
            if (i < uri.length && uri.data[i] == '?') break;
            start = i + 1;
        } else if (uri.data[i] == '%') {
            /* Encoded path separators/dot segments are outside this URI subset. */
            return 0;
        }
    }
    return 1;
}
uint32_t bc_redfish_uri_supported(bc_string uri) { return (uint32_t)bc_redfish_uri_valid(uri); }
void bc_redfish_retain(bc_redfish_operation *op) { if (op) ++op->refs; }
void bc_redfish_release(bc_redfish_operation *op) {
    if (!op || --op->refs) return;
    for (uint32_t i = 0; i < op->collection.member_count; ++i) free((void *)op->members[i].data);
    for (uint32_t i = 0; i < op->page_count; ++i) free(op->pages[i]);
    free(op->members); free((void *)op->result.resource_uri.data); free((void *)op->result.redfish_version.data);
    free((void *)op->result.id.data); free((void *)op->result.name.data); free((void *)op->result.raw_power_state.data);
    free((void *)op->identity.manufacturer.data); free((void *)op->identity.model.data);
    free((void *)op->identity.serial_number.data); free((void *)op->identity.uuid.data); free((void *)op->identity.host_name.data);
    free((void *)op->reset.target.data);
    free((void *)op->task.task_uri.data); free((void *)op->task.monitor_uri.data);
    free((void *)op->task.state.data); free((void *)op->task.status.data); free((void *)op->task.retry_after.data);
    free((void *)op->task_identity.data);
    free((void *)op->task.messages_json.data); free((void *)op->task.final_body.data);
    bc_redfish_clear_sensor(&op->sensor); bc_redfish_clear_context(&op->context);
    free((void *)op->resource.odata_type.data); free((void *)op->resource.json.data); free((void *)op->resource.oem_json.data);
    free((void *)op->media.id.data); free((void *)op->media.name.data); free((void *)op->media.image.data);
    free((void *)op->media.image_name.data); free((void *)op->media.connected_via.data);
    free((void *)op->media.insert_target.data); free((void *)op->media.eject_target.data);
    for (uint32_t i = 0; i < op->console.connect_type_count; ++i) free((void *)op->console_types[i].data);
    free(op->console_types);
    for (uint32_t i = 0; i < op->media.media_type_count; ++i) free((void *)op->media_types[i].data);
    free(op->media_types);
    free((void *)op->insert.image.data); free((void *)op->insert.transfer_method.data);
    free((void *)op->insert.transfer_protocol_type.data);
    free((void *)op->network.host_name.data); free((void *)op->network.fqdn.data);
    for (uint32_t i = 0; i < op->network.ntp_server_count; ++i) free((void *)op->network.ntp_servers[i].data);
    for (uint32_t i = 0; i < op->network.ntp_network_supplied_count; ++i) free((void *)op->network.ntp_network_supplied[i].data);
    free((void *)op->ethernet.mac.data); free((void *)op->ethernet.state.data); free((void *)op->ethernet.health.data);
    free((void *)op->ethernet.host_name.data); free((void *)op->ethernet.fqdn.data); free((void *)op->ethernet.link_status.data);
    for (uint32_t i = 0; i < op->ethernet.ipv4_count; ++i) {
        free((void *)op->ethernet.ipv4[i].address.data); free((void *)op->ethernet.ipv4[i].subnet_mask.data);
        free((void *)op->ethernet.ipv4[i].gateway.data); free((void *)op->ethernet.ipv4[i].address_origin.data);
    }
    for (uint32_t i = 0; i < op->ethernet.ipv6_count; ++i) {
        free((void *)op->ethernet.ipv6[i].address.data); free((void *)op->ethernet.ipv6[i].address_origin.data);
        free((void *)op->ethernet.ipv6[i].address_state.data);
    }
    free((void *)op->irmc_media_etag.data);
    free((void *)op->result.error_body.data); bc_endpoint_release(op->endpoint); free(op);
}
const bc_redfish_system_identity *bc_redfish_system_identity_get(const bc_redfish_operation *op) {
    return op && op->done && op->result.status == BC_OK && op->result.kind == BC_REDFISH_SYSTEM ? &op->identity : NULL;
}
const bc_redfish_result *bc_redfish_result_get(const bc_redfish_operation *op) { return op && op->done ? &op->result : NULL; }
const bc_redfish_resource_info *bc_redfish_resource_info_get(const bc_redfish_operation *op) {
    return op && op->done && op->result.status == BC_OK &&
        (op->result.kind == BC_REDFISH_RESOURCE || op->result.kind == BC_REDFISH_ACTION ||
         op->result.kind == BC_REDFISH_PATCH || op->result.kind == BC_REDFISH_PROBE)
        ? &op->resource : NULL;
}
const bc_redfish_boot_info *bc_redfish_boot_info_get(const bc_redfish_operation *op) {
    return op && op->done && op->boot.struct_size && (op->result.kind == BC_REDFISH_BOOT || op->result.kind == BC_REDFISH_BOOT_ONCE) ? &op->boot : NULL;
}
const bc_redfish_reset_info *bc_redfish_reset_info_get(const bc_redfish_operation *op) {
    return op && op->done && (op->result.kind == BC_REDFISH_RESET_CAPABILITIES || op->result.kind == BC_REDFISH_RESET) ? &op->reset : NULL;
}
const bc_redfish_task_info *bc_redfish_task_info_get(const bc_redfish_operation *op) {
    return op && op->done && (op->result.kind == BC_REDFISH_TASK || op->result.kind == BC_REDFISH_TASK_MONITOR ||
        ((op->phase == PHASE_RESET_POST || op->phase == PHASE_VM_POST) && op->result.http_status == 202) ||
        ((op->result.kind == BC_REDFISH_ACTION || op->result.kind == BC_REDFISH_BOOT_ONCE) && (op->result.flags & BC_REDFISH_COMMAND_ACCEPTED))) ? &op->task : NULL;
}
bc_status bc_redfish_sensor_temperature_reading(const bc_redfish_operation *op, uint32_t allow_cpu, bc_temperature_reading *out) {
    if (!op || !out || allow_cpu > 1 || !op->done || op->result.status != BC_OK || op->result.kind != BC_REDFISH_SENSOR) return BC_INVALID_ARGUMENT;
    *out = (bc_temperature_reading){0};
    if (op->context.status != BC_OK) return op->context.status;
    return bc_redfish_temperature(&op->sensor, &op->context, allow_cpu, out);
}
const bc_redfish_context_info *bc_redfish_context_info_get(const bc_redfish_operation *op) {
    return op && op->done && op->result.status == BC_OK &&
        (op->result.kind == BC_REDFISH_SENSOR || op->result.kind == BC_REDFISH_SYSTEM || op->result.kind == BC_REDFISH_RESOURCE) ? &op->context : NULL;
}
const bc_redfish_sensor_info *bc_redfish_sensor_info_get(const bc_redfish_operation *op) {
    return op && op->done && op->result.kind == BC_REDFISH_SENSOR ? &op->sensor : NULL;
}
bc_status bc_redfish_sensor_details_get(const bc_redfish_operation *op, bc_sensor_details *out) {
    if (!op || !op->done || op->result.kind != BC_REDFISH_SENSOR_DETAILS || !bc_sensor_details_valid(out)) return BC_INVALID_ARGUMENT;
    *out = op->sensor_details;
    if (!out->struct_size || op->result.status != BC_OK) {
        bc_sensor_details_reset(out); bc_sensor_details_error(out, op->result.status);
    }
    return out->status;
}
const bc_redfish_graphical_console_info *bc_redfish_graphical_console_info_get(const bc_redfish_operation *op) {
    return op && op->done && op->result.status == BC_OK && op->result.kind == BC_REDFISH_GRAPHICAL_CONSOLE ? &op->console : NULL;
}
const bc_redfish_network_protocol_info *bc_redfish_network_protocol_info_get(const bc_redfish_operation *op) {
    return op && op->done && op->result.status == BC_OK && op->result.kind == BC_REDFISH_NETWORK_PROTOCOL ? &op->network : NULL;
}
const bc_redfish_ethernet_info *bc_redfish_ethernet_info_get(const bc_redfish_operation *op) {
    return op && op->done && op->result.status == BC_OK && op->result.kind == BC_REDFISH_ETHERNET_INTERFACE ? &op->ethernet : NULL;
}
const bc_redfish_virtual_media_info *bc_redfish_virtual_media_info_get(const bc_redfish_operation *op) {
    /* Slot details stay readable when the resource lacks both standard media actions
     * (status UNSUPPORTED); callers gate writes on the action flags. */
    return op && op->done && (op->result.status == BC_OK || op->result.status == BC_UNSUPPORTED) &&
        (op->result.kind == BC_REDFISH_VIRTUAL_MEDIA || op->result.kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT ||
         op->result.kind == BC_REDFISH_VIRTUAL_MEDIA_EJECT) ? &op->media : NULL;
}
const bc_redfish_collection_info *bc_redfish_collection_info_get(const bc_redfish_operation *op) {
    return op && op->done && op->collection.members ? &op->collection : NULL;
}
bc_status bc_redfish_cancel(bc_redfish_operation *op) {
    if (!op) return BC_INVALID_ARGUMENT;
    return !op->done && op->request ? bc_request_cancel(op->request) : BC_OK;
}
static void finish(bc_redfish_operation *op, bc_status status) {
    if (op->phase == PHASE_BOOT_VERIFY && status != BC_OK) status = BC_OUTCOME_UNKNOWN;
    if (op->phase == PHASE_VM_POST && status != BC_OK && (op->result.flags & BC_REDFISH_COMMAND_SUBMITTED)) {
        uint32_t http = op->result.http_status;
        int rejected = status == BC_HTTP_ERROR && (http == 401 || http == 403 || http == 404 || http == 405);
        if (!rejected) op->result.flags |= BC_REDFISH_COMMAND_UNCONFIRMED;
    }
    op->done = 1; op->result.status = status;
    if (status == BC_OK)
        BC_LOG_INFO(BC_LOG_CATEGORY_REDFISH, "redfish.finish", "kind=%u phase=%u status=ok http=%u",
            op->result.kind, op->phase, op->result.http_status);
    else
        BC_LOG_WARN(BC_LOG_CATEGORY_REDFISH, "redfish.finish", "kind=%u phase=%u status=%s http=%u",
            op->result.kind, op->phase, bc_status_string(status), op->result.http_status);
    op->callback(op, &op->result, op->userdata); bc_redfish_release(op);
}
static void http_done(bc_request *, const bc_response *, void *);
static bc_status get(bc_redfish_operation *op, const char *uri) {
    if (!bc_redfish_uri_valid(str(uri))) return BC_UNSUPPORTED;
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = str(uri); options.timeout_ms = op->options.request_timeout_ms;
    return bc_http_submit(op->endpoint, &options, http_done, op, &op->request);
}
static bc_status get_inspur_asset(bc_redfish_operation *op, int script) {
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = str(script ? "/js/signin.js" : "/index.html");
    options.timeout_ms = op->options.request_timeout_ms;
    return bc_http_submit(op->endpoint, &options, http_done, op, &op->request);
}
static bc_status add_page(bc_redfish_operation *op, const char *uri) {
    if (!bc_redfish_uri_valid(str(uri))) return BC_UNSUPPORTED;
    if (op->page_count == 64) return BC_LIMIT_EXCEEDED;
    for (uint32_t i = 0; i < op->page_count; ++i) if (!strcmp(op->pages[i], uri)) return BC_PROTOCOL_ERROR;
    bc_string s = copy(str(uri));
    if (!s.data) return BC_NO_MEMORY;
    op->pages[op->page_count++] = (char *)s.data;
    return get(op, s.data);
}
static bc_status set_string(bc_string *out, yyjson_val *v, size_t limit, int required) {
    /* DMTF resources may serialize absent optional strings as JSON null (iBMC does this for
     * Image/ImageName on empty virtual media slots); treat null as absent. */
    if (yyjson_is_null(v)) v = NULL;
    if (!v && !required) return BC_OK;
    const char *value = json_string(v, limit);
    if (!value || (required && !*value)) return BC_PROTOCOL_ERROR;
    *out = copy(str(value)); return out->data ? BC_OK : BC_NO_MEMORY;
}
static bc_status collection(bc_redfish_operation *op, yyjson_val *root) {
    yyjson_val *members = yyjson_obj_get(root, "Members");
    if (!yyjson_is_arr(members)) return BC_PROTOCOL_ERROR;
    size_t i, maximum; yyjson_val *item;
    yyjson_arr_foreach(members, i, maximum, item) {
        const char *uri = json_string(yyjson_obj_get(item, "@odata.id"), 8192);
        if (!uri) return BC_PROTOCOL_ERROR;
        if (!bc_redfish_uri_valid(str(uri))) return BC_UNSUPPORTED;
        int duplicate = 0;
        for (uint32_t n = 0; n < op->collection.member_count; ++n) if (!strcmp(op->members[n].data, uri)) { duplicate = 1; break; }
        if (duplicate) continue;
        if (op->collection.member_count >= op->options.max_systems) return BC_LIMIT_EXCEEDED;
        bc_string owned = copy(str(uri));
        if (!owned.data) return BC_NO_MEMORY;
        op->members[op->collection.member_count++] = owned;
        if (op->result.kind == BC_REDFISH_DISCOVERY) op->result.system_count = op->collection.member_count;
    }
    BC_LOG_DEBUG(BC_LOG_CATEGORY_REDFISH, "redfish.collection", "kind=%u phase=%u members=%u",
        op->result.kind, op->phase, op->collection.member_count);
    return BC_OK;
}
static bc_status system_result(bc_redfish_operation *op, yyjson_val *root) {
    bc_status status = set_string(&op->result.id, yyjson_obj_get(root, "Id"), 1024, 0);
    if (status == BC_OK) status = set_string(&op->result.name, yyjson_obj_get(root, "Name"), 4096, 0);
    static const char *keys[] = {"Manufacturer", "Model", "SerialNumber", "UUID", "HostName"};
    bc_string *values[] = {&op->identity.manufacturer, &op->identity.model, &op->identity.serial_number, &op->identity.uuid, &op->identity.host_name};
    for (size_t i = 0; status == BC_OK && i < sizeof(keys) / sizeof(keys[0]); ++i) {
        yyjson_val *value = yyjson_obj_get(root, keys[i]);
        if (!yyjson_is_null(value)) status = set_string(values[i], value, 4096, 0);
    }
    yyjson_val *power_value = yyjson_obj_get(root, "PowerState");
    if (status == BC_OK && !yyjson_is_null(power_value)) status = set_string(&op->result.raw_power_state, power_value, 128, 0);
    if (status != BC_OK) return status;
    const char *power = op->result.raw_power_state.data;
    if (power) {
        if (!strcmp(power, "On")) op->result.power_state = BC_POWER_ON;
        else if (!strcmp(power, "Off")) op->result.power_state = BC_POWER_OFF;
        else if (!strcmp(power, "PoweringOn")) op->result.power_state = BC_POWERING_ON;
        else if (!strcmp(power, "PoweringOff")) op->result.power_state = BC_POWERING_OFF;
    }
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_INFO
    char manufacturer[BC_LOG_TEXT_MAX], model[BC_LOG_TEXT_MAX];
    bc_log_text(manufacturer, sizeof(manufacturer), op->identity.manufacturer.data, op->identity.manufacturer.length);
    bc_log_text(model, sizeof(model), op->identity.model.data, op->identity.model.length);
    BC_LOG_INFO(BC_LOG_CATEGORY_REDFISH, "redfish.system", "manufacturer=%s model=%s power_state=%u",
        manufacturer[0] ? manufacturer : "-", model[0] ? model : "-", op->result.power_state);
#endif
    return BC_OK;
}
static bc_status reset_values(bc_redfish_operation *op, yyjson_val *values) {
    if (!values) return BC_UNSUPPORTED;
    if (!yyjson_is_arr(values)) return BC_PROTOCOL_ERROR;
    if (yyjson_arr_size(values) > 128) return BC_LIMIT_EXCEEDED;
    size_t i, count; yyjson_val *item;
    yyjson_arr_foreach(values, i, count, item) {
        if (yyjson_is_null(item)) continue;
        const char *name = json_string(item, 128);
        if (!name || !*name) return BC_PROTOCOL_ERROR;
        for (uint32_t n = 0; n < sizeof(reset_names) / sizeof(reset_names[0]); ++n)
            if (!strcmp(name, reset_names[n])) op->reset.supported_reset_types |= UINT32_C(1) << n;
    }
    return BC_OK;
}
static bc_status action_info(bc_redfish_operation *op, yyjson_val *root) {
    yyjson_val *parameters = yyjson_obj_get(root, "Parameters"), *values = NULL;
    if (!yyjson_is_arr(parameters)) return BC_PROTOCOL_ERROR;
    if (yyjson_arr_size(parameters) > 64) return BC_LIMIT_EXCEEDED;
    size_t i, count; yyjson_val *item; int found = 0;
    yyjson_arr_foreach(parameters, i, count, item) {
        const char *name = json_string(yyjson_obj_get(item, "Name"), 128);
        yyjson_val *required = yyjson_obj_get(item, "Required");
        if (!name || (required && !yyjson_is_bool(required))) return BC_PROTOCOL_ERROR;
        if (strcmp(name, "ResetType")) {
            if (yyjson_is_true(required)) return BC_UNSUPPORTED;
            continue;
        }
        if (found++) return BC_PROTOCOL_ERROR;
        const char *type = json_string(yyjson_obj_get(item, "DataType"), 128);
        if (!type || strcmp(type, "String")) return BC_UNSUPPORTED;
        values = yyjson_obj_get(item, "AllowableValues");
    }
    return reset_values(op, values);
}
static bc_status submit_reset(bc_redfish_operation *op) {
    if (!(op->reset.supported_reset_types & (UINT32_C(1) << op->reset_type))) return BC_UNSUPPORTED;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return BC_NO_MEMORY;
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    if (!root || !yyjson_mut_obj_add_str(doc, root, "ResetType", reset_names[op->reset_type])) {
        yyjson_mut_doc_free(doc); return BC_NO_MEMORY;
    }
    size_t length = 0; char *body = yyjson_mut_write(doc, 0, &length);
    yyjson_mut_doc_free(doc);
    if (!body) return BC_NO_MEMORY;
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = op->reset.target; options.timeout_ms = op->options.request_timeout_ms;
    options.method = BC_HTTP_POST; options.body = (bc_bytes){(const unsigned char *)body, length};
    op->phase = PHASE_RESET_POST;
    bc_redfish_log_request("reset", op->endpoint, BC_HTTP_POST, op->reset.target, options.body);
    bc_status status = bc_http_submit(op->endpoint, &options, http_done, op, &op->request);
    free(body); return status;
}
static bc_status replace_uri(bc_string *out, bc_string uri) {
    if (!bc_redfish_uri_valid(uri)) return BC_UNSUPPORTED;
    bc_string owned = copy(uri);
    if (!owned.data) return BC_NO_MEMORY;
    free((void *)out->data); *out = owned; return BC_OK;
}
static bc_status relationship(bc_redfish_operation *op, yyjson_val *root, const char *key) {
    yyjson_val *value = yyjson_obj_get(root, key);
    if (!value) return BC_UNSUPPORTED;
    const char *uri = json_string(yyjson_obj_get(value, "@odata.id"), 8192);
    return uri ? replace_uri(&op->result.resource_uri, str(uri)) : BC_PROTOCOL_ERROR;
}
static bc_status task_metadata(bc_redfish_operation *op, const bc_http_metadata *metadata, int monitor) {
    if (!metadata) return BC_OK;
    if (metadata->retry_after.length) {
        op->task.retry_after = copy(metadata->retry_after);
        if (!op->task.retry_after.data) return BC_NO_MEMORY;
    }
    return monitor && metadata->location.length ? replace_uri(&op->task.monitor_uri, metadata->location) : BC_OK;
}
static bc_status task_result(bc_redfish_operation *op, yyjson_val *root, int hints) {
    if ((!hints || yyjson_obj_get(root, "@odata.type")) && !bc_redfish_resource_type(root, "#Task.", ".Task")) return BC_PROTOCOL_ERROR;
    bc_status status = set_string(&op->task.state, yyjson_obj_get(root, "TaskState"), 128, 0);
    if (status == BC_OK) status = set_string(&op->task.status, yyjson_obj_get(root, "TaskStatus"), 128, 0);
    const char *keys[] = {"@odata.id", "TaskMonitor"};
    bc_string *outputs[] = {&op->task.task_uri, &op->task.monitor_uri};
    for (size_t i = 0; status == BC_OK && i < 2; ++i) {
        yyjson_val *value = yyjson_obj_get(root, keys[i]);
        if (!value) continue;
        const char *uri = json_string(value, 8192);
        status = uri ? replace_uri(outputs[i], str(uri)) : BC_PROTOCOL_ERROR;
    }
    yyjson_val *percent = yyjson_obj_get(root, "PercentComplete");
    if (status == BC_OK && percent && !yyjson_is_null(percent)) {
        if (!yyjson_is_uint(percent) || yyjson_get_uint(percent) > 100) status = BC_PROTOCOL_ERROR;
        else { op->task.percent_complete = (uint32_t)yyjson_get_uint(percent); op->task.flags |= BC_TASK_PERCENT_PRESENT; }
    }
    yyjson_val *messages = yyjson_obj_get(root, "Messages");
    if (status == BC_OK && messages) {
        if (!yyjson_is_arr(messages)) status = BC_PROTOCOL_ERROR;
        else {
            size_t length = 0; char *json = yyjson_val_write(messages, 0, &length);
            if (!json) status = BC_NO_MEMORY;
            else op->task.messages_json = (bc_bytes){(const unsigned char *)json, length};
        }
    }
    if (status != BC_OK) return status;
    const char *state = op->task.state.data;
    if (state) {
        if (!strcmp(state, "Completed") || !strcmp(state, "Exception") || !strcmp(state, "Killed") || !strcmp(state, "Cancelled"))
            op->task.flags |= BC_TASK_TERMINAL;
        if (!strcmp(state, "Exception")) op->task.flags |= BC_TASK_FAILED;
        if (!strcmp(state, "Cancelled") || !strcmp(state, "Killed")) op->task.flags |= BC_TASK_CANCELLED;
    }
    if ((op->task.flags & BC_TASK_TERMINAL) && op->task.status.data && !strcmp(op->task.status.data, "Critical")) op->task.flags |= BC_TASK_FAILED;
    return BC_OK;
}
static bc_status task_response(bc_redfish_operation *op, bc_request *request, const bc_response *response) {
    int monitor = op->phase == PHASE_TASK_MONITOR || op->phase == PHASE_RESET_POST || op->phase == PHASE_VM_POST;
    if (op->phase == PHASE_TASK_MONITOR && response->http_status != 202) {
        op->task.flags |= BC_TASK_MONITOR_COMPLETE;
        if (response->body.length) {
            bc_string bytes = copy((bc_string){(const char *)response->body.data, response->body.length});
            if (!bytes.data) return BC_NO_MEMORY;
            op->task.final_body = (bc_bytes){(const unsigned char *)bytes.data, bytes.length};
            yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
            int error = doc && yyjson_obj_get(yyjson_doc_get_root(doc), "error");
            if (doc) yyjson_doc_free(doc);
            if (error) return BC_REDFISH_ERROR;
        }
        return BC_OK;
    }
    if (monitor) op->task.flags |= BC_TASK_MONITOR_PENDING;
    bc_status status = BC_OK;
    if (response->body.length) {
        yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
        yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
        if (!yyjson_is_obj(root)) status = BC_PROTOCOL_ERROR;
        else if (yyjson_obj_get(root, "error")) status = BC_REDFISH_ERROR;
        else status = task_result(op, root, monitor);
        if (status == BC_OK) {
            unsigned char safe[BC_REDFISH_TASK_REFERENCE_MAX]; uint32_t length = 0;
            if (bc_redfish_task_identity_capture(response->body, safe, sizeof(safe), &length) == BC_OK) {
                bc_string owned = copy((bc_string){(const char *)safe, length});
                if (owned.data) { free((void *)op->task_identity.data); op->task_identity = (bc_bytes){(const unsigned char *)owned.data, owned.length}; }
            }
        }
        if (doc) yyjson_doc_free(doc);
    } else if (!monitor) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) status = task_metadata(op, bc_request_http_metadata(request), monitor);
    return status;
}
static bc_status reset_response(bc_redfish_operation *op, const bc_response *response) {
    if (response->http_status != 200 && response->http_status != 202 && response->http_status != 204) return BC_OUTCOME_UNKNOWN;
    if (response->body.length) {
        yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
        yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
        bc_status status = !yyjson_is_obj(root) ? BC_OUTCOME_UNKNOWN : yyjson_obj_get(root, "error") ? BC_REDFISH_ERROR : BC_OK;
        if (doc) yyjson_doc_free(doc);
        if (status != BC_OK) return status;
    }
    op->result.flags |= BC_REDFISH_COMMAND_ACCEPTED;
    if (response->http_status == 202) op->result.flags |= BC_REDFISH_TASK_PENDING;
    return BC_OK;
}
static void save_error(bc_redfish_operation *op, const bc_response *r) {
    if (!r->body.length) return;
    unsigned char *bytes = malloc((size_t)r->body.length);
    if (bytes) { memcpy(bytes, r->body.data, (size_t)r->body.length); op->result.error_body = (bc_bytes){bytes, r->body.length}; }
    BC_LOG_DEBUG(BC_LOG_CATEGORY_REDFISH, "redfish.error_body", "bytes=%" PRIu64 " stored=%u",
        r->body.length, bytes != NULL);
}
int bc_redfish_resource_type(yyjson_val *root, const char *prefix, const char *suffix) {
    const char *type = json_string(yyjson_obj_get(root, "@odata.type"), 256);
    if (!type) return 0;
    size_t n = strlen(type), first = strlen(prefix), last = strlen(suffix);
    return n >= first && n >= last && !strncmp(type, prefix, first) && !strcmp(type + n - last, suffix);
}
static int collection_type(bc_redfish_operation *op, yyjson_val *root) {
    const char *type = json_string(yyjson_obj_get(root, "@odata.type"), 256);
    const char *name = collection_names[op->collection.collection_kind];
    if (!type || *type++ != '#') return 0;
    size_t n = strlen(name), length = strlen(type);
    return length >= 2 * n + 1 && !strncmp(type, name, n) && type[n] == '.' && type[length - n - 1] == '.' && !strcmp(type + length - n, name);
}
static int version_valid(bc_string version) {
    unsigned parts = 0, digits = 0;
    for (uint64_t i = 0; i < version.length; ++i) {
        char c = version.data[i];
        if (c >= '0' && c <= '9') ++digits;
        else if (c == '.' && digits && parts < 2) { ++parts; digits = 0; }
        else return 0;
    }
    return parts == 2 && digits;
}
static bc_status resource_result(bc_redfish_operation *op, yyjson_val *root, const bc_response *response) {
    bc_status status = set_string(&op->resource.odata_type, yyjson_obj_get(root, "@odata.type"), 1024, 0);
    if (status != BC_OK) return status;
    bc_string body;
    if (bc_endpoint_redfish_profile(op->endpoint) == BC_REDFISH_PROFILE_INSPUR) {
        size_t length = 0;
        char *json = yyjson_val_write(root, 0, &length);
        body = (bc_string){json, length};
    } else body = copy((bc_string){(const char *)response->body.data, response->body.length});
    if (!body.data) return BC_NO_MEMORY;
    op->resource.json = (bc_bytes){(const unsigned char *)body.data, body.length};
    yyjson_val *oem = yyjson_obj_get(root, "Oem");
    if (oem) {
        size_t length = 0; char *json = yyjson_val_write(oem, 0, &length);
        if (!json) return BC_NO_MEMORY;
        op->resource.oem_json = (bc_bytes){(const unsigned char *)json, length};
    }
    return BC_OK;
}
static bc_status virtual_action_target(bc_redfish_operation *op, yyjson_val *root, const char *name, bc_string *target, uint32_t flag) {
    yyjson_val *action = yyjson_obj_get(yyjson_obj_get(root, "Actions"), name);
    if (!action) return BC_OK;
    const char *uri = json_string(yyjson_obj_get(action, "target"), 8192);
    if (!uri || !bc_redfish_uri_valid(str(uri))) return BC_PROTOCOL_ERROR;
    *target = copy(str(uri));
    if (!target->data) return BC_NO_MEMORY;
    op->media.flags |= flag;
    return BC_OK;
}
static bc_status virtual_media_result(bc_redfish_operation *op, yyjson_val *root) {
    op->media.struct_size = sizeof(op->media);
    bc_status status = set_string(&op->media.id, yyjson_obj_get(root, "Id"), 1024, 0);
    if (status == BC_OK) status = set_string(&op->media.name, yyjson_obj_get(root, "Name"), 4096, 0);
    if (status == BC_OK) status = set_string(&op->media.image, yyjson_obj_get(root, "Image"), 8192, 0);
    if (status == BC_OK) status = set_string(&op->media.image_name, yyjson_obj_get(root, "ImageName"), 1024, 0);
    if (status == BC_OK) status = set_string(&op->media.connected_via, yyjson_obj_get(root, "ConnectedVia"), 64, 0);
    if (status != BC_OK) return status;
    yyjson_val *inserted = yyjson_obj_get(root, "Inserted");
    if (inserted && !yyjson_is_null(inserted)) {
        if (!yyjson_is_bool(inserted)) return BC_PROTOCOL_ERROR;
        op->media.flags |= BC_REDFISH_VM_INSERTED_PRESENT;
        if (yyjson_is_true(inserted)) { op->media.flags |= BC_REDFISH_VM_INSERTED; op->media.inserted = 1; }
    }
    yyjson_val *protected_value = yyjson_obj_get(root, "WriteProtected");
    if (protected_value && !yyjson_is_null(protected_value)) {
        if (!yyjson_is_bool(protected_value)) return BC_PROTOCOL_ERROR;
        if (yyjson_is_true(protected_value)) { op->media.flags |= BC_REDFISH_VM_WRITE_PROTECTED; op->media.write_protected = 1; }
    }
    yyjson_val *types = yyjson_obj_get(root, "MediaTypes");
    if (yyjson_is_null(types)) types = NULL;
    if (types) {
        if (!yyjson_is_arr(types) || yyjson_arr_size(types) > 16) return BC_PROTOCOL_ERROR;
        op->media.media_type_count = (uint32_t)yyjson_arr_size(types);
        op->media_types = calloc(op->media.media_type_count, sizeof(*op->media_types));
        if (!op->media_types) return BC_NO_MEMORY;
        op->media.media_types = op->media_types;
        size_t i, count; yyjson_val *item;
        yyjson_arr_foreach(types, i, count, item) {
            const char *value = json_string(item, 128);
            if (!value) return BC_PROTOCOL_ERROR;
            op->media_types[i] = copy(str(value));
            if (!op->media_types[i].data) return BC_NO_MEMORY;
        }
    }
    status = virtual_action_target(op, root, "#VirtualMedia.InsertMedia", &op->media.insert_target, BC_REDFISH_VM_INSERT_ACTION);
    if (status == BC_OK) status = virtual_action_target(op, root, "#VirtualMedia.EjectMedia", &op->media.eject_target, BC_REDFISH_VM_EJECT_ACTION);
    if (status != BC_OK) return status;
    if (!(op->media.flags & (BC_REDFISH_VM_INSERT_ACTION | BC_REDFISH_VM_EJECT_ACTION))) return BC_UNSUPPORTED;
    return BC_OK;
}
static int media_url_valid(bc_string url) {
    if (!url.data || url.length < 8 || url.length > 8192) return 0;
    if (memcmp(url.data, "http://", 7) && memcmp(url.data, "https://", 8) &&
        memcmp(url.data, "nfs://", 6) && memcmp(url.data, "cifs://", 7) && memcmp(url.data, "smb://", 6)) return 0;
    for (uint64_t i = 0; i < url.length; ++i) {
        unsigned char c = (unsigned char)url.data[i];
        if (c <= 0x20 || c == 0x7f) return 0;
    }
    return 1;
}
static bc_status graphical_console_result(bc_redfish_operation *op, yyjson_val *root) {
    yyjson_val *console = yyjson_obj_get(root, "GraphicalConsole");
    if (!console) return BC_UNSUPPORTED;
    if (!yyjson_is_obj(console)) return BC_PROTOCOL_ERROR;
    op->console.struct_size = sizeof(op->console);
    yyjson_val *enabled = yyjson_obj_get(console, "ServiceEnabled");
    if (enabled) {
        if (!yyjson_is_bool(enabled)) return BC_PROTOCOL_ERROR;
        op->console.service_enabled = yyjson_is_true(enabled);
        op->console.flags |= BC_REDFISH_CONSOLE_SERVICE_ENABLED;
    }
    yyjson_val *port = yyjson_obj_get(console, "Port");
    if (port) {
        if (!yyjson_is_uint(port) || yyjson_get_uint(port) > 65535) return BC_PROTOCOL_ERROR;
        op->console.port = (uint32_t)yyjson_get_uint(port);
        op->console.flags |= BC_REDFISH_CONSOLE_PORT_PRESENT;
    }
    yyjson_val *sessions = yyjson_obj_get(console, "MaxConcurrentSessions");
    if (sessions) {
        if (!yyjson_is_uint(sessions) || yyjson_get_uint(sessions) > 1024) return BC_PROTOCOL_ERROR;
        op->console.max_sessions = (uint32_t)yyjson_get_uint(sessions);
        op->console.flags |= BC_REDFISH_CONSOLE_SESSIONS_PRESENT;
    }
    yyjson_val *types = yyjson_obj_get(console, "ConnectTypesSupported");
    if (types) {
        if (!yyjson_is_arr(types) || yyjson_arr_size(types) > 16) return BC_PROTOCOL_ERROR;
        op->console.connect_type_count = (uint32_t)yyjson_arr_size(types);
        op->console_types = calloc(op->console.connect_type_count, sizeof(*op->console_types));
        if (!op->console_types) return BC_NO_MEMORY;
        op->console.connect_types = op->console_types;
        size_t i, count; yyjson_val *item;
        yyjson_arr_foreach(types, i, count, item) {
            const char *value = json_string(item, 64);
            if (!value) return BC_PROTOCOL_ERROR;
            op->console_types[i] = copy(str(value));
            if (!op->console_types[i].data) return BC_NO_MEMORY;
        }
        op->console.flags |= BC_REDFISH_CONSOLE_TYPES_PRESENT;
    }
    return BC_OK;
}
static bc_status protocol_object_parse(bc_redfish_network_protocol_entry *entry, yyjson_val *object) {
    yyjson_val *enabled = yyjson_obj_get(object, "ProtocolEnabled");
    if (enabled) {
        entry->flags |= BC_REDFISH_NET_PROTOCOL_ENABLED;
        if (yyjson_is_null(enabled)) entry->null_flags |= BC_REDFISH_NET_PROTOCOL_ENABLED_NULL;
        else {
            if (!yyjson_is_bool(enabled)) return BC_PROTOCOL_ERROR;
            entry->enabled = yyjson_is_true(enabled);
        }
    }
    yyjson_val *port = yyjson_obj_get(object, "Port");
    if (port) {
        entry->flags |= BC_REDFISH_NET_PROTOCOL_PORT;
        if (yyjson_is_null(port)) entry->null_flags |= BC_REDFISH_NET_PROTOCOL_PORT_NULL;
        else {
            if (!yyjson_is_uint(port) || yyjson_get_uint(port) > 65535) return BC_PROTOCOL_ERROR;
            entry->port = (uint32_t)yyjson_get_uint(port);
        }
    }
    return BC_OK;
}
static bc_status ntp_servers_parse(bc_string *out, uint32_t *count, yyjson_val *list) {
    if (!yyjson_is_arr(list)) return BC_PROTOCOL_ERROR;
    if (yyjson_arr_size(list) > BC_REDFISH_NETWORK_MAX_SERVERS) return BC_LIMIT_EXCEEDED;
    size_t i, total; yyjson_val *item;
    yyjson_arr_foreach(list, i, total, item) {
        const char *value = json_string(item, 256);
        if (!value) return BC_PROTOCOL_ERROR;
        bc_string owned = copy(str(value));
        if (!owned.data) return BC_NO_MEMORY;
        out[*count] = owned;
        *count += 1;
    }
    return BC_OK;
}
static bc_status network_protocol_result(bc_redfish_operation *op, yyjson_val *root) {
    static const char *const keys[BC_REDFISH_NETWORK_PROTOCOL_COUNT] = {
        "NTP", "SSH", "SNMP", "HTTP", "HTTPS", "IPMI", "VirtualMedia", "KVMIP", "SSDP", "Telnet"
    };
    op->network.struct_size = sizeof(op->network);
    bc_status status = BC_OK;
    for (size_t i = 0; status == BC_OK && i < BC_REDFISH_NETWORK_PROTOCOL_COUNT; ++i) {
        yyjson_val *object = yyjson_obj_get(root, keys[i]);
        if (!object || yyjson_is_null(object)) continue;
        if (!yyjson_is_obj(object)) return BC_PROTOCOL_ERROR;
        bc_redfish_network_protocol_entry *entry = &op->network.protocols[i];
        entry->flags |= BC_REDFISH_NET_PROTOCOL_PRESENT;
        status = protocol_object_parse(entry, object);
        if (status == BC_OK && i == BC_REDFISH_PROTOCOL_NTP) {
            yyjson_val *servers = yyjson_obj_get(object, "NTPServers");
            if (servers && !yyjson_is_null(servers))
                status = ntp_servers_parse(op->network.ntp_servers, &op->network.ntp_server_count, servers);
            if (status == BC_OK) {
                yyjson_val *supplied = yyjson_obj_get(object, "NetworkSuppliedServers");
                if (supplied && !yyjson_is_null(supplied))
                    status = ntp_servers_parse(op->network.ntp_network_supplied, &op->network.ntp_network_supplied_count, supplied);
            }
        }
    }
    if (status == BC_OK) {
        yyjson_val *host_name = yyjson_obj_get(root, "HostName");
        if (host_name) {
            if (yyjson_is_null(host_name)) op->network.null_flags |= BC_REDFISH_NETWORK_HOST_NAME_NULL;
            else status = set_string(&op->network.host_name, host_name, 256, 0);
        }
    }
    if (status == BC_OK) {
        yyjson_val *fqdn = yyjson_obj_get(root, "FQDN");
        if (fqdn) {
            if (yyjson_is_null(fqdn)) op->network.null_flags |= BC_REDFISH_NETWORK_FQDN_NULL;
            else status = set_string(&op->network.fqdn, fqdn, 256, 0);
        }
    }
    return status;
}
static bc_status eth_string(bc_string *out, uint32_t *flags, uint32_t *null_flags, uint32_t bit, yyjson_val *value) {
    if (!value) return BC_OK;
    *flags |= bit;
    if (yyjson_is_null(value)) { *null_flags |= bit; return BC_OK; }
    const char *text_value = json_string(value, 1024);
    if (!text_value) return BC_PROTOCOL_ERROR;
    *out = copy(str(text_value));
    return out->data ? BC_OK : BC_NO_MEMORY;
}
static bc_status eth_bool(uint32_t *slot, uint32_t *flags, uint32_t *null_flags, uint32_t bit, yyjson_val *value) {
    if (!value) return BC_OK;
    *flags |= bit;
    if (yyjson_is_null(value)) { *null_flags |= bit; return BC_OK; }
    if (!yyjson_is_bool(value)) return BC_PROTOCOL_ERROR;
    *slot = yyjson_is_true(value);
    return BC_OK;
}
static bc_status ethernet_result(bc_redfish_operation *op, yyjson_val *root) {
    bc_redfish_ethernet_info *eth = &op->ethernet;
    eth->struct_size = sizeof(*eth);
    bc_status status = set_string(&op->result.id, yyjson_obj_get(root, "Id"), 1024, 0);
    if (status == BC_OK) status = set_string(&op->result.name, yyjson_obj_get(root, "Name"), 4096, 0);
    if (status == BC_OK) status = eth_string(&eth->mac, &eth->flags, &eth->null_flags, BC_REDFISH_ETH_MAC, yyjson_obj_get(root, "MACAddress"));
    yyjson_val *status_object = yyjson_obj_get(root, "Status");
    if (status == BC_OK && status_object && !yyjson_is_null(status_object)) {
        if (!yyjson_is_obj(status_object)) return BC_PROTOCOL_ERROR;
        status = eth_string(&eth->state, &eth->flags, &eth->null_flags, BC_REDFISH_ETH_STATUS_STATE,
            yyjson_obj_get(status_object, "State"));
        if (status == BC_OK) status = eth_string(&eth->health, &eth->flags, &eth->null_flags, BC_REDFISH_ETH_STATUS_HEALTH,
            yyjson_obj_get(status_object, "Health"));
    }
    yyjson_val *dhcp4 = yyjson_obj_get(root, "DHCPv4");
    if (status == BC_OK && dhcp4 && !yyjson_is_null(dhcp4)) {
        if (!yyjson_is_obj(dhcp4)) return BC_PROTOCOL_ERROR;
        status = eth_bool(&eth->dhcp4_enabled, &eth->flags, &eth->null_flags, BC_REDFISH_ETH_DHCP4_ENABLED,
            yyjson_obj_get(dhcp4, "DHCPEnabled"));
    }
    yyjson_val *dhcp6 = yyjson_obj_get(root, "DHCPv6");
    if (status == BC_OK && dhcp6 && !yyjson_is_null(dhcp6)) {
        if (!yyjson_is_obj(dhcp6)) return BC_PROTOCOL_ERROR;
        status = eth_bool(&eth->dhcp6_enabled, &eth->flags, &eth->null_flags, BC_REDFISH_ETH_DHCP6_ENABLED,
            yyjson_obj_get(dhcp6, "DHCPEnabled"));
    }
    if (status == BC_OK) status = eth_string(&eth->host_name, &eth->flags, &eth->null_flags, BC_REDFISH_ETH_HOST_NAME, yyjson_obj_get(root, "HostName"));
    if (status == BC_OK) status = eth_string(&eth->fqdn, &eth->flags, &eth->null_flags, BC_REDFISH_ETH_FQDN, yyjson_obj_get(root, "FQDN"));
    if (status == BC_OK) status = eth_bool(&eth->interface_enabled, &eth->flags, &eth->null_flags,
        BC_REDFISH_ETH_INTERFACE_ENABLED, yyjson_obj_get(root, "InterfaceEnabled"));
    if (status == BC_OK) status = eth_string(&eth->link_status, &eth->flags, &eth->null_flags, BC_REDFISH_ETH_LINK_STATUS, yyjson_obj_get(root, "LinkStatus"));
    yyjson_val *ipv4 = yyjson_obj_get(root, "IPv4Addresses");
    if (status == BC_OK && ipv4 && !yyjson_is_null(ipv4)) {
        if (!yyjson_is_arr(ipv4)) return BC_PROTOCOL_ERROR;
        if (yyjson_arr_size(ipv4) > BC_REDFISH_ETH_IPV4_COUNT) return BC_LIMIT_EXCEEDED;
        size_t i, total; yyjson_val *item;
        yyjson_arr_foreach(ipv4, i, total, item) {
            if (!yyjson_is_obj(item)) return BC_PROTOCOL_ERROR;
            bc_redfish_ipv4_entry *entry = &eth->ipv4[eth->ipv4_count];
            eth->ipv4_count++;
            status = eth_string(&entry->address, &entry->flags, &entry->null_flags, 1u, yyjson_obj_get(item, "Address"));
            if (status == BC_OK) status = eth_string(&entry->subnet_mask, &entry->flags, &entry->null_flags, 2u, yyjson_obj_get(item, "SubnetMask"));
            if (status == BC_OK) status = eth_string(&entry->gateway, &entry->flags, &entry->null_flags, 4u, yyjson_obj_get(item, "Gateway"));
            if (status == BC_OK) status = eth_string(&entry->address_origin, &entry->flags, &entry->null_flags, 8u, yyjson_obj_get(item, "AddressOrigin"));
            if (status != BC_OK) return status;
        }
    }
    yyjson_val *ipv6 = yyjson_obj_get(root, "IPv6Addresses");
    if (status == BC_OK && ipv6 && !yyjson_is_null(ipv6)) {
        if (!yyjson_is_arr(ipv6)) return BC_PROTOCOL_ERROR;
        if (yyjson_arr_size(ipv6) > BC_REDFISH_ETH_IPV6_COUNT) return BC_LIMIT_EXCEEDED;
        size_t i, total; yyjson_val *item;
        yyjson_arr_foreach(ipv6, i, total, item) {
            if (!yyjson_is_obj(item)) return BC_PROTOCOL_ERROR;
            bc_redfish_ipv6_entry *entry = &eth->ipv6[eth->ipv6_count];
            eth->ipv6_count++;
            status = eth_string(&entry->address, &entry->flags, &entry->null_flags, 1u, yyjson_obj_get(item, "Address"));
            yyjson_val *prefix = yyjson_obj_get(item, "PrefixLength");
            if (status == BC_OK && prefix && !yyjson_is_null(prefix)) {
                if (!yyjson_is_uint(prefix) || yyjson_get_uint(prefix) > 128) return BC_PROTOCOL_ERROR;
                entry->flags |= 2u;
                entry->prefix_length = (uint32_t)yyjson_get_uint(prefix);
            }
            if (status == BC_OK) status = eth_string(&entry->address_origin, &entry->flags, &entry->null_flags, 4u, yyjson_obj_get(item, "AddressOrigin"));
            if (status == BC_OK) status = eth_string(&entry->address_state, &entry->flags, &entry->null_flags, 8u, yyjson_obj_get(item, "AddressState"));
            if (status != BC_OK) return status;
        }
    }
    return status;
}
static bc_status virtual_media_insert_parameters(yyjson_val *root, unsigned *supported) {
    yyjson_val *parameters = yyjson_obj_get(root, "Parameters");
    if (!yyjson_is_arr(parameters)) return BC_PROTOCOL_ERROR;
    size_t i, count;
    yyjson_val *parameter;
    int image = 0;
    *supported = 0;
    yyjson_arr_foreach(parameters, i, count, parameter) {
        const char *name = json_string(yyjson_obj_get(parameter, "Name"), 128);
        if (!name) return BC_PROTOCOL_ERROR;
        if (!strcmp(name, "Image")) image = 1;
        else if (!strcmp(name, "Inserted")) *supported |= VM_PARAM_INSERTED;
        else if (!strcmp(name, "WriteProtected")) *supported |= VM_PARAM_WRITE_PROTECTED;
        else if (!strcmp(name, "TransferMethod")) *supported |= VM_PARAM_TRANSFER_METHOD;
        else if (!strcmp(name, "TransferProtocolType")) *supported |= VM_PARAM_TRANSFER_PROTOCOL;
        else if (yyjson_is_true(yyjson_obj_get(parameter, "Required"))) return BC_UNSUPPORTED;
    }
    return image ? BC_OK : BC_UNSUPPORTED;
}
static bc_status submit_virtual_media(bc_redfish_operation *op, unsigned parameters) {
    int insert = op->result.kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT;
    if(insert&&(op->media.inserted||op->media.image.length))return BC_CONFIRMATION_REQUIRED;
    bc_string target = insert ? op->media.insert_target : op->media.eject_target;
    if (!target.length) return BC_UNSUPPORTED;
    char *body = NULL;
    size_t length = 0;
    if (insert) {
        if ((op->insert.flags & BC_REDFISH_VM_WRITE_PROTECTED_SET) &&
            !(parameters & VM_PARAM_WRITE_PROTECTED) &&
            (op->insert.write_protected != op->media.write_protected ||
             !op->media.write_protected)) return BC_UNSUPPORTED;
        if ((op->insert.transfer_method.length && !(parameters & VM_PARAM_TRANSFER_METHOD)) ||
            (op->insert.transfer_protocol_type.length && !(parameters & VM_PARAM_TRANSFER_PROTOCOL))) return BC_UNSUPPORTED;
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
        yyjson_mut_val *root = doc ? yyjson_mut_obj(doc) : NULL;
        if (!root) { if (doc) yyjson_mut_doc_free(doc); return BC_NO_MEMORY; }
        yyjson_mut_doc_set_root(doc, root);
        int ok = yyjson_mut_obj_add_strncpy(doc, root, "Image", op->insert.image.data, op->insert.image.length);
        if (ok && (parameters & VM_PARAM_INSERTED))
            ok = yyjson_mut_obj_add_bool(doc, root, "Inserted", 1);
        if (ok && (parameters & VM_PARAM_WRITE_PROTECTED) && (op->insert.flags & BC_REDFISH_VM_WRITE_PROTECTED_SET))
            ok = yyjson_mut_obj_add_bool(doc, root, "WriteProtected", op->insert.write_protected != 0);
        if (ok && op->insert.transfer_method.length)
            ok = yyjson_mut_obj_add_strncpy(doc, root, "TransferMethod", op->insert.transfer_method.data, op->insert.transfer_method.length);
        if (ok && op->insert.transfer_protocol_type.length)
            ok = yyjson_mut_obj_add_strncpy(doc, root, "TransferProtocolType", op->insert.transfer_protocol_type.data,
                op->insert.transfer_protocol_type.length);
        if (!ok) { yyjson_mut_doc_free(doc); return BC_NO_MEMORY; }
        body = yyjson_mut_write(doc, 0, &length);
        yyjson_mut_doc_free(doc);
        if (!body) return BC_NO_MEMORY;
    }
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = target; options.timeout_ms = op->options.request_timeout_ms;
    options.method = BC_HTTP_POST;
    options.body = insert ? (bc_bytes){(const unsigned char *)body, length} :
        (bc_bytes){(const unsigned char *)"{}", 2};
    op->phase = PHASE_VM_POST;
    bc_redfish_log_request("virtual-media", op->endpoint, BC_HTTP_POST, target, options.body);
    bc_status status = bc_http_submit(op->endpoint, &options, http_done, op, &op->request);
    free(body);
    if (status == BC_OK) {
        op->result.flags |= BC_REDFISH_COMMAND_SUBMITTED;
        op->submitted_method = options.method;
        op->result.http_status = 0;
    }
    return status;
}
static bc_status irmc_media_submit(bc_redfish_operation *op, bc_string target, uint32_t phase) {
    int patch = phase == PHASE_IRMC_VM_PATCH;
    char *owned = NULL;
    const char *body = op->result.kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT ?
        "{\"FTSVirtualMediaAction\":\"ConnectCD\"}" : "{\"FTSVirtualMediaAction\":\"DisconnectCD\"}";
    size_t length = strlen(body);
    bc_status status = BC_OK;
    if (patch) {
        status = bc_irmc_media_config_body(op->insert.image, &owned, &length);
        if (status != BC_OK) return status;
        body = owned;
    }
    bc_http_options options = {0};
    options.struct_size = sizeof(options);
    options.abi_version = BC_ABI_VERSION;
    options.path = target;
    options.method = patch ? BC_HTTP_PATCH : BC_HTTP_POST;
    options.timeout_ms = op->options.request_timeout_ms;
    options.body = (bc_bytes){(const uint8_t *)body, length};
    char if_match[1024];
    bc_string header;
    if (patch && op->irmc_media_etag.length) {
        snprintf(if_match, sizeof(if_match), "If-Match: %s", op->irmc_media_etag.data);
        header = str(if_match);
        options.headers = &header;
        options.header_count = 1;
    }
    op->phase = phase;
    status = bc_http_submit(op->endpoint, &options, http_done, op, &op->request);
    free(owned);
    if (status == BC_OK && !patch) {
        op->result.flags |= BC_REDFISH_COMMAND_SUBMITTED;
        op->submitted_method = BC_HTTP_POST;
        op->result.http_status = 0;
    }
    return status;
}

static bc_status irmc_media_read(bc_redfish_operation *op, yyjson_val *root) {
    bc_status status = bc_irmc_media_system_path(op->result.resource_uri, op->irmc_media_system,
        sizeof(op->irmc_media_system));
    if (status != BC_OK) return status;
    yyjson_val *cd = yyjson_obj_get(root, "CDImage");
    yyjson_val *active = yyjson_obj_get(root, "IsAnyVirtualMediaActive");
    yyjson_val *count = yyjson_obj_get(cd, "MaximumNumberOfDevices");
    if (!yyjson_is_true(yyjson_obj_get(root, "RemoteMountEnabled")) || !yyjson_is_uint(count) || !yyjson_get_uint(count))
        return BC_UNSUPPORTED;
    if (!yyjson_is_bool(active)) return BC_PROTOCOL_ERROR;
    op->irmc_media_active = yyjson_is_true(active);
    status = set_string(&op->irmc_media_etag, yyjson_obj_get(root, "@odata.etag"), 900, 0);
    if (status == BC_OK && op->irmc_media_etag.data && strpbrk(op->irmc_media_etag.data, "\r\n"))
        status = BC_PROTOCOL_ERROR;
    if (status != BC_OK) return status;
    op->media.struct_size = sizeof(op->media);
    op->media.id = copy(str("CDImage"));
    op->media.name = copy(str("Remote CD/DVD"));
    op->media_types = calloc(1, sizeof(*op->media_types));
    if (!op->media.id.data || !op->media.name.data || !op->media_types) return BC_NO_MEMORY;
    op->media_types[0] = copy(str("CD"));
    op->media.media_type_count = 1;
    op->media.media_types = op->media_types;
    if (!op->media_types[0].data) return BC_NO_MEMORY;
    op->media.flags = BC_REDFISH_VM_WRITE_PROTECTED;
    op->media.write_protected = 1;
    if (op->irmc_media_active) {
        status = set_string(&op->media.image_name, yyjson_obj_get(cd, "ImageName"), 1024, 0);
        if (status == BC_OK) status = bc_irmc_media_report_image(cd, &op->media.image);
        if (status != BC_OK) return status;
    }
    op->phase = PHASE_IRMC_VM_SYSTEM;
    return add_page(op, op->irmc_media_system);
}

static bc_status irmc_media_system(bc_redfish_operation *op, yyjson_val *root) {
    uint32_t state = 0;
    const char *config = bc_irmc_media_system_link(root);
    const char *target = bc_irmc_media_action(root, &state);
    if (!config || !target || !bc_redfish_uri_valid(str(target))) return BC_UNSUPPORTED;
    size_t system_length = strlen(op->irmc_media_system);
    if (strncmp(target, op->irmc_media_system, system_length) ||
        strncmp(target + system_length, "/Actions/", sizeof("/Actions/") - 1))
        return BC_PROTOCOL_ERROR;
    if (op->phase == PHASE_IRMC_VM_DISCOVERY) {
        char system[1025];
        bc_status status = bc_irmc_media_system_path(str(config), system, sizeof(system));
        if (status != BC_OK) return status;
        if (strcmp(system, op->irmc_media_system) || !bc_redfish_uri_valid(str(config))) return BC_PROTOCOL_ERROR;
        op->members[0] = copy(str(config));
        if (!op->members[0].data) return BC_NO_MEMORY;
        op->collection.member_count = 1;
        return BC_OK;
    }
    if (strcmp(config, op->result.resource_uri.data)) return BC_PROTOCOL_ERROR;
    if (op->phase == PHASE_IRMC_VM_CONNECT) {
        if (state != BC_IRMC_MEDIA_CONNECT_CD || strcmp(target, op->media.insert_target.data)) return BC_OUTCOME_UNKNOWN;
        return irmc_media_submit(op, op->media.insert_target, PHASE_VM_POST);
    }
    int inserted = state == BC_IRMC_MEDIA_DISCONNECT_CD;
    if ((state & BC_IRMC_MEDIA_DISCONNECT_CD) && !inserted) return BC_PROTOCOL_ERROR;
    if (op->irmc_media_active && !inserted)
        return op->result.kind == BC_REDFISH_VIRTUAL_MEDIA ? BC_UNSUPPORTED : BC_CONFIRMATION_REQUIRED;
    op->media.insert_target = copy(str(target));
    op->media.eject_target = copy(str(target));
    if (!op->media.insert_target.data || !op->media.eject_target.data) return BC_NO_MEMORY;
    op->media.flags |= BC_REDFISH_VM_INSERT_ACTION | BC_REDFISH_VM_EJECT_ACTION | BC_REDFISH_VM_INSERTED_PRESENT;
    if (inserted) {
        op->media.inserted = 1;
        op->media.flags |= BC_REDFISH_VM_INSERTED;
        op->media.connected_via = copy(str("URI"));
        if (!op->media.connected_via.data) return BC_NO_MEMORY;
    }
    if (op->result.kind == BC_REDFISH_VIRTUAL_MEDIA) return BC_OK;
    if (op->result.kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT) {
        if (inserted) return BC_CONFIRMATION_REQUIRED;
        return irmc_media_submit(op, op->result.resource_uri, PHASE_IRMC_VM_PATCH);
    }
    return inserted ? irmc_media_submit(op, op->media.eject_target, PHASE_VM_POST) : BC_OK;
}

static void process_http(bc_redfish_operation *op, bc_request *request, const bc_response *response) {
    op->result.http_status = response->http_status;
    bc_status status = response->status;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_REDFISH, "redfish.response", "kind=%u phase=%u status=%s http=%u bytes=%" PRIu64,
        op->result.kind, op->phase, bc_status_string(status), response->http_status, response->body.length);
    if (status == BC_OK && (response->http_status < 200 || response->http_status >= 300)) status = BC_HTTP_ERROR;
    if (op->phase == PHASE_PROBE && status == BC_HTTP_ERROR && response->http_status == 500) {
        op->phase = PHASE_INSPUR_PAGE;
        status = get_inspur_asset(op, 0);
        if (status != BC_OK) finish(op, status);
        return;
    }
    if (op->phase == PHASE_INSPUR_PAGE || op->phase == PHASE_INSPUR_SCRIPT) {
        int page = op->phase == PHASE_INSPUR_PAGE;
        int matches = status == BC_OK && response->http_status == 200 && response->body.length <= 262144 &&
            (page ? bc_inspur_login_page_matches(response->body.data, (uint32_t)response->body.length) :
                bc_inspur_login_script_matches(response->body.data, (uint32_t)response->body.length));
        if (!matches) { finish(op, status == BC_OK ? BC_UNSUPPORTED : status); return; }
        if (!page) { finish(op, BC_OK); return; }
        op->phase = PHASE_INSPUR_SCRIPT;
        status = get_inspur_asset(op, 1);
        if (status != BC_OK) finish(op, status);
        return;
    }
    if (op->result.kind == BC_REDFISH_SENSOR_DETAILS && status == BC_HTTP_ERROR && response->http_status == 501) status = BC_UNSUPPORTED;
    if (status != BC_OK) { save_error(op, response); finish(op, op->phase == PHASE_BOOT_VERIFY ? BC_OUTCOME_UNKNOWN : status); return; }
    if (op->phase == PHASE_PATCH && op->result.kind == BC_REDFISH_BOOT_ONCE && response->http_status != 202) {
        if (response->body.length) {
            yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
            yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
            status = !yyjson_is_obj(root) ? BC_PROTOCOL_ERROR : yyjson_obj_get(root, "error") ? BC_REDFISH_ERROR : BC_OK;
            if (doc) yyjson_doc_free(doc);
        }
        if (status == BC_OK) {
            op->phase = PHASE_BOOT_VERIFY;
            status = get(op, op->result.resource_uri.data);
            if (status == BC_OK) return;
        }
        finish(op, BC_OUTCOME_UNKNOWN); return;
    }
    if (op->phase == PHASE_ACTION_POST || op->phase == PHASE_PATCH) {
        if (response->http_status == 202) op->result.flags |= BC_REDFISH_COMMAND_ACCEPTED;
        if (status == BC_OK && response->body.length) {
            yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
            yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
            if (!root || !yyjson_is_obj(root)) status = BC_PROTOCOL_ERROR;
            else if (yyjson_obj_get(root, "error")) status = BC_REDFISH_ERROR;
            else status = resource_result(op, root, response);
            if (status != BC_OK) save_error(op, response);
            if (doc) yyjson_doc_free(doc);
        }
        if (status == BC_OK && (op->phase == PHASE_ACTION_POST || op->result.kind == BC_REDFISH_BOOT_ONCE) && (op->result.flags & BC_REDFISH_COMMAND_ACCEPTED))
            status = task_metadata(op, bc_request_http_metadata(request), 1);
        finish(op, status);
        return;
    }
    if (op->phase == PHASE_IRMC_VM_PATCH) {
        if (status == BC_OK && response->body.length) {
            yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
            yyjson_val *root = yyjson_doc_get_root(doc);
            status = !yyjson_is_obj(root) ? BC_PROTOCOL_ERROR : yyjson_obj_get(root, "error") ? BC_REDFISH_ERROR : BC_OK;
            yyjson_doc_free(doc);
        }
        if (status == BC_OK && response->http_status != 202) {
            op->phase = PHASE_IRMC_VM_CONNECT;
            if (get(op, op->irmc_media_system) == BC_OK) return;
            status = BC_OUTCOME_UNKNOWN;
        } else if (status == BC_OK) status = BC_OUTCOME_UNKNOWN;
        finish(op, status);
        return;
    }
    if (op->phase == PHASE_VM_POST) {
        status = reset_response(op, response);
        if (status == BC_OK && op->result.flags & BC_REDFISH_TASK_PENDING) status = task_response(op, request, response);
        if (status != BC_OK) save_error(op, response);
        finish(op, status);
        return;
    }
    if (op->phase == PHASE_RESET_POST) {
        status = reset_response(op, response);
        if (status == BC_OK && response->http_status == 202) status = task_response(op, request, response);
        if (status != BC_OK) save_error(op, response);
        finish(op, status); return;
    }
    if (op->phase == PHASE_TASK || op->phase == PHASE_TASK_MONITOR) {
        status = task_response(op, request, response);
        if (status != BC_OK) save_error(op, response);
        finish(op, status); return;
    }
    yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    if (!root || !yyjson_is_obj(root)) { save_error(op, response); if (doc) yyjson_doc_free(doc); finish(op, BC_PROTOCOL_ERROR); return; }
    if (bc_endpoint_redfish_profile(op->endpoint) == BC_REDFISH_PROFILE_INSPUR) {
        size_t length = 0;
        char *normalized = bc_inspur_redfish_resource(root, &length);
        yyjson_doc_free(doc);
        doc = normalized ? yyjson_read(normalized, length, 0) : NULL;
        free(normalized);
        if (!doc) { finish(op, BC_NO_MEMORY); return; }
        root = yyjson_doc_get_root(doc);
    }
    if (yyjson_obj_get(root, "error")) { save_error(op, response); yyjson_doc_free(doc); finish(op, BC_REDFISH_ERROR); return; }
    int type_ok = op->phase == PHASE_RESOURCE ? 1 : op->phase == PHASE_MANAGER_LINK ? 1 :
        op->phase == PHASE_ROOT ? bc_redfish_resource_type(root, "#ServiceRoot.", ".ServiceRoot") :
        op->phase == PHASE_COLLECTION ? collection_type(op, root) :
        (op->phase == PHASE_ACTION_INFO || op->phase == PHASE_VM_INSERT_INFO) ? bc_redfish_resource_type(root, "#ActionInfo.", ".ActionInfo") :
        op->phase == PHASE_PROBE ? bc_redfish_resource_type(root, "#ServiceRoot.", ".ServiceRoot") :
        op->phase == PHASE_VM_READ ? (bc_redfish_resource_type(root, "#VirtualMedia.", ".VirtualMedia") ||
            bc_irmc_media_config_matches(root)) :
        op->phase == PHASE_TASK_SERVICE ? bc_redfish_resource_type(root, "#TaskService.", ".TaskService") :
        op->phase == PHASE_VM_MANAGER ? bc_redfish_resource_type(root, "#Manager.", ".Manager") :
        op->phase == PHASE_NETWORK_PROTOCOL ? bc_redfish_resource_type(root, "#ManagerNetworkProtocol.", ".ManagerNetworkProtocol") :
        op->phase == PHASE_ETHERNET ? bc_redfish_resource_type(root, "#EthernetInterface.", ".EthernetInterface") :
        op->phase == PHASE_GRAPHICAL_CONSOLE ? (bc_redfish_resource_type(root, "#Manager.", ".Manager") ||
            bc_redfish_resource_type(root, "#ComputerSystem.", ".ComputerSystem")) :
        op->phase == PHASE_SENSOR ? bc_redfish_resource_type(root, "#Sensor.", ".Sensor") :
        op->phase == PHASE_CHASSIS ? bc_redfish_resource_type(root, "#Chassis.", ".Chassis") : bc_redfish_resource_type(root, "#ComputerSystem.", ".ComputerSystem");
    if (!type_ok) {
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_WARN
        const char *actual = json_string(yyjson_obj_get(root, "@odata.type"), 256);
        char actual_text[BC_LOG_TEXT_MAX];
        bc_log_text(actual_text, sizeof(actual_text), actual ? actual : "", actual ? strlen(actual) : 0);
        BC_LOG_WARN(BC_LOG_CATEGORY_REDFISH, "redfish.type_mismatch",
            "kind=%u phase=%u actual=%s", op->result.kind, op->phase, actual_text[0] ? actual_text : "-");
#endif
        save_error(op, response); yyjson_doc_free(doc); finish(op, BC_PROTOCOL_ERROR); return;
    }
    if (op->phase == PHASE_BOOT_VERIFY) {
        status = bc_redfish_boot_parse(response->body, &op->boot);
        yyjson_doc_free(doc);
        if (status == BC_OK) {
            int enabled = (op->boot.boot.flags & BC_BOOT_ENABLED) != 0;
            if ((op->boot_target == BC_BOOT_NONE && enabled) || (op->boot_target != BC_BOOT_NONE &&
                (!enabled || (op->boot.boot.flags & BC_BOOT_PERSISTENT) || op->boot.boot.target != op->boot_target ||
                (op->boot_mode && op->boot.boot.mode != op->boot_mode)))) status = BC_PROTOCOL_ERROR;
        }
        if (status == BC_OK) op->result.flags |= BC_REDFISH_BOOT_VERIFIED;
        finish(op, status == BC_OK ? BC_OK : BC_OUTCOME_UNKNOWN); return;
    }
    if (op->phase == PHASE_BOOT_READ) {
        status = bc_redfish_boot_parse(response->body, &op->boot);
        if (status == BC_OK && op->result.kind == BC_REDFISH_BOOT_ONCE) {
            uint8_t body[256]; uint32_t length = 0;
            status = bc_redfish_boot_patch_build(&op->boot, op->boot_target, op->boot_mode, body, sizeof(body), &length);
            if (status == BC_OK) {
                bc_http_options options = {0};
                options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
                options.path = op->result.resource_uri; options.timeout_ms = op->options.request_timeout_ms;
                options.method = BC_HTTP_PATCH; options.body = (bc_bytes){body, length};
                char match[1024]; bc_string header;
                yyjson_val *etag_value = yyjson_obj_get(root, "@odata.etag");
                const char *etag = json_string(etag_value, 900);
                if (etag_value && (!etag || strpbrk(etag, "\r\n"))) status = BC_PROTOCOL_ERROR;
                if (status == BC_OK && etag) {
                    int count = snprintf(match, sizeof(match), "If-Match: %s", etag);
                    header = (bc_string){match, (uint64_t)count}; options.headers = &header; options.header_count = 1;
                }
                op->phase = PHASE_PATCH;
                if (status == BC_OK) {
                    bc_redfish_log_request("boot", op->endpoint, BC_HTTP_PATCH, op->result.resource_uri, (bc_bytes){body, length});
                    status = bc_http_submit(op->endpoint, &options, http_done, op, &op->request);
                }
                if (status == BC_OK) { yyjson_doc_free(doc); return; }
            }
        }
        yyjson_doc_free(doc); finish(op, status); return;
    }
    if (op->phase == PHASE_IRMC_VM_DISCOVERY || op->phase == PHASE_IRMC_VM_SYSTEM || op->phase == PHASE_IRMC_VM_CONNECT) {
        status = irmc_media_system(op, root);
        yyjson_doc_free(doc);
        if (status != BC_OK || !op->request) finish(op, status);
        return;
    }
    if (op->phase == PHASE_VM_INSERT_INFO) {
        unsigned parameters;
        status = virtual_media_insert_parameters(root, &parameters);
        yyjson_doc_free(doc);
        if (status == BC_OK) status = submit_virtual_media(op, parameters);
        if (status != BC_OK) finish(op, status);
        return;
    }
    if (op->phase == PHASE_VM_READ) {
        if (bc_irmc_media_config_matches(root)) {
            status = irmc_media_read(op, root);
            yyjson_doc_free(doc);
            if (status != BC_OK) finish(op, status);
            return;
        }
        bc_status vm_status = virtual_media_result(op, root);
        if (vm_status == BC_OK && op->result.kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT && op->media.insert_target.length) {
            yyjson_val *insert = yyjson_obj_get(yyjson_obj_get(root, "Actions"), "#VirtualMedia.InsertMedia");
            yyjson_val *info = yyjson_obj_get(insert, "@Redfish.ActionInfo");
            if (info) {
                const char *uri = json_string(info, 8192);
                vm_status = uri ? get(op, uri) : BC_PROTOCOL_ERROR;
                if (vm_status == BC_OK) {
                    op->phase = PHASE_VM_INSERT_INFO;
                    yyjson_doc_free(doc);
                    return;
                }
            }
        }
        yyjson_doc_free(doc);
        if (vm_status == BC_OK && op->result.kind != BC_REDFISH_VIRTUAL_MEDIA)
            vm_status = submit_virtual_media(op, VM_PARAM_DEFAULTS);
        /* Missing standard actions is a capability result, not a transport error: keep the parsed
         * slot details and do not retain the resource body as an error payload. */
        if (vm_status != BC_OK && vm_status != BC_UNSUPPORTED) save_error(op, response);
        if (vm_status == BC_OK && op->result.kind != BC_REDFISH_VIRTUAL_MEDIA) return;
        finish(op, vm_status);
        return;
    }
    char *next = NULL; int more = 0;
    if (op->phase == PHASE_PROBE) {
        status = set_string(&op->result.redfish_version, yyjson_obj_get(root, "RedfishVersion"), 128, 1);
        if (status == BC_OK && !version_valid(op->result.redfish_version)) status = BC_PROTOCOL_ERROR;
        if (status == BC_OK) status = resource_result(op, root, response);
        static const struct { const char *key; uint32_t flag; } services[] = {
            {"Systems", BC_REDFISH_CAPABILITY_SYSTEMS}, {"Chassis", BC_REDFISH_CAPABILITY_CHASSIS},
            {"Managers", BC_REDFISH_CAPABILITY_MANAGERS}, {"SessionService", BC_REDFISH_CAPABILITY_SESSION_SERVICE},
            {"TaskService", BC_REDFISH_CAPABILITY_TASK_SERVICE}
        };
        for (size_t i = 0; status == BC_OK && i < sizeof(services) / sizeof(services[0]); ++i) {
            yyjson_val *link = yyjson_obj_get(root, services[i].key);
            if (!link) continue;
            const char *uri = json_string(yyjson_obj_get(link, "@odata.id"), 8192);
            if (!uri || !bc_redfish_uri_valid(str(uri))) status = BC_PROTOCOL_ERROR;
            else op->result.flags |= services[i].flag;
        }
        yyjson_val *sessions = yyjson_obj_get(yyjson_obj_get(root, "Links"), "Sessions");
        if (status == BC_OK && sessions) {
            const char *uri = json_string(yyjson_obj_get(sessions, "@odata.id"), 8192);
            if (!uri || !bc_redfish_uri_valid(str(uri))) status = BC_PROTOCOL_ERROR;
            else op->result.flags |= BC_REDFISH_CAPABILITY_SESSION_SERVICE;
        }
    }
    else if (op->phase == PHASE_RESOURCE) status = resource_result(op, root, response);
    else if (op->phase == PHASE_ROOT) {
        status = set_string(&op->result.redfish_version, yyjson_obj_get(root, "RedfishVersion"), 128, 1);
        if (status == BC_OK && !version_valid(op->result.redfish_version)) status = BC_PROTOCOL_ERROR;
        if (status == BC_OK) status = relationship(op, root, op->result.kind == BC_REDFISH_TASK_DISCOVERY ? "TaskService" :
            op->result.kind == BC_REDFISH_CHASSIS_DISCOVERY ? "Chassis" :
            op->result.kind == BC_REDFISH_MANAGER_DISCOVERY ? "Managers" : "Systems");
        if (status == BC_OK) { op->phase = op->result.kind == BC_REDFISH_TASK_DISCOVERY ? PHASE_TASK_SERVICE : PHASE_COLLECTION;
            next = (char *)op->result.resource_uri.data; more = 1; }
    } else if (op->phase == PHASE_MANAGER_LINK) {
        status = relationship(op, root, op->result.kind == BC_REDFISH_ETHERNET_DISCOVERY ? "EthernetInterfaces" : "NetworkProtocol");
        if (status == BC_OK) {
            op->phase = op->result.kind == BC_REDFISH_ETHERNET_DISCOVERY ? PHASE_COLLECTION : PHASE_NETWORK_PROTOCOL;
            next = (char *)op->result.resource_uri.data; more = 1;
        }
    } else if (op->phase == PHASE_NETWORK_PROTOCOL) status = network_protocol_result(op, root);
    else if (op->phase == PHASE_ETHERNET) status = ethernet_result(op, root);
    else if (op->phase == PHASE_TASK_SERVICE) {
        status = relationship(op, root, "Tasks");
        if (status == BC_OK) { op->phase = PHASE_COLLECTION; next = (char *)op->result.resource_uri.data; more = 1; }
    } else if (op->phase == PHASE_GRAPHICAL_CONSOLE) {
        status = graphical_console_result(op, root);
    } else if (op->phase == PHASE_VM_MANAGER) {
        const char *system = bc_irmc_media_manager_system(root);
        if (system && bc_redfish_uri_valid(str(system)) && strlen(system) < sizeof(op->irmc_media_system))
            strcpy(op->irmc_media_system, system);
        status = relationship(op, root, "VirtualMedia");
        if (status == BC_OK) { op->phase = PHASE_COLLECTION; next = (char *)op->result.resource_uri.data; more = 1; }
    } else if (op->phase == PHASE_CHASSIS) {
        status = relationship(op, root, "Sensors");
        if (status == BC_OK) { op->phase = PHASE_COLLECTION; next = (char *)op->result.resource_uri.data; more = 1; }
    } else if (op->phase == PHASE_COLLECTION) {
        status = collection(op, root);
        yyjson_val *link = yyjson_obj_get(root, "Members@odata.nextLink");
        if (status == BC_OK && link) {
            const char *uri = json_string(link, 8192);
            if (!uri || !*uri) status = BC_PROTOCOL_ERROR;
            else { bc_string owned = copy(str(uri)); next = (char *)owned.data; more = 2; if (!next) status = BC_NO_MEMORY; }
        } else if (status == BC_OK && op->result.kind == BC_REDFISH_VIRTUAL_MEDIA_DISCOVERY &&
            !op->collection.member_count && op->irmc_media_system[0]) {
            op->phase = PHASE_IRMC_VM_DISCOVERY;
            next = op->irmc_media_system;
            more = 1;
        }
    } else if (op->phase == PHASE_RESET_SYSTEM) {
        yyjson_val *action = yyjson_obj_get(yyjson_obj_get(root, "Actions"), "#ComputerSystem.Reset");
        if (!action) status = BC_UNSUPPORTED;
        else status = set_string(&op->reset.target, yyjson_obj_get(action, "target"), 8192, 1);
        if (status == BC_OK && !bc_redfish_uri_valid(op->reset.target)) status = BC_UNSUPPORTED;
        yyjson_val *info = yyjson_obj_get(action, "@Redfish.ActionInfo");
        if (status == BC_OK && info) {
            const char *uri = json_string(info, 8192);
            if (!uri || !*uri) status = BC_PROTOCOL_ERROR;
            else {
                bc_string owned = copy(str(uri)); next = (char *)owned.data;
                more = 2; op->phase = PHASE_ACTION_INFO;
                if (!next) status = BC_NO_MEMORY;
            }
        } else if (status == BC_OK) status = reset_values(op, yyjson_obj_get(action, "ResetType@Redfish.AllowableValues"));
    } else if (op->phase == PHASE_ACTION_INFO) status = action_info(op, root);
    else if (op->phase == PHASE_SENSOR) {
        status = set_string(&op->result.id, yyjson_obj_get(root, "Id"), 1024, 0);
        if (status == BC_OK) status = set_string(&op->result.name, yyjson_obj_get(root, "Name"), 4096, 0);
        if (status == BC_OK) status = op->result.kind == BC_REDFISH_SENSOR_DETAILS ?
            bc_redfish_parse_sensor_details(root, &op->sensor, &op->sensor_details) : bc_redfish_parse_sensor(root, &op->sensor);
    }
    else status = system_result(op, root);
    if (status == BC_OK && (op->result.kind == BC_REDFISH_SENSOR || op->result.kind == BC_REDFISH_SYSTEM || op->result.kind == BC_REDFISH_RESOURCE))
        bc_redfish_parse_context(root, op->result.resource_uri, &op->context);
    yyjson_doc_free(doc);
    if (status == BC_OK && more) status = add_page(op, next);
    if (more == 2) free(next);
    if (status == BC_OK && !more && op->result.kind == BC_REDFISH_RESET) {
        status = submit_reset(op);
        if (status == BC_OK) return;
    }
    if (status != BC_OK || !more) finish(op, status);
}
static void http_done(bc_request *request, const bc_response *response, void *userdata) {
    bc_redfish_operation *op = userdata; op->request = NULL;
    process_http(op, request, response);
    bc_request_release(request);
}
static bc_status create(bc_endpoint *endpoint, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, uint32_t kind, bc_string uri, uint32_t selection, bc_redfish_operation **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION || !callback ||
        options->request_timeout_ms > INT32_MAX || options->max_systems > 4096 ||
        (kind != BC_REDFISH_DISCOVERY && kind != BC_REDFISH_CHASSIS_DISCOVERY && kind != BC_REDFISH_PROBE &&
         kind != BC_REDFISH_TASK_DISCOVERY && kind != BC_REDFISH_MANAGER_DISCOVERY && !bc_redfish_uri_valid(uri)) ||
        (kind == BC_REDFISH_RESET && selection >= sizeof(reset_names) / sizeof(reset_names[0])) ||
        (kind == BC_REDFISH_COLLECTION && selection > BC_COLLECTION_ETHERNET_INTERFACES)) return BC_INVALID_ARGUMENT;
    bc_redfish_operation *op = calloc(1, sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    op->refs = 1; op->endpoint = endpoint; bc_endpoint_retain(endpoint);
    op->options = *options; if (!op->options.max_systems) op->options.max_systems = 256;
    op->callback = callback; op->userdata = userdata;
    op->reset.struct_size = sizeof(op->reset); op->reset_type = kind == BC_REDFISH_RESET ? selection : 0;
    op->identity.struct_size = sizeof(op->identity);
    op->task.struct_size = sizeof(op->task);
    op->sensor.struct_size = sizeof(op->sensor);
    op->resource.struct_size = sizeof(op->resource);
    op->collection.struct_size = sizeof(op->collection);
    op->collection.collection_kind = kind == BC_REDFISH_SENSOR_DISCOVERY ? BC_COLLECTION_SENSORS :
        kind == BC_REDFISH_CHASSIS_DISCOVERY ? BC_COLLECTION_CHASSIS :
        kind == BC_REDFISH_TASK_DISCOVERY ? BC_COLLECTION_TASKS :
        kind == BC_REDFISH_VIRTUAL_MEDIA_DISCOVERY ? BC_COLLECTION_VIRTUAL_MEDIA :
        kind == BC_REDFISH_MANAGER_DISCOVERY ? BC_COLLECTION_MANAGERS :
        kind == BC_REDFISH_ETHERNET_DISCOVERY ? BC_COLLECTION_ETHERNET_INTERFACES :
        kind == BC_REDFISH_COLLECTION ? selection : BC_COLLECTION_SYSTEMS;
    op->result.struct_size = sizeof(op->result); op->result.kind = kind; op->result.endpoint_revision = bc_endpoint_revision(endpoint);
    if (kind == BC_REDFISH_DISCOVERY || kind == BC_REDFISH_COLLECTION || kind == BC_REDFISH_SENSOR_DISCOVERY ||
        kind == BC_REDFISH_CHASSIS_DISCOVERY || kind == BC_REDFISH_TASK_DISCOVERY || kind == BC_REDFISH_VIRTUAL_MEDIA_DISCOVERY ||
        kind == BC_REDFISH_MANAGER_DISCOVERY || kind == BC_REDFISH_ETHERNET_DISCOVERY) {
        op->members = calloc(op->options.max_systems, sizeof(bc_string));
        op->collection.members = op->members;
        if (kind == BC_REDFISH_DISCOVERY) op->result.systems = op->members;
        if (!op->members) { bc_redfish_release(op); return BC_NO_MEMORY; }
    }
    int start_root = kind == BC_REDFISH_DISCOVERY || kind == BC_REDFISH_CHASSIS_DISCOVERY || kind == BC_REDFISH_TASK_DISCOVERY || kind == BC_REDFISH_PROBE || kind == BC_REDFISH_MANAGER_DISCOVERY;
    if (kind == BC_REDFISH_PROBE) op->phase = PHASE_PROBE;
    if (!start_root) {
        op->phase = kind == BC_REDFISH_SYSTEM ? PHASE_SYSTEM : PHASE_RESET_SYSTEM; op->result.resource_uri = copy(uri);
        if (!op->result.resource_uri.data) { bc_redfish_release(op); return BC_NO_MEMORY; }
        if (kind == BC_REDFISH_TASK || kind == BC_REDFISH_TASK_MONITOR) {
            op->phase = kind == BC_REDFISH_TASK ? PHASE_TASK : PHASE_TASK_MONITOR;
            bc_string *link = kind == BC_REDFISH_TASK ? &op->task.task_uri : &op->task.monitor_uri;
            *link = copy(uri);
            if (!link->data) { bc_redfish_release(op); return BC_NO_MEMORY; }
        }
        if (kind == BC_REDFISH_BOOT || kind == BC_REDFISH_BOOT_ONCE) op->phase = PHASE_BOOT_READ;
        if (kind == BC_REDFISH_SENSOR || kind == BC_REDFISH_SENSOR_DETAILS) op->phase = PHASE_SENSOR;
        if (kind == BC_REDFISH_RESOURCE) op->phase = PHASE_RESOURCE;
        if (kind == BC_REDFISH_PROBE) op->phase = PHASE_PROBE;
        if (kind == BC_REDFISH_VIRTUAL_MEDIA || kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT || kind == BC_REDFISH_VIRTUAL_MEDIA_EJECT)
            op->phase = PHASE_VM_READ;
        if (kind == BC_REDFISH_VIRTUAL_MEDIA_DISCOVERY) op->phase = PHASE_VM_MANAGER;
        if (kind == BC_REDFISH_GRAPHICAL_CONSOLE) op->phase = PHASE_GRAPHICAL_CONSOLE;
        if (kind == BC_REDFISH_SENSOR_DISCOVERY) op->phase = PHASE_CHASSIS;
        if (kind == BC_REDFISH_COLLECTION) op->phase = PHASE_COLLECTION;
        if (kind == BC_REDFISH_NETWORK_PROTOCOL || kind == BC_REDFISH_ETHERNET_DISCOVERY) op->phase = PHASE_MANAGER_LINK;
        if (kind == BC_REDFISH_ETHERNET_INTERFACE) op->phase = PHASE_ETHERNET;
    }
    bc_status status = kind == BC_REDFISH_COLLECTION ? add_page(op, op->result.resource_uri.data) : get(op, start_root ? "/redfish/v1/" : op->result.resource_uri.data);
    if (status != BC_OK) { bc_redfish_release(op); return status; }
    ++op->refs; *out = op; return BC_OK;
}
bc_status bc_redfish_discover(bc_endpoint *endpoint, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_DISCOVERY, (bc_string){NULL, 0}, 0, out);
}
bc_status bc_redfish_get_boot(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_BOOT, uri, 0, out);
}
bc_status bc_redfish_boot_set_once(bc_endpoint *endpoint, bc_string uri, uint32_t target, uint32_t mode,
    const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (target > BC_BOOT_UEFI_SHELL || mode > BC_BOOT_MODE_UEFI) return BC_INVALID_ARGUMENT;
    bc_status status = create(endpoint, options, callback, userdata, BC_REDFISH_BOOT_ONCE, uri, 0, out);
    if (status == BC_OK) { (*out)->boot_target = target; (*out)->boot_mode = mode; }
    return status;
}
bc_status bc_redfish_get_system(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_SYSTEM, uri, 0, out);
}
bc_status bc_redfish_get_reset_capabilities(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_RESET_CAPABILITIES, uri, 0, out);
}
bc_status bc_redfish_reset(bc_endpoint *endpoint, bc_string uri, uint32_t reset_type, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_RESET, uri, reset_type, out);
}
bc_status bc_redfish_get_task(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_TASK, uri, 0, out);
}
bc_status bc_redfish_get_task_monitor(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_TASK_MONITOR, uri, 0, out);
}
bc_status bc_redfish_get_sensor(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_SENSOR, uri, 0, out);
}
bc_status bc_redfish_get_sensor_details(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_SENSOR_DETAILS, uri, 0, out);
}
bc_status bc_redfish_get_resource(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_RESOURCE, uri, 0, out);
}
bc_status bc_redfish_probe(bc_endpoint *endpoint, const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_PROBE, (bc_string){"/redfish/v1/", 12}, 0, out);
}
static bc_status create_body(bc_endpoint *endpoint, bc_string uri, uint32_t method, bc_bytes body,
    const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, uint32_t kind, bc_redfish_operation **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION || !callback ||
        options->request_timeout_ms > INT32_MAX || !bc_redfish_uri_valid(uri)) return BC_INVALID_ARGUMENT;
    if ((body.length && !body.data) || body.length > BC_REDFISH_MAX_BODY) return BC_INVALID_ARGUMENT;
    if (method == BC_HTTP_PATCH && !body.length) return BC_INVALID_ARGUMENT;
    bc_redfish_operation *op = calloc(1, sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    op->refs = 1; op->endpoint = endpoint; bc_endpoint_retain(endpoint);
    op->options = *options;
    op->callback = callback; op->userdata = userdata;
    op->result.struct_size = sizeof(op->result); op->result.kind = kind; op->result.endpoint_revision = bc_endpoint_revision(endpoint);
    op->result.resource_uri = copy(uri);
    op->resource.struct_size = sizeof(op->resource);
    if (!op->result.resource_uri.data) { bc_redfish_release(op); return BC_NO_MEMORY; }
    op->phase = method == BC_HTTP_POST ? PHASE_ACTION_POST : PHASE_PATCH;
    bc_http_options request = {0};
    request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION;
    request.path = uri; request.timeout_ms = op->options.request_timeout_ms;
    request.method = method; request.body = body;
    bc_redfish_log_request(method == BC_HTTP_POST ? "action" : "patch", endpoint, method, uri, body);
    bc_status status = bc_http_submit(endpoint, &request, http_done, op, &op->request);
    if (status != BC_OK) { bc_redfish_release(op); return status; }
    ++op->refs; *out = op; return BC_OK;
}

bc_status bc_redfish_action(bc_endpoint *endpoint, bc_string uri, bc_bytes body, const bc_redfish_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_body(endpoint, uri, BC_HTTP_POST, body, options, callback, userdata, BC_REDFISH_ACTION, out);
}

bc_status bc_redfish_patch(bc_endpoint *endpoint, bc_string uri, bc_bytes body, const bc_redfish_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_body(endpoint, uri, BC_HTTP_PATCH, body, options, callback, userdata, BC_REDFISH_PATCH, out);
}

static bc_status create_virtual_media(bc_endpoint *endpoint, bc_string uri, uint32_t kind,
    const bc_redfish_virtual_media_insert_options *request, const bc_redfish_options *options, bc_redfish_completion callback,
    void *userdata, bc_redfish_operation **out) {
    if (kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT) {
        if (!request || request->struct_size != sizeof(*request) || !media_url_valid(request->image) ||
            request->write_protected > 1 || request->reserved ||
            (request->transfer_method.length && !request->transfer_method.data) ||
            (request->transfer_protocol_type.length && !request->transfer_protocol_type.data) ||
            request->transfer_method.length > 64 || request->transfer_protocol_type.length > 64) return BC_INVALID_ARGUMENT;
    } else if (request) return BC_INVALID_ARGUMENT;
    bc_status status = create(endpoint, options, callback, userdata, kind, uri, 0, out);
    if (status != BC_OK) return status;
    if (kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT) {
        bc_redfish_operation *op = *out;
        op->insert = *request;
        op->insert.struct_size = sizeof(op->insert);
        op->insert.image = copy(request->image);
        op->insert.transfer_method = copy(request->transfer_method);
        op->insert.transfer_protocol_type = copy(request->transfer_protocol_type);
        if (!op->insert.image.data || (request->transfer_method.length && !op->insert.transfer_method.data) ||
            (request->transfer_protocol_type.length && !op->insert.transfer_protocol_type.data)) {
            bc_redfish_release(op); *out = NULL; return BC_NO_MEMORY;
        }
    }
    return BC_OK;
}

bc_status bc_redfish_get_virtual_media(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_VIRTUAL_MEDIA, uri, 0, out);
}

bc_status bc_redfish_get_graphical_console(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_GRAPHICAL_CONSOLE, uri, 0, out);
}

bc_status bc_redfish_discover_virtual_media(bc_endpoint *endpoint, bc_string manager_uri,
    const bc_redfish_collection_options *options, bc_redfish_completion callback, void *userdata,
    bc_redfish_operation **out) {
    return create(endpoint, &(bc_redfish_options){sizeof(bc_redfish_options), BC_ABI_VERSION,
        options ? options->request_timeout_ms : 5000, options ? options->max_members : 256},
        callback, userdata, BC_REDFISH_VIRTUAL_MEDIA_DISCOVERY, manager_uri, 0, out);
}

bc_status bc_redfish_virtual_media_insert(bc_endpoint *endpoint, bc_string uri, const bc_redfish_virtual_media_insert_options *request,
    const bc_redfish_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_virtual_media(endpoint, uri, BC_REDFISH_VIRTUAL_MEDIA_INSERT, request, options, callback, userdata, out);
}

bc_status bc_redfish_virtual_media_eject(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_virtual_media(endpoint, uri, BC_REDFISH_VIRTUAL_MEDIA_EJECT, NULL, options, callback, userdata, out);
}

static bc_status create_collection(bc_endpoint *endpoint, bc_string uri, uint32_t kind, uint32_t collection_kind, const bc_redfish_collection_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION) return BC_INVALID_ARGUMENT;
    bc_redfish_options mapped = {sizeof(mapped), BC_ABI_VERSION, options->request_timeout_ms, options->max_members};
    return create(endpoint, &mapped, callback, userdata, kind, uri, collection_kind, out);
}
bc_status bc_redfish_discover_chassis(bc_endpoint *endpoint, const bc_redfish_collection_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_collection(endpoint, (bc_string){NULL, 0}, BC_REDFISH_CHASSIS_DISCOVERY, BC_COLLECTION_CHASSIS, options, callback, userdata, out);
}
bc_status bc_redfish_discover_sensors(bc_endpoint *endpoint, bc_string uri, const bc_redfish_collection_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_collection(endpoint, uri, BC_REDFISH_SENSOR_DISCOVERY, BC_COLLECTION_SENSORS, options, callback, userdata, out);
}
bc_status bc_redfish_get_collection(bc_endpoint *endpoint, bc_string uri, uint32_t kind, const bc_redfish_collection_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_collection(endpoint, uri, BC_REDFISH_COLLECTION, kind, options, callback, userdata, out);
}

bc_status bc_redfish_discover_tasks(bc_endpoint *endpoint, const bc_redfish_collection_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_collection(endpoint, (bc_string){NULL, 0}, BC_REDFISH_TASK_DISCOVERY, BC_COLLECTION_TASKS, options, callback, userdata, out);
}
bc_status bc_redfish_discover_managers(bc_endpoint *endpoint, const bc_redfish_collection_options *options, bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_collection(endpoint, (bc_string){NULL, 0}, BC_REDFISH_MANAGER_DISCOVERY, BC_COLLECTION_MANAGERS, options, callback, userdata, out);
}
bc_status bc_redfish_get_network_protocol(bc_endpoint *endpoint, bc_string manager_uri, const bc_redfish_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_NETWORK_PROTOCOL, manager_uri, 0, out);
}
bc_status bc_redfish_discover_ethernet(bc_endpoint *endpoint, bc_string manager_uri, const bc_redfish_collection_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create_collection(endpoint, manager_uri, BC_REDFISH_ETHERNET_DISCOVERY, BC_COLLECTION_ETHERNET_INTERFACES, options, callback, userdata, out);
}
bc_status bc_redfish_get_ethernet_interface(bc_endpoint *endpoint, bc_string uri, const bc_redfish_options *options,
    bc_redfish_completion callback, void *userdata, bc_redfish_operation **out) {
    return create(endpoint, options, callback, userdata, BC_REDFISH_ETHERNET_INTERFACE, uri, 0, out);
}

static int task_reference_operations(const bc_redfish_operation *value, const bc_redfish_operation *discovery) {
    return value && discovery && value->done && discovery->done && value->result.status == BC_OK && discovery->result.status == BC_OK &&
        discovery->result.kind == BC_REDFISH_TASK_DISCOVERY && discovery->collection.collection_kind == BC_COLLECTION_TASKS &&
        value->endpoint == discovery->endpoint && value->result.endpoint_revision == discovery->result.endpoint_revision &&
        value->result.endpoint_revision == bc_endpoint_revision(value->endpoint);
}
bc_status bc_redfish_task_reference_capture_operation(const bc_redfish_operation *write, const bc_redfish_operation *discovery,
    bc_string endpoint_id, bc_string address_digest, bc_redfish_task_reference *reference, unsigned char *output, uint32_t capacity, uint32_t *written) {
    if (reference) memset(reference, 0, sizeof(*reference));
    if (written) *written = 0;
    if (output && capacity) output[0] = 0;
    if (!output || !capacity || !written) return BC_INVALID_ARGUMENT;
    if (!task_reference_operations(write, discovery) ||
        (write->result.kind != BC_REDFISH_VIRTUAL_MEDIA_INSERT && write->result.kind != BC_REDFISH_VIRTUAL_MEDIA_EJECT) ||
        !(write->result.flags & BC_REDFISH_COMMAND_SUBMITTED) || !(write->result.flags & BC_REDFISH_COMMAND_ACCEPTED) ||
        write->submitted_method != BC_HTTP_POST || !write->task_identity.length) return BC_UNSUPPORTED;
    bc_redfish_task_binding binding = {0}; binding.struct_size = sizeof(binding);
    binding.action = write->result.kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT ? BC_REDFISH_TASK_REFERENCE_INSERT : BC_REDFISH_TASK_REFERENCE_EJECT;
    binding.http_method = write->submitted_method; binding.endpoint_id = endpoint_id; binding.address_digest = address_digest;
    binding.collection_uri = discovery->result.resource_uri; binding.media_uri = write->result.resource_uri;
    binding.target_uri = write->result.kind == BC_REDFISH_VIRTUAL_MEDIA_INSERT ? write->media.insert_target : write->media.eject_target;
    bc_status status = bc_redfish_task_reference_export(write->task_identity, &binding, output, capacity, written);
    if (status == BC_OK && reference) status = bc_redfish_task_reference_import((bc_bytes){output, *written}, &binding, reference);
    if (status != BC_OK) { output[0] = 0; *written = 0; }
    return status;
}
bc_status bc_redfish_task_reference_export_operation(const bc_redfish_operation *write, const bc_redfish_operation *discovery,
    bc_string endpoint_id, bc_string address_digest, unsigned char *output, uint32_t capacity, uint32_t *written) {
    return bc_redfish_task_reference_capture_operation(write, discovery, endpoint_id, address_digest, NULL, output, capacity, written);
}
bc_status bc_redfish_task_reference_restore_operation(bc_bytes saved, const bc_redfish_operation *media, const bc_redfish_operation *discovery,
    bc_string endpoint_id, bc_string address_digest, uint32_t action, bc_redfish_task_reference *reference) {
    if (!reference) return BC_INVALID_ARGUMENT;
    memset(reference, 0, sizeof(*reference));
    if (!task_reference_operations(media, discovery) || media->result.kind != BC_REDFISH_VIRTUAL_MEDIA ||
        (action != BC_REDFISH_TASK_REFERENCE_INSERT && action != BC_REDFISH_TASK_REFERENCE_EJECT)) return BC_UNSUPPORTED;
    bc_redfish_task_binding binding = {0}; binding.struct_size = sizeof(binding); binding.action = action; binding.http_method = BC_HTTP_POST;
    binding.endpoint_id = endpoint_id; binding.address_digest = address_digest; binding.collection_uri = discovery->result.resource_uri;
    binding.media_uri = media->result.resource_uri;
    binding.target_uri = action == BC_REDFISH_TASK_REFERENCE_INSERT ? media->media.insert_target : media->media.eject_target;
    return bc_redfish_task_reference_import(saved, &binding, reference);
}
bc_status bc_redfish_task_reference_match_operation(const bc_redfish_task_reference *reference, const bc_redfish_operation *read,
    const bc_redfish_operation *discovery, bc_string endpoint_id, bc_string address_digest, uint32_t *flags) {
    if (flags) *flags = 0;
    if (!reference || !flags) return BC_INVALID_ARGUMENT;
    if (!task_reference_operations(read, discovery) || read->result.kind != BC_REDFISH_TASK || !read->task_identity.length) return BC_UNSUPPORTED;
    bc_redfish_task_binding binding = {0}; binding.struct_size = sizeof(binding);
    binding.action = reference->action; binding.http_method = reference->http_method; binding.endpoint_id = endpoint_id; binding.address_digest = address_digest;
    binding.collection_uri = discovery->result.resource_uri;
    if (!memchr(reference->collection_uri, 0, sizeof(reference->collection_uri)) ||
        !memchr(reference->media_uri, 0, sizeof(reference->media_uri)) || !memchr(reference->target_uri, 0, sizeof(reference->target_uri)) ||
        !memchr(reference->task_uri, 0, sizeof(reference->task_uri))) return BC_INVALID_ARGUMENT;
    binding.media_uri = str(reference->media_uri); binding.target_uri = str(reference->target_uri);
    unsigned char saved[BC_REDFISH_TASK_REFERENCE_MAX]; uint32_t length = 0;
    bc_status status = bc_redfish_task_reference_export(read->task_identity, &binding, saved, sizeof(saved), &length);
    bc_redfish_task_reference checked;
    if (status == BC_OK) status = bc_redfish_task_reference_import((bc_bytes){saved, length}, &binding, &checked);
    if (status != BC_OK || strcmp(checked.collection_uri, reference->collection_uri) || read->result.resource_uri.length != strlen(reference->task_uri) ||
        memcmp(read->result.resource_uri.data, reference->task_uri, (size_t)read->result.resource_uri.length)) return BC_UNSUPPORTED;
    if (!memchr(reference->endpoint_id, 0, sizeof(reference->endpoint_id)) || !memchr(reference->address_digest, 0, sizeof(reference->address_digest)) ||
        endpoint_id.length != strlen(reference->endpoint_id) || address_digest.length != strlen(reference->address_digest) ||
        !endpoint_id.data || !address_digest.data || memcmp(endpoint_id.data, reference->endpoint_id, (size_t)endpoint_id.length) ||
        memcmp(address_digest.data, reference->address_digest, (size_t)address_digest.length)) return BC_UNSUPPORTED;
    return bc_redfish_task_reference_match(reference, read->task_identity, flags);
}

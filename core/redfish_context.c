#include "redfish_internal.h"
#include <stdlib.h>
#include <string.h>

static bc_status text(yyjson_val *root, const char *key, bc_string *out) {
    yyjson_val *item = yyjson_obj_get(root, key);
    if (!item || yyjson_is_null(item)) return BC_OK;
    const char *s = yyjson_get_str(item); size_t n = yyjson_get_len(item);
    if (!s || n > 1024 || strlen(s) != n) return BC_PROTOCOL_ERROR;
    char *copy = malloc(n + 1); if (!copy) return BC_NO_MEMORY;
    memcpy(copy, s, n + 1); *out = (bc_string){copy, n}; return BC_OK;
}
static void clear_links(const bc_string *items, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) free((void *)items[i].data);
    free((void *)items);
}
void bc_redfish_clear_context(bc_redfish_context_info *info) {
    free((void *)info->physical_context.data); free((void *)info->reading_basis.data);
    free((void *)info->sensor_collection_uri.data); free((void *)info->thermal_uri.data);
    clear_links(info->related_items, info->related_count);
    clear_links(info->chassis, info->chassis_count); clear_links(info->systems, info->system_count);
    memset(info, 0, sizeof(*info));
}
static int local_uri(const char *s, size_t n, int fragment) {
    const char *hash = memchr(s, '#', n);
    if (!hash) return bc_redfish_uri_valid((bc_string){s, n});
    if (!fragment || !bc_redfish_uri_valid((bc_string){s, (uint64_t)(hash - s)})) return 0;
    for (const char *p = hash + 1; p < s + n; ++p)
        if ((unsigned char)*p <= 32 || *p == 127 || *p == '\\' || *p == '#') return 0;
    return 1;
}
static bc_status link(yyjson_val *root, const char *key, bc_string *out) {
    yyjson_val *item = yyjson_obj_get(root, key);
    if (!item || yyjson_is_null(item)) return BC_OK;
    if (!yyjson_is_obj(item)) return BC_PROTOCOL_ERROR;
    bc_status status = text(item, "@odata.id", out);
    if (status == BC_OK && !out->data) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK && !bc_redfish_uri_valid(*out)) status = BC_UNSUPPORTED;
    return status;
}
static bc_status links(yyjson_val *root, const char *key, const bc_string **out, uint32_t *count, int fragment) {
    yyjson_val *array = yyjson_obj_get(root, key);
    if (!array || yyjson_is_null(array)) return BC_OK;
    if (!yyjson_is_arr(array)) return BC_PROTOCOL_ERROR;
    size_t length = yyjson_arr_size(array);
    if (length > BC_REDFISH_MAX_CONTEXT_LINKS) return BC_LIMIT_EXCEEDED;
    if (!length) return BC_OK;
    bc_string *items = calloc(length, sizeof(*items)); if (!items) return BC_NO_MEMORY;
    *out = items;
    size_t i, max; yyjson_val *item;
    yyjson_arr_foreach(array, i, max, item) {
        yyjson_val *id = yyjson_obj_get(item, "@odata.id");
        const char *s = yyjson_get_str(id); size_t n = yyjson_get_len(id);
        if (!yyjson_is_obj(item) || !s || !n || n > 8192 || strlen(s) != n) return BC_PROTOCOL_ERROR;
        if (!local_uri(s, n, fragment)) return BC_UNSUPPORTED;
        int duplicate = 0;
        for (uint32_t j = 0; j < *count; ++j) if (!strcmp(items[j].data, s)) { duplicate = 1; break; }
        if (duplicate) continue;
        char *copy = malloc(n + 1); if (!copy) return BC_NO_MEMORY;
        memcpy(copy, s, n + 1); items[(*count)++] = (bc_string){copy, n};
    }
    return BC_OK;
}
static void filter_chassis_subresources(yyjson_val *root, bc_string uri, bc_redfish_context_info *info) {
    static const char prefix[] = "/redfish/v1/Chassis/";
    if (!info->system_count || !uri.data || uri.length <= sizeof(prefix) - 1 ||
        memcmp(uri.data, prefix, sizeof(prefix) - 1) ||
        memchr(uri.data + sizeof(prefix) - 1, '/', (size_t)uri.length - (sizeof(prefix) - 1)) ||
        memchr(uri.data, '?', (size_t)uri.length) ||
        !bc_redfish_resource_type(root, "#Chassis.", ".Chassis")) return;
    bc_string *systems = (bc_string *)info->systems;
    uint32_t kept = 0;
    for (uint32_t i = 0; i < info->system_count; ++i) {
        bc_string system = systems[i];
        if (system.length > uri.length + 1 && system.data[uri.length] == '/' &&
            !memcmp(system.data, uri.data, (size_t)uri.length) &&
            strcmp(system.data + uri.length + 1, "Oem") &&
            strncmp(system.data + uri.length + 1, "Oem/", 4)) {
            free((void *)system.data);
            info->flags |= BC_REDFISH_CONTEXT_CHASSIS_SUBRESOURCE_LINK;
        } else systems[kept++] = system;
    }
    info->system_count = kept;
}
void bc_redfish_parse_context(yyjson_val *root, bc_string uri, bc_redfish_context_info *info) {
    bc_status status = text(root, "PhysicalContext", &info->physical_context);
    if (yyjson_obj_get(root, "ReadingBasis")) info->flags |= BC_REDFISH_CONTEXT_BASIS_PRESENT;
    if (status == BC_OK) status = text(root, "ReadingBasis", &info->reading_basis);
    yyjson_val *enabled = yyjson_obj_get(root, "Enabled");
    if (enabled) {
        info->flags |= BC_REDFISH_CONTEXT_ENABLED_PRESENT;
        if (yyjson_is_true(enabled)) info->enabled = 1;
        else if (!yyjson_is_false(enabled) && !yyjson_is_null(enabled)) status = BC_PROTOCOL_ERROR;
    }
    if (status == BC_OK) status = links(root, "RelatedItem", &info->related_items, &info->related_count, 1);
    if (status == BC_OK) status = link(root, "Sensors", &info->sensor_collection_uri);
    if (status == BC_OK) status = link(root, "Thermal", &info->thermal_uri);
    yyjson_val *related = yyjson_obj_get(root, "Links");
    if (status == BC_OK && related && !yyjson_is_null(related)) {
        if (!yyjson_is_obj(related)) status = BC_PROTOCOL_ERROR;
        else {
            status = links(related, "Chassis", &info->chassis, &info->chassis_count, 0);
            if (status == BC_OK) status = links(related, "ComputerSystems", &info->systems, &info->system_count, 0);
        }
    }
    if (status == BC_OK) filter_chassis_subresources(root, uri, info);
    else bc_redfish_clear_context(info);
    info->struct_size = sizeof(*info); info->status = status;
}

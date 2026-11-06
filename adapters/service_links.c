#include "bcontrol/console_discovery.h"
#include "bcontrol/redfish.h"
#include "yyjson.h"
#include "discovery_internal.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    bc_string manager;
    bc_console_metadata_link links[32];
    uint32_t count;
} link_reader;
static int equal(yyjson_val *v, const char *s) {
    return yyjson_is_str(v) && yyjson_get_len(v) == strlen(s) && !memcmp(yyjson_get_str(v), s, strlen(s));
}
static int unique_field(yyjson_val *obj, const char *name, yyjson_val **out) {
    *out = NULL;
    size_t i, n; yyjson_val *key, *value;
    yyjson_obj_foreach(obj, i, n, key, value) {
        if (!equal(key, name)) continue;
        if (*out) return 0;
        *out = value;
    }
    return 1;
}
static bc_status add_one(link_reader *r, yyjson_val *value, uint32_t kind) {
    if (yyjson_is_null(value)) return BC_OK;
    if (!yyjson_is_obj(value)) return BC_PROTOCOL_ERROR;
    yyjson_val *id;
    if (!unique_field(value, "@odata.id", &id)) return BC_PROTOCOL_ERROR;
    if (!id) return BC_OK;
    if (!yyjson_is_str(id)) return BC_PROTOCOL_ERROR;
    bc_string uri = {yyjson_get_str(id), yyjson_get_len(id)};
    if (!bc_redfish_uri_supported(uri) || uri.length > 1024 || uri.length <= r->manager.length ||
        !bc_discovery_uri_matches((bc_string){uri.data, r->manager.length}, r->manager,
            "/redfish/v1/Managers/*") || uri.data[r->manager.length] != '/')
        return BC_PROTOCOL_ERROR;
    for (uint64_t i = 0; i < uri.length; ++i)
        if (uri.data[i] == '?' || uri.data[i] == '%') return BC_PROTOCOL_ERROR;
    for (uint32_t i = 0; i < r->count; ++i)
        if (r->links[i].kind == kind && !strcmp(r->links[i].uri, uri.data)) return BC_OK;
    if (r->count == 32) return BC_LIMIT_EXCEEDED;
    bc_console_metadata_link *out = &r->links[r->count++];
    out->kind = kind; memcpy(out->uri, uri.data, (size_t)uri.length); out->uri[uri.length] = 0;
    return BC_OK;
}
static bc_status add(link_reader *r, yyjson_val *value, uint32_t kind) {
    if (!yyjson_is_arr(value)) return add_one(r, value, kind);
    size_t i, n; yyjson_val *entry;
    yyjson_arr_foreach(value, i, n, entry) {
        if (!yyjson_is_obj(entry)) return BC_PROTOCOL_ERROR;
        bc_status status = add_one(r, entry, kind);
        if (status != BC_OK) return status;
    }
    return BC_OK;
}
static bc_status walk(link_reader *r, yyjson_val *v, uint32_t depth) {
    if (depth > 32) return BC_LIMIT_EXCEEDED;
    size_t i, n; yyjson_val *key, *value;
    if (yyjson_is_obj(v)) {
        yyjson_val *unused;
        if (!unique_field(v, "KvmService", &unused) || !unique_field(v, "Attributes", &unused) ||
            !unique_field(v, "DellAttributes", &unused)) return BC_PROTOCOL_ERROR;
        yyjson_obj_foreach(v, i, n, key, value) {
            uint32_t kind = equal(key, "KvmService") ? BC_CONSOLE_METADATA_KVM :
                equal(key, "Attributes") || equal(key, "DellAttributes") ? BC_CONSOLE_METADATA_ATTRIBUTES : 0;
            bc_status status = kind ? add(r, value, kind) : BC_OK;
            if (status != BC_OK) return status;
            if (equal(key, "Actions")) continue;
            status = walk(r, value, depth + 1);
            if (status != BC_OK) return status;
        }
    } else if (yyjson_is_arr(v)) {
        yyjson_arr_foreach(v, i, n, value) {
            bc_status status = walk(r, value, depth + 1);
            if (status != BC_OK) return status;
        }
    }
    return BC_OK;
}
bc_status bc_console_manager_metadata_links(const uint8_t *data, uint32_t length,
    bc_string manager, bc_console_metadata_link *out, uint32_t capacity, uint32_t *written) {
    if (written) *written = 0;
    if (!out || !written || !capacity || capacity > 32) return BC_INVALID_ARGUMENT;
    memset(out, 0, (size_t)capacity * sizeof(*out));
    manager = bc_discovery_resource_path(manager);
    if (!data || !length || manager.length > 1024 ||
        !bc_discovery_uri_matches(manager, manager, "/redfish/v1/Managers/*")) return BC_INVALID_ARGUMENT;
    if (length > 65536) return BC_LIMIT_EXCEEDED;
    yyjson_doc *doc = yyjson_read((const char *)data, length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL, *id;
    bc_status status = BC_PROTOCOL_ERROR;
    link_reader *reader = calloc(1, sizeof(*reader));
    if (!reader) status = BC_NO_MEMORY;
    else if (yyjson_is_obj(root) && unique_field(root, "@odata.id", &id) && yyjson_is_str(id) &&
        bc_discovery_uri_matches(bc_discovery_resource_path((bc_string){yyjson_get_str(id), yyjson_get_len(id)}), manager,
            "/redfish/v1/Managers/*")) {
        reader->manager = manager;
        status = walk(reader, root, 0);
        if (status == BC_OK && reader->count > capacity) status = BC_LIMIT_EXCEEDED;
        if (status == BC_OK) {
            memcpy(out, reader->links, (size_t)reader->count * sizeof(*out)); *written = reader->count;
        }
    }
    free(reader); if (doc) yyjson_doc_free(doc);
    return status;
}

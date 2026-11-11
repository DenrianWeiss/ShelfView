#include "bcontrol/zte.h"
#include "../megarac/probe_internal.h"
#include "yyjson.h"
#include <stdio.h>
#include <string.h>

static yyjson_doc *document(const uint8_t *data, uint32_t length) {
    return data && length && length <= 65536 ? yyjson_read((const char *)data, length, 0) : NULL;
}
static int equals(yyjson_val *v, const char *text) {
    return yyjson_is_str(v) && yyjson_get_len(v) == strlen(text) && !memcmp(yyjson_get_str(v), text, strlen(text));
}
static yyjson_val *field(yyjson_val *root, const char *name) {
    yyjson_val *found = NULL, *key, *value; size_t i, n;
    yyjson_obj_foreach(root, i, n, key, value) {
        if (!equals(key, name)) continue;
        if (found) return NULL;
        found = value;
    }
    return found;
}
int bc_zte_service_root_matches(const uint8_t *data, uint32_t length) {
    yyjson_doc *doc = document(data, length);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    int matches = yyjson_is_obj(root) && equals(field(root, "Product"), "ZTE Redfish Server") &&
        yyjson_is_str(field(root, "RedfishVersion"));
    if (doc) yyjson_doc_free(doc);
    return matches;
}
static int manager_link(yyjson_val *link, const char *key, bc_string manager, const char *suffix) {
    yyjson_val *value = field(link, key);
    const char *path = yyjson_get_str(value);
    size_t n = strlen(suffix);
    return path && yyjson_get_len(value) == manager.length + n &&
        !memcmp(path, manager.data, (size_t)manager.length) &&
        !memcmp(path + manager.length, suffix, n);
}
int bc_zte_manager_matches(const uint8_t *data, uint32_t length, bc_string manager) {
    if (!manager.data || manager.length <= 21 || manager.length > 1024 ||
        memcmp(manager.data, "/redfish/v1/Managers/", 21)) return 0;
    yyjson_doc *doc = document(data, length);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_val *actions = field(field(root, "Actions"), "Oem");
    int matches = manager_link(root, "@odata.id", manager, "") &&
        manager_link(field(root, "KvmService"), "@odata.id", manager, "/KvmService") &&
        manager_link(field(actions, "#Manager.Dump"), "target", manager, "/Actions/Oem/ZTE/Manager.Dump");
    if (doc) yyjson_doc_free(doc);
    return matches;
}
bc_status bc_zte_kvm_token(const uint8_t *data, uint32_t length, bc_string origin,
    char *out, uint32_t capacity) {
    if (!out || !capacity) return BC_INVALID_ARGUMENT;
    memset(out, 0, capacity);
    if (!origin.data || origin.length < 9 || origin.length > 1024 ||
        memcmp(origin.data, "https://", 8)) return BC_INVALID_ARGUMENT;
    if (length > 65536) return BC_LIMIT_EXCEEDED;
    yyjson_doc *doc = document(data, length);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    bc_status status = BC_PROTOCOL_ERROR;
    if (!yyjson_is_obj(root)) goto done;
    yyjson_val *value = field(root, "KvmUrl");
    if (!value) { status = BC_UNSUPPORTED; goto done; }
    yyjson_val *type_value = field(root, "@odata.type"), *id_value = field(root, "@odata.id");
    const char *url = yyjson_get_str(value), *type = yyjson_get_str(type_value);
    const char *id = yyjson_get_str(id_value);
    if (!url || !type || !id || strncmp(type, "#KvmService.v", 13) ||
        strncmp(id, "/redfish/v1/Managers/", 21) || strlen(id) != yyjson_get_len(id_value) ||
        strlen(type) != yyjson_get_len(type_value) || strlen(type) < 25 ||
        strcmp(type + strlen(type) - 11, ".KvmService") || strpbrk(id, "?#%\\")) goto done;
    const char *suffix = strchr(id + 21, '/');
    if (!suffix || suffix == id + 21 || strcmp(suffix, "/KvmService")) goto done;
    size_t size = (size_t)origin.length;
    while (size > 8 && origin.data[size - 1] == '/') --size;
    if (yyjson_get_len(value) <= size || memcmp(url, origin.data, size)) goto done;
    const char *path = url + size;
    if (!strncmp(path, ":443/", 5) && !memchr(origin.data + 8, ':', size - 8)) path += 4;
    if (strncmp(path, "/viewer.html?", 13)) goto done;
    const char *token = path + 13;
    if (*token == '&') ++token;
    if (strncmp(token, "token=", 6)) goto done;
    token += 6;
    size_t count = strlen(token);
    if (!count || count > 128 || strlen(url) != yyjson_get_len(value)) goto done;
    for (size_t i = 0; i < count; ++i) {
        unsigned char c = (unsigned char)token[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_')) goto done;
    }
    if (count >= capacity) { status = BC_LIMIT_EXCEEDED; goto done; }
    memcpy(out, token, count); status = BC_OK;
done:
    if (doc) yyjson_doc_free(doc);
    return status;
}
static bc_status h5_mode(const bc_response *response, int *use_h5) {
    *use_h5 = 1;
    if (response->http_status == 404 || response->http_status == 405) return BC_OK;
    if (response->status != BC_OK) return response->status;
    if (response->http_status != 200) return BC_HTTP_ERROR;
    yyjson_doc *doc = response->body.length <= 65536 ?
        document(response->body.data, (uint32_t)response->body.length) : NULL;
    yyjson_val *flag = doc ? field(yyjson_doc_get_root(doc), "h5kvm_enableflag") : NULL;
    bc_status status = BC_PROTOCOL_ERROR;
    if (yyjson_is_uint(flag) && yyjson_get_uint(flag) <= 1) {
        *use_h5 = yyjson_get_uint(flag) == 1;
        status = BC_OK;
    }
    if (doc) yyjson_doc_free(doc);
    return status;
}
bc_status bc_zte_kvm_probe_start(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    const uint8_t *data, uint32_t length, bc_megarac_probe_completion callback, void *user, bc_megarac_probe **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint) return BC_INVALID_ARGUMENT;
    char token[129], body[192];
    bc_status status = bc_zte_kvm_token(data, length, bc_endpoint_origin(endpoint), token, sizeof(token));
    if (status == BC_OK) {
        int count = snprintf(body, sizeof(body), "cmccflag=true&cmcctoken=%s&kvmflag=true", token);
        status = bc_megarac_probe_start_form(endpoint, options,
            (bc_bytes){(const uint8_t *)body, (uint64_t)count},
            "/api/settings/media/remote/h5kvm_enable_flag", h5_mode, callback, user, out);
    }
    volatile unsigned char *p = (volatile unsigned char *)token;
    for (size_t i = 0; i < sizeof(token); ++i) p[i] = 0;
    p = (volatile unsigned char *)body;
    for (size_t i = 0; i < sizeof(body); ++i) p[i] = 0;
    return status;
}

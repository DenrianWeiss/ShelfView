#include "h5_internal.h"
#include "yyjson.h"
#include <stdlib.h>
#include <string.h>

bc_status bc_megarac_split_h5_config(const uint8_t *token, uint32_t token_length,
    const uint8_t *config, uint32_t config_length, int inspur_viewer, bc_megarac_kvm_info *info, bc_service_profile *profile) {
    if (!info || !profile || !token || !config || token_length > 65536 || config_length > 65536) return BC_INVALID_ARGUMENT;
    yyjson_doc *doc = yyjson_read((const char *)config, config_length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    /* The Inspur viewer opens /kvm independently of the legacy single-port setting. */
    int enabled = yyjson_get_uint(yyjson_obj_get(root, "status")) == 1 &&
        (inspur_viewer || yyjson_get_uint(yyjson_obj_get(root, "singleport_status")) == 1);
    if (doc) yyjson_doc_free(doc);
    if (!enabled) return BC_UNSUPPORTED;
    /* Reuse the strict token-field parser; this generation has no server-IP field on wire. */
    doc = yyjson_read((const char *)token, token_length, 0);
    root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_mut_doc *copy = root ? yyjson_doc_mut_copy(doc, NULL) : NULL;
    if (doc) yyjson_doc_free(doc);
    if (!copy) return BC_PROTOCOL_ERROR;
    yyjson_mut_obj_add_str(copy, yyjson_mut_doc_get_root(copy), "server_ip", "unused");
    size_t n = 0; char *json = yyjson_mut_write(copy, 0, &n); yyjson_mut_doc_free(copy);
    bc_status status = json ? bc_megarac_discover_h5_config((const uint8_t *)json, (uint32_t)n, info, profile) : BC_NO_MEMORY;
    if (json) { volatile char *wipe = json; for (size_t i = 0; i < n; ++i) wipe[i] = 0; free(json); }
    if (status == BC_OK) {
        info->kind = BC_MEGARAC_KVM_H5VIEWER_373; info->server_ip[0] = 0;
        profile->variant = BC_SERVICE_MEGARAC_KVM_H5_373;
    }
    return status;
}
bc_status bc_megarac_split_h5_media(const uint8_t *data, uint32_t length, int web_proxy, bc_megarac_media_parameters *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    yyjson_doc *doc = data && length <= 65536 ? yyjson_read((const char *)data, length, 0) : NULL;
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    uint64_t count = yyjson_get_uint(yyjson_obj_get(root, "num_cd"));
    uint64_t kvm = yyjson_get_uint(yyjson_obj_get(root, "kvm_num_cd"));
    int enabled = yyjson_get_uint(yyjson_obj_get(root, "cd_status")) == 1 &&
        (web_proxy || yyjson_get_uint(yyjson_obj_get(root, "single_port_enabled")) == 1) &&
        count && count <= 255 && kvm && kvm <= count;
    if (enabled) *out = (bc_megarac_media_parameters){sizeof(*out), BC_MEGARAC_MEDIA_WEBSOCKET |
        BC_MEGARAC_MEDIA_DEVICES_PRESENT, 0, 0, 0, (uint32_t)kvm, 1};
    if (doc) yyjson_doc_free(doc);
    return enabled ? BC_OK : BC_UNSUPPORTED;
}

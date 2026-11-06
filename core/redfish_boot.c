#include "bcontrol/redfish.h"
#include "redfish_internal.h"
#include <stdio.h>
#include <string.h>

static const char *const targets[] = {"None", "Pxe", "Hdd", "Cd", "BiosSetup", "Usb", "UefiShell"};
static uint32_t target(const char *name) {
    for (uint32_t i = 0; name && i < sizeof(targets) / sizeof(targets[0]); ++i) if (!strcmp(name, targets[i])) return i;
    return BC_BOOT_UNKNOWN;
}
static const char *string(yyjson_val *v) {
    const char *s = yyjson_get_str(v);
    return s && yyjson_get_len(v) <= 128 && strlen(s) == yyjson_get_len(v) ? s : NULL;
}
bc_status bc_redfish_boot_parse(bc_bytes json, bc_redfish_boot_info *out) {
    if (!json.data || !json.length || json.length > BC_REDFISH_MAX_BODY || !out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->boot.struct_size = sizeof(out->boot);
    out->boot.target = BC_BOOT_UNKNOWN;
    yyjson_doc *doc = yyjson_read((const char *)json.data, (size_t)json.length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL, *boot = yyjson_obj_get(root, "Boot");
    bc_status status = !yyjson_is_obj(root) ? BC_PROTOCOL_ERROR : !boot || yyjson_is_null(boot) ? BC_UNSUPPORTED : BC_OK;
    if (status == BC_OK && !bc_redfish_resource_type(root, "#ComputerSystem.", ".ComputerSystem")) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK && !yyjson_is_obj(boot)) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) {
        const char *enabled = string(yyjson_obj_get(boot, "BootSourceOverrideEnabled"));
        const char *selected = string(yyjson_obj_get(boot, "BootSourceOverrideTarget"));
        if (!enabled || !selected) status = BC_UNSUPPORTED;
        else {
            if (!strcmp(enabled, "Once")) out->boot.flags |= BC_BOOT_ENABLED;
            else if (!strcmp(enabled, "Continuous")) out->boot.flags |= BC_BOOT_ENABLED | BC_BOOT_PERSISTENT;
            else if (strcmp(enabled, "Disabled")) status = BC_UNSUPPORTED;
            out->boot.target = target(selected);
            const char *mode = string(yyjson_obj_get(boot, "BootSourceOverrideMode"));
            if (mode && !strcmp(mode, "UEFI")) out->boot.mode = BC_BOOT_MODE_UEFI;
            else if (mode && !strcmp(mode, "Legacy")) out->boot.mode = BC_BOOT_MODE_LEGACY;
            yyjson_val *values = yyjson_obj_get(boot, "BootSourceOverrideTarget@Redfish.AllowableValues");
            if (values) {
                if (!yyjson_is_arr(values) || yyjson_arr_size(values) > 64) status = BC_PROTOCOL_ERROR;
                else {
                    out->boot.flags |= BC_BOOT_TARGETS_KNOWN;
                    size_t i, n; yyjson_val *v;
                    yyjson_arr_foreach(values, i, n, v) {
                        const char *name = string(v); uint32_t id = target(name);
                        if (!name) status = BC_PROTOCOL_ERROR;
                        if (id != BC_BOOT_UNKNOWN) out->boot.supported_targets |= UINT32_C(1) << id;
                    }
                }
            }
            values = yyjson_obj_get(boot, "BootSourceOverrideEnabled@Redfish.AllowableValues");
            if (!values) out->boot.flags |= BC_BOOT_ONCE_INFERRED;
            else if (!yyjson_is_arr(values) || yyjson_arr_size(values) > 16) status = BC_PROTOCOL_ERROR;
            else {
                size_t i, n; yyjson_val *v;
                yyjson_arr_foreach(values, i, n, v) {
                    const char *name = string(v);
                    if (!name) status = BC_PROTOCOL_ERROR;
                    else if (!strcmp(name, "Once")) out->boot.flags |= BC_BOOT_ONCE_SUPPORTED;
                }
            }
            values = yyjson_obj_get(boot, "BootSourceOverrideMode@Redfish.AllowableValues");
            if (!values && out->boot.mode) out->supported_modes = (1u << BC_BOOT_MODE_LEGACY) | (1u << BC_BOOT_MODE_UEFI);
            else if (values) {
                if (!yyjson_is_arr(values) || yyjson_arr_size(values) > 16) status = BC_PROTOCOL_ERROR;
                else {
                    size_t i, n; yyjson_val *v;
                    yyjson_arr_foreach(values, i, n, v) {
                        const char *name = string(v);
                        if (!name) status = BC_PROTOCOL_ERROR;
                        else if (!strcmp(name, "Legacy")) out->supported_modes |= 1u << BC_BOOT_MODE_LEGACY;
                        else if (!strcmp(name, "UEFI")) out->supported_modes |= 1u << BC_BOOT_MODE_UEFI;
                    }
                }
            }
        }
    }
    if (doc) yyjson_doc_free(doc);
    out->boot.status = status; return status;
}
bc_status bc_redfish_boot_patch_build(const bc_redfish_boot_info *info, uint32_t selected, uint32_t mode,
    uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!info || info->struct_size != sizeof(*info) || !out || !written || mode > BC_BOOT_MODE_UEFI || selected >= sizeof(targets) / sizeof(targets[0])) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (info->boot.status != BC_OK) return info->boot.status;
    if (selected != BC_BOOT_NONE && (!(info->boot.flags & BC_BOOT_TARGETS_KNOWN) ||
        !(info->boot.supported_targets & (1u << selected)) || !(info->boot.flags & (BC_BOOT_ONCE_SUPPORTED | BC_BOOT_ONCE_INFERRED)))) return BC_UNSUPPORTED;
    if (selected != BC_BOOT_NONE && mode && !(info->supported_modes & (1u << mode))) return BC_UNSUPPORTED;
    char body[256]; int size;
    if (selected == BC_BOOT_NONE) size = snprintf(body, sizeof(body), "{\"Boot\":{\"BootSourceOverrideEnabled\":\"Disabled\"}}");
    else size = snprintf(body, sizeof(body), "{\"Boot\":{\"BootSourceOverrideEnabled\":\"Once\",\"BootSourceOverrideTarget\":\"%s\"%s%s%s}}",
        targets[selected], mode ? ",\"BootSourceOverrideMode\":\"" : "", mode ? (mode == BC_BOOT_MODE_UEFI ? "UEFI" : "Legacy") : "", mode ? "\"" : "");
    if (size < 0 || (uint32_t)size > capacity) return BC_LIMIT_EXCEEDED;
    memcpy(out, body, (size_t)size); *written = (uint32_t)size; return BC_OK;
}

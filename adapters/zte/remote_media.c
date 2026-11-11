#include "remote_media.h"
#include <string.h>

static int equals(yyjson_val *value, bc_string text) {
    return yyjson_is_str(value) && yyjson_get_len(value) == text.length &&
        !memcmp(yyjson_get_str(value), text.data, (size_t)text.length);
}

bc_status bc_zte_media_target(yyjson_val *root, bc_string slot, const char **target, const char **media_type) {
    static const char suffix[] = "/Oem/ZTE/Actions/VirtualMedia.VmmControl";
    *target = NULL;
    *media_type = NULL;
    yyjson_val *oem = yyjson_obj_get(yyjson_obj_get(root, "Oem"), "Public");
    yyjson_val *action = yyjson_obj_get(yyjson_obj_get(oem, "Actions"), "#VirtualMedia.VmmControl");
    if (!action) return BC_UNSUPPORTED;
    yyjson_val *value = yyjson_obj_get(action, "target");
    const char *uri = yyjson_get_str(value);
    if (!uri || yyjson_get_len(value) != slot.length + sizeof(suffix) - 1 ||
        memcmp(uri, slot.data, (size_t)slot.length) || strcmp(uri + slot.length, suffix) ||
        !equals(yyjson_obj_get(root, "@odata.id"), slot)) return BC_PROTOCOL_ERROR;
    static const char prefix[] = "/redfish/v1/Managers/";
    if (slot.length < sizeof(prefix) || memcmp(slot.data, prefix, sizeof(prefix) - 1)) return BC_UNSUPPORTED;
    const char *manager = slot.data + sizeof(prefix) - 1;
    const char *media = strchr(manager, '/');
    if (!media || media == manager) return BC_UNSUPPORTED;
    if (!strcmp(media, "/VirtualMedia/CD") || !strcmp(media, "/VirtualMedia/CD1")) {
        *target = uri;
        *media_type = "CD";
    } else if (!strcmp(media, "/VirtualMedia/USBStick") || !strcmp(media, "/VirtualMedia/USBStick1"))
        *media_type = "USBStick";
    else return BC_UNSUPPORTED;
    return BC_OK;
}

bc_status bc_zte_media_body(const bc_redfish_virtual_media_insert_options *insert, char **body, size_t *length) {
    if (insert) {
        bc_string image = insert->image;
        if (image.length > 256 || image.length < 9 || memcmp(image.data, "nfs://", 6) ||
            (insert->flags & BC_REDFISH_VM_WRITE_PROTECTED_SET && !insert->write_protected) ||
            (insert->transfer_method.length &&
             (insert->transfer_method.length != 6 || memcmp(insert->transfer_method.data, "Stream", 6))) ||
            (insert->transfer_protocol_type.length &&
             (insert->transfer_protocol_type.length != 3 || memcmp(insert->transfer_protocol_type.data, "NFS", 3))))
            return BC_UNSUPPORTED;
        const char *host = image.data + 6, *path = memchr(host, '/', (size_t)image.length - 6);
        if (!path || path == host || path + 1 == image.data + image.length || memchr(host, '@', (size_t)(path - host)))
            return BC_INVALID_ARGUMENT;
    }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = doc ? yyjson_mut_obj(doc) : NULL;
    int ok = root && yyjson_mut_obj_add_str(doc, root, "VmmControlType", insert ? "Connect" : "Disconnect");
    if (ok && insert) ok = yyjson_mut_obj_add_strncpy(doc, root, "Image", insert->image.data, (size_t)insert->image.length);
    if (ok) yyjson_mut_doc_set_root(doc, root);
    *body = ok ? yyjson_mut_write(doc, 0, length) : NULL;
    if (doc) yyjson_mut_doc_free(doc);
    return *body ? BC_OK : BC_NO_MEMORY;
}

int bc_zte_media_accepted(bc_bytes body, bc_string slot) {
    yyjson_doc *doc = body.data && body.length <= 65536 ? yyjson_read((const char *)body.data, (size_t)body.length, 0) : NULL;
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    int ok = equals(yyjson_obj_get(yyjson_obj_get(root, "Information"), "target"), slot);
    if (doc) yyjson_doc_free(doc);
    return ok;
}

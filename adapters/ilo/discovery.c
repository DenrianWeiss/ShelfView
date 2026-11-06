#include "bcontrol/ilo.h"
#include "yyjson.h"
#include <string.h>

static yyjson_val *field(yyjson_val *object, const char *name) {
    size_t i, n; yyjson_val *key, *value, *found = NULL;
    yyjson_obj_foreach(object, i, n, key, value) {
        if (!yyjson_equals_str(key, name)) continue;
        if (found) return NULL;
        found = value;
    }
    return found;
}
bc_status bc_ilo_discover_generation(const uint8_t *data, uint32_t length, uint32_t *generation) {
    if (!generation) return BC_INVALID_ARGUMENT;
    *generation = 0;
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > 1024u * 1024u) return BC_LIMIT_EXCEEDED;
    yyjson_doc *doc = yyjson_read((const char *)data, length, 0);
    if (!doc) return BC_PROTOCOL_ERROR;
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *managers = field(field(field(root, "Oem"), "Hpe"), "Manager");
    bc_status status = BC_UNSUPPORTED;
    if (yyjson_is_arr(managers) && yyjson_arr_size(managers) == 1 &&
        yyjson_equals_str(field(yyjson_arr_get_first(managers), "ManagerType"), "iLO 5")) {
        *generation = 5; status = BC_OK;
    }
    yyjson_doc_free(doc);
    return status;
}

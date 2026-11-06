#include "bcontrol/idrac_kvm.h"
#include "yyjson.h"
#include <string.h>

static int equal(yyjson_val *v, const char *s) {
    return yyjson_is_str(v) && yyjson_get_len(v) == strlen(s) && !memcmp(yyjson_get_str(v), s, strlen(s));
}
static yyjson_val *field(yyjson_val *object, const char *name, int *valid) {
    if (!yyjson_is_obj(object)) { *valid = 0; return NULL; }
    size_t i, n; yyjson_val *key, *value, *found = NULL;
    yyjson_obj_foreach(object, i, n, key, value) {
        if (!equal(key, name)) continue;
        if (found) *valid = 0;
        found = value;
    }
    return found;
}
bc_status bc_idrac_kvm_discover_attributes(const uint8_t *data, uint32_t length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > 65536) return BC_LIMIT_EXCEEDED;
    yyjson_doc *doc = yyjson_read((const char *)data, length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    int valid = 1;
    yyjson_val *type = field(root, "@odata.type", &valid);
    yyjson_val *attributes = field(root, "Attributes", &valid);
    yyjson_val *plugin = field(attributes, "VirtualConsole.1.PluginType", &valid);
    bc_status status = !valid ? BC_PROTOCOL_ERROR :
        !equal(type, "#DellAttributes.v1_0_0.DellAttributes") ? BC_UNSUPPORTED :
        equal(plugin, "eHTML5") || equal(plugin, "3") || (yyjson_is_uint(plugin) && yyjson_get_uint(plugin) == 3) ? BC_OK : BC_UNSUPPORTED;
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out), BC_SERVICE_KVM,
        BC_SERVICE_FAMILY_IDRAC, BC_SERVICE_IDRAC_KVM_EHTML5, BC_SERVICE_EVIDENCE_HINT};
    if (doc) yyjson_doc_free(doc);
    return status;
}

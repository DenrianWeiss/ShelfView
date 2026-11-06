#include "redfish.h"
#include <string.h>

static int equal(yyjson_mut_val *value, const char *text) {
    const char *s = yyjson_mut_get_str(value);
    return s && !strcmp(s, text);
}

char *bc_inspur_redfish_resource(yyjson_val *source, size_t *length) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return NULL;
    yyjson_mut_val *root = yyjson_val_mut_copy(doc, source);
    if (!root) { yyjson_mut_doc_free(doc); return NULL; }
    yyjson_mut_doc_set_root(doc, root);
    const char *type = yyjson_get_str(yyjson_obj_get(source, "@odata.type"));
    if (type && strlen(type) >= 10 && !strcmp(type + strlen(type) - 10, "Collection")) {
        yyjson_mut_val *members = yyjson_mut_obj_get(root, "Members");
        size_t count = yyjson_mut_arr_size(members);
        for (size_t i = 0; i < count; ++i) {
            const char *uri = yyjson_mut_get_str(yyjson_mut_arr_get(members, i));
            if (!uri) continue;
            yyjson_mut_val *link = yyjson_mut_obj(doc);
            if (!link || !yyjson_mut_obj_add_str(doc, link, "@odata.id", uri)) {
                yyjson_mut_doc_free(doc); return NULL;
            }
            yyjson_mut_arr_replace(members, i, link);
        }
    }
    if (type && !strncmp(type, "#Chassis.", 9)) {
        yyjson_mut_val *links = yyjson_mut_obj_get(root, "Links");
        yyjson_mut_val *systems = yyjson_mut_obj_get(links, "ComputerSystems");
        const char *self = yyjson_mut_get_str(yyjson_mut_obj_get(root, "@odata.id"));
        if (self && yyjson_mut_arr_size(systems) == 1) {
            const char *target = yyjson_mut_get_str(yyjson_mut_obj_get(yyjson_mut_arr_get_first(systems), "@odata.id"));
            size_t n = strlen(self);
            if (target && !strncmp(target, self, n) && !strcmp(target + n, "/NetworkAdapters"))
                yyjson_mut_obj_remove_key(links, "ComputerSystems");
        }
    }
    if (type && (!strncmp(type, "#Thermal.", 9) || !strncmp(type, "#Power.", 7))) {
        static const char *const groups[] = {"Temperatures", "Fans", "Voltages", "PowerSupplies"};
        for (size_t g = 0; g < sizeof(groups) / sizeof(groups[0]); ++g) {
            size_t i, count; yyjson_mut_val *item;
            yyjson_mut_arr_foreach(yyjson_mut_obj_get(root, groups[g]), i, count, item) {
                yyjson_mut_val *state = yyjson_mut_obj_get(yyjson_mut_obj_get(item, "Status"), "State");
                if (equal(state, "ENABLE")) yyjson_mut_set_str(state, "Enabled");
                else if (equal(state, "DISABLE")) yyjson_mut_set_str(state, "Disabled");
                if (g != 1 || yyjson_mut_obj_get(item, "Reading")) continue;
                const char *speed = yyjson_mut_get_str(yyjson_mut_obj_get(item, "Speed"));
                if (!speed || !*speed || strlen(speed) > 9) continue;
                uint32_t rpm = 0; const char *p = speed;
                for (; *p >= '0' && *p <= '9'; ++p) rpm = rpm * 10 + (uint32_t)(*p - '0');
                if (*p) continue;
                if (!yyjson_mut_obj_add_uint(doc, item, "Reading", rpm) ||
                    (!yyjson_mut_obj_get(item, "ReadingUnits") && !yyjson_mut_obj_add_str(doc, item, "ReadingUnits", "RPM"))) {
                    yyjson_mut_doc_free(doc); return NULL;
                }
            }
        }
    }
    char *json = yyjson_mut_write(doc, 0, length);
    yyjson_mut_doc_free(doc);
    return json;
}

#include "remote_media.h"
#include <string.h>

uint32_t bc_lenovo_media_candidate(yyjson_val *root, bc_string uri, char owner[1025]) {
    const char *id = yyjson_get_str(yyjson_obj_get(root, "Id"));
    const char *resource = yyjson_get_str(yyjson_obj_get(root, "@odata.id"));
    if (!id || !resource || !uri.data || uri.length > 1024 || strlen(resource) != uri.length ||
        memcmp(resource, uri.data, (size_t)uri.length)) return 0;
    uint32_t flags = 0;
    if (strlen(id) == 4 && !strncmp(id, "EXT", 3) && id[3] >= '1' && id[3] <= '4')
        flags = BC_REDFISH_VM_INSERT_ACTION | BC_REDFISH_VM_EJECT_ACTION;
    else if (strlen(id) == 5 && !strncmp(id, "RDOC", 4) && id[4] >= '1' && id[4] <= '2')
        flags = BC_REDFISH_VM_EJECT_ACTION;
    if (!flags) return 0;
    const char *slot = strstr(resource, "/VirtualMedia/");
    if (!slot || strcmp(slot + 14, id)) return 0;
    const char *prefix = !strncmp(resource, "/redfish/v1/Systems/", 20) ? resource + 20 :
        !strncmp(resource, "/redfish/v1/Managers/", 21) ? resource + 21 : NULL;
    if (!prefix || prefix >= slot || memchr(prefix, '/', (size_t)(slot - prefix))) return 0;
    memcpy(owner, resource, (size_t)(slot - resource)); owner[slot - resource] = 0;
    return flags;
}
int bc_lenovo_media_owner(yyjson_val *root, bc_string uri) {
    const char *id = yyjson_get_str(yyjson_obj_get(root, "@odata.id"));
    yyjson_val *oem = yyjson_obj_get(yyjson_obj_get(root, "Oem"), "Lenovo");
    const char *type = yyjson_get_str(yyjson_obj_get(oem, "@odata.type"));
    const char *link = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(root, "VirtualMedia"), "@odata.id"));
    if (!id || !type || !link || !uri.data) return 0;
    size_t n = strlen(id), m = strlen(link);
    return n + 14 < uri.length && !memcmp(uri.data, id, n) &&
        !memcmp(uri.data + n, "/VirtualMedia/", 14) && m == n + 13 &&
        !strncmp(link, id, n) && !strcmp(link + n, "/VirtualMedia") &&
        (!strncmp(type, "#LenovoComputerSystem.", 22) || !strncmp(type, "#LenovoManager.", 15));
}

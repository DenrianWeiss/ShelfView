#include "network.h"
#include <string.h>
yyjson_val *bc_lenovo_network_mode(yyjson_val *root) {
    yyjson_val *oem = yyjson_obj_get(yyjson_obj_get(root, "Oem"), "Lenovo");
    const char *type = yyjson_get_str(yyjson_obj_get(oem, "@odata.type"));
    if (!type || strncmp(type, "#LenovoEthernetInterface.", 25)) return NULL;
    return yyjson_obj_get(yyjson_obj_get(oem, "InterfaceNicMode"), "NicMode");
}

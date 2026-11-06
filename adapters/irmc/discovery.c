#include "discovery.h"
#include "yyjson.h"
#include <string.h>

int bc_irmc_service_root_matches(bc_bytes body) {
    if (!body.data || !body.length || body.length > 65536) return 0;
    yyjson_doc *doc = yyjson_read((const char *)body.data, (size_t)body.length, 0);
    yyjson_val *oem = yyjson_obj_get(yyjson_doc_get_root(doc), "Oem");
    yyjson_val *fujitsu = yyjson_obj_get(oem, "ts_fujitsu");
    yyjson_val *type = yyjson_obj_get(fujitsu, "@odata.type");
    const char *name = yyjson_get_str(type);
    const char prefix[] = "http://ts.fujitsu.com/redfish-schemas/v1/FTSSchema.";
    int match = name && !strncmp(name, prefix, sizeof(prefix) - 1) &&
        strstr(name, "#FTSServiceRoot.") != NULL;
    yyjson_doc_free(doc);
    return match;
}

bc_status bc_irmc_send(bc_kvm_transport *transport, const uint8_t *data, uint32_t length) {
    if (length < 8 || memcmp(data, "CONNECT ", 8))
        return bc_kvm_transport_send(transport, data, length);

    /* The iRMC JViewer writes CONNECT and the service request separately. */
    for (uint32_t i = 8; i + 4 < length; ++i) {
        if (memcmp(data + i, "\r\n\r\n", 4)) continue;
        uint32_t split = i + 4;
        bc_status status = bc_kvm_transport_send(transport, data, split);
        return status == BC_OK ? bc_kvm_transport_send(transport, data + split, length - split) : status;
    }
    return BC_PROTOCOL_ERROR;
}

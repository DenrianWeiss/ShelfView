#include "megarac.h"
#include "jar.h"
#include <stdlib.h>
#include <string.h>
bc_status bc_megarac_jviewer_jar_evidence(const uint8_t *jar, uint32_t length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!jar || !length) return BC_INVALID_ARGUMENT;
    if (length > 16 * 1024 * 1024) return BC_LIMIT_EXCEEDED;
#ifndef BC_MEGARAC_ZLIB
    return BC_UNSUPPORTED;
#else
    static const char *const names[] = {"com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr.class", "com/ami/kvm/jviewer/gui/JViewerApp.class"};
    bc_jar_entry classes[2] = {{0}, {0}};
    bc_status status = bc_jar_extract(jar, length, names, 2, classes);
    if (status == BC_OK) status = bc_megarac_jviewer_class_evidence(classes[0].data, classes[0].length,
        classes[1].data, classes[1].length, out);
    free(classes[0].data); free(classes[1].data); return status;
#endif
}
bc_status bc_megarac_jviewer_jar_token_default(const uint8_t *jar, uint32_t length, uint32_t *value) {
    if (!value) return BC_INVALID_ARGUMENT;
    *value = UINT32_MAX;
    if (!jar || !length) return BC_INVALID_ARGUMENT;
    if (length > 16 * 1024 * 1024) return BC_LIMIT_EXCEEDED;
#ifndef BC_MEGARAC_ZLIB
    return BC_UNSUPPORTED;
#else
    static const char *const names[] = {"com/ami/kvm/jviewer/JViewer.class"};
    bc_jar_entry entry = {0};
    bc_status status = bc_jar_extract(jar, length, names, 1, &entry);
    if (status == BC_OK) status = bc_megarac_jviewer_class_token_default(entry.data, entry.length, value);
    free(entry.data); return status;
#endif
}

bc_status bc_megarac_jviewer_jar_media_hint(const uint8_t *jar, uint32_t length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    if (!jar || !length) return BC_INVALID_ARGUMENT;
    if (length > 16*1024*1024) return BC_LIMIT_EXCEEDED;
#ifndef BC_MEGARAC_ZLIB
    return BC_UNSUPPORTED;
#else
    static const char *const names[] = {"com/ami/iusb/protocol/IUSBHeader.class", "com/ami/iusb/protocol/RedirHeader.class",
        "com/ami/iusb/CDROMRedir.class", "com/ami/iusb/protocol/PacketMaster.class",
        "com/ami/kvm/jviewer/JViewer.class", "com/ami/kvm/jviewer/gui/JViewerApp.class",
        "com/ami/iusb/protocol/IUSBSCSI.class", "com/ami/iusb/protocol/RedirPacket.class"};
    bc_jar_entry entry[8] = {{0},{0},{0},{0},{0},{0},{0},{0}};
    bc_status status = bc_jar_extract(jar,length,names,8,entry);
    if (status == BC_OK) status = bc_megarac_jviewer_class_media_hint(entry[0].data,entry[0].length,entry[1].data,entry[1].length,out);
    if (status == BC_OK) status = bc_megarac_jviewer_class_media_order_hint(entry[2].data,entry[2].length,entry[3].data,entry[3].length,out);
    if (status == BC_OK) status = bc_megarac_jviewer_class_media_auth_hint(entry[2].data,entry[2].length,out);
    if (status == BC_OK) status = bc_megarac_jviewer_class_media_runtime_hint(entry[4].data,entry[4].length,entry[5].data,entry[5].length,out);
    if (status == BC_OK) status = bc_megarac_jviewer_class_media_send_hint(entry[6].data,entry[6].length,entry[3].data,entry[3].length,out);
    if (status == BC_OK) status = bc_megarac_jviewer_class_media_state_hint(entry[0].data,entry[0].length,entry[6].data,entry[6].length,entry[7].data,entry[7].length,out);
    if (status != BC_OK) memset(out,0,sizeof(*out));
    for (unsigned i = 0; i < 8; ++i) free(entry[i].data);
    return status;
#endif
}

bc_status bc_megarac_jviewer_jar_single_port_default(const uint8_t *jar, uint32_t length, uint32_t *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = UINT32_MAX;
    if (!jar || !length) return BC_INVALID_ARGUMENT;
    if (length > 16*1024*1024) return BC_LIMIT_EXCEEDED;
#ifndef BC_MEGARAC_ZLIB
    return BC_UNSUPPORTED;
#else
    static const char *const names[] = {"com/ami/kvm/jviewer/JViewer.class"}; bc_jar_entry entry = {0};
    bc_status status = bc_jar_extract(jar,length,names,1,&entry);
    if (status == BC_OK) status = bc_megarac_jviewer_class_single_port_default(entry.data,entry.length,out);
    free(entry.data); return status;
#endif
}

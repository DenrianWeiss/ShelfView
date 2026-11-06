#ifndef BC_MEGARAC_H5_INTERNAL_H
#define BC_MEGARAC_H5_INTERNAL_H
#include "bcontrol/megarac.h"
#include <string.h>
static inline int bc_megarac_h5_contains(const uint8_t *data, uint32_t length, const char *text) {
    size_t n = strlen(text);
    if (!data || n > length) return 0;
    for (size_t i = 0; i <= length - n; ++i) if (!memcmp(data + i, text, n)) return 1;
    return 0;
}
static inline int bc_megarac_split_h5_viewer_matches(const uint8_t *data, uint32_t length) {
    static const char *const fields[] = {"VIDEO_PACKET_SIZE:373", "SSI_HASH_SIZE:129",
        "CLIENT_USERNAME_LENGTH:129", "CLINET_OWN_IP_LENGTH:65", "CLINET_OWN_MAC_LENGTH:49",
        "\"/api/kvm/token\"", "\"/api/settings/media/adviser\"", "\"/api/settings/media/instance\"",
        "this.bmc_ip+\"/kvm\"", "\"/cd-server\""};
    if (length > 2097152) return 0;
    for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); ++i)
        if (!bc_megarac_h5_contains(data, length, fields[i])) return 0;
    return 1;
}
static inline uint32_t bc_megarac_h5_keyboard_mode(const uint8_t *data, uint32_t length) {
    static const char *const fields[] = {
        "this.m_USBKeyProcessor.setAutoKeybreakMode(!0)",
        "this.m_USBKeyProcessor.convertKeyCode(this.keyCode,this.keyLocation,this.keyPress)",
        "this.autoKeybreakMode&&(i=!0)", "if(this.autoKeybreakMode)return null"
    };
    if (length > 2097152) return BC_MEGARAC_KEYBOARD_DEFAULT;
    for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); ++i)
        if (!bc_megarac_h5_contains(data, length, fields[i])) return BC_MEGARAC_KEYBOARD_DEFAULT;
    if (!bc_megarac_h5_contains(data, length, "t.writeInt8(n),t.writeInt8(e?1:0),t.writeInt8Array(l)") &&
        !bc_megarac_h5_contains(data, length, "u.writeInt8(n),u.writeInt8(e?1:0),u.writeInt8Array(l)"))
        return BC_MEGARAC_KEYBOARD_DEFAULT;
    return BC_MEGARAC_KEYBOARD_AUTO_BREAK;
}
bc_status bc_megarac_split_h5_config(const uint8_t *, uint32_t, const uint8_t *, uint32_t,
    int, bc_megarac_kvm_info *, bc_service_profile *);
bc_status bc_megarac_split_h5_media(const uint8_t *, uint32_t, int, bc_megarac_media_parameters *);
#endif

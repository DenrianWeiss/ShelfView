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
static inline int bc_megarac_h5_number(const uint8_t *data, uint32_t length, const char *key, const char *number) {
    size_t key_length = strlen(key), number_length = strlen(number);
    for (size_t i = 0; i + key_length < length; ++i) {
        if (i && !strchr("{,\n\r\t \"'", data[i - 1])) continue;
        if (memcmp(data + i, key, key_length)) continue;
        size_t p = i + key_length;
        if (data[p] == '"' || data[p] == '\'') ++p;
        while (p < length && data[p] && strchr(" \t\r\n", data[p])) ++p;
        if (p == length || data[p++] != ':') continue;
        while (p < length && data[p] && strchr(" \t\r\n", data[p])) ++p;
        if (p + number_length >= length || memcmp(data + p, number, number_length)) continue;
        p += number_length;
        while (p < length && data[p] && strchr(" \t\r\n", data[p])) ++p;
        if (p < length && (data[p] == ',' || data[p] == '}')) return 1;
    }
    return 0;
}
static inline int bc_megarac_h5_extended_packet(const uint8_t *data, uint32_t length) {
    const char prefix[] = "new DataStream(", base[] = ".VIDEO_PACKET_SIZE+", extra[] = ".CLINET_OWN_IP_LENGTH)";
    for (size_t i = 0; i + sizeof(prefix) < length; ++i) {
        if (memcmp(data + i, prefix, sizeof(prefix) - 1)) continue;
        size_t begin = i + sizeof(prefix) - 1, end = begin;
        while (end < length && ((data[end] >= 'a' && data[end] <= 'z') ||
            (data[end] >= 'A' && data[end] <= 'Z') || data[end] == '_' || data[end] == '$')) ++end;
        size_t name = end - begin, tail = end + sizeof(base) - 1;
        if (!name || tail + name + sizeof(extra) - 1 > length) continue;
        if (!memcmp(data + end, base, sizeof(base) - 1) && !memcmp(data + tail, data + begin, name) &&
            !memcmp(data + tail + name, extra, sizeof(extra) - 1))
            return bc_megarac_h5_contains(data, length, ".writeCString(this.server_ip,");
    }
    return 0;
}
static inline uint32_t bc_megarac_h5_viewer_layout(const uint8_t *data, uint32_t length) {
    if (!data || length > 2097152 ||
        (!bc_megarac_h5_contains(data, length, "\"/kvm\"") && !bc_megarac_h5_contains(data, length, "'/kvm'")) ||
        !bc_megarac_h5_number(data, length, "SSI_HASH_SIZE", "129") ||
        !bc_megarac_h5_number(data, length, "CLIENT_USERNAME_LENGTH", "129") ||
        !bc_megarac_h5_number(data, length, "CLINET_OWN_IP_LENGTH", "65") ||
        !bc_megarac_h5_number(data, length, "CLINET_OWN_MAC_LENGTH", "49")) return 0;
    int legacy = bc_megarac_h5_number(data, length, "VIDEO_PACKET_SIZE", "373");
    int extended = bc_megarac_h5_number(data, length, "VIDEO_PACKET_SIZE", "438");
    if (legacy && !extended && bc_megarac_h5_extended_packet(data, length)) return BC_SERVICE_MEGARAC_KVM_H5_438;
    return legacy == extended ? 0 : legacy ? BC_SERVICE_MEGARAC_KVM_H5_373 : BC_SERVICE_MEGARAC_KVM_H5_438;
}
static inline int bc_megarac_split_h5_viewer_matches(const uint8_t *data, uint32_t length) {
    return bc_megarac_h5_viewer_layout(data, length) == BC_SERVICE_MEGARAC_KVM_H5_373 &&
        bc_megarac_h5_contains(data, length, "\"/api/kvm/token\"") &&
        bc_megarac_h5_contains(data, length, "\"/api/settings/media/adviser\"") &&
        bc_megarac_h5_contains(data, length, "\"/api/settings/media/instance\"") &&
        bc_megarac_h5_contains(data, length, "\"/cd-server\"");
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
bc_status bc_megarac_discover_h5_layout(const uint8_t *, uint32_t, uint32_t,
    bc_megarac_kvm_info *, bc_service_profile *);
bc_status bc_megarac_split_h5_media(const uint8_t *, uint32_t, int, bc_megarac_media_parameters *);
#endif

#include "bcontrol/avocent.h"
#include "bcontrol/wire.h"
#include <string.h>
bc_status bc_avocent_apcp_request(uint32_t channel, uint32_t transports,
    const uint8_t nonce[32], uint8_t out[BC_AVOCENT_APCP_SIZE]) {
    if (!nonce || !out || channel < BC_AVOCENT_MEDIA || channel > BC_AVOCENT_VIDEO ||
        !transports || (transports & ~5u)) return BC_INVALID_ARGUMENT;
    memset(out, 0, BC_AVOCENT_APCP_SIZE);
    memcpy(out, "APCP", 4); out[7] = BC_AVOCENT_APCP_SIZE; out[8] = 1;
    out[12] = (uint8_t)channel;
    if (channel != BC_AVOCENT_MEDIA) { out[13] = 2; out[14] = 34; }
    out[19] = (uint8_t)transports; out[20] = 32; memcpy(out + 21, nonce, 32);
    return BC_OK;
}
bc_status bc_avocent_apcp_parse(const uint8_t *data, uint32_t length, bc_avocent_setup *out) {
    if (!out || (!data && length)) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out);
    if (length != BC_AVOCENT_APCP_SIZE || memcmp(data, "APCP", 4) ||
        bc_wire_read_be(data + 4, 4) != BC_AVOCENT_APCP_SIZE || data[8] != 0x81 || data[9] ||
        data[10] || data[11] || data[20] > 32) return BC_PROTOCOL_ERROR;
    out->major = data[12]; out->minor = data[13]; out->transports = (uint32_t)bc_wire_read_be(data + 14, 4);
    out->port = (uint32_t)data[18] << 8 | data[19]; out->challenge_length = data[20];
    memcpy(out->challenge, data + 21, out->challenge_length);
    return BC_OK;
}

static size_t bounded_length(const char *s, size_t capacity) {
    size_t n = 0; while (n < capacity && s[n]) ++n; return n;
}
bc_status bc_avocent_login_encode(const bc_avocent_launch *launch, uint32_t client_id,
    uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (!launch || launch->struct_size != sizeof(*launch) || !out) return BC_INVALID_ARGUMENT;
    if (launch->service != BC_AVOCENT_CONTROL && launch->service != BC_AVOCENT_MEDIA) return BC_UNSUPPORTED;
    size_t user = bounded_length(launch->username, sizeof(launch->username));
    size_t password = bounded_length(launch->password, sizeof(launch->password));
    uint32_t media = launch->service == BC_AVOCENT_MEDIA, size = media ? 153u : 217u;
    if (!user || user > 96 || !password || password > (media ? 32u : 96u)) return BC_INVALID_ARGUMENT;
    if (!media && launch->apcp != 1) return BC_UNSUPPORTED;
    if (capacity < size) return BC_LIMIT_EXCEEDED;
    memset(out, 0, size);
    if (media) {
        memcpy(out, "AVMP", 4); bc_wire_write_be(out + 4, size, 4); out[8] = 1;
        out[12] = (uint8_t)user; memcpy(out + 13, launch->username, user);
        memcpy(out + 109, launch->password, password);
    } else {
        memcpy(out, "BEEF", 4); bc_wire_write_be(out + 4, 0x0102, 2); bc_wire_write_be(out + 6, size, 2);
        out[8] = (uint8_t)user; memcpy(out + 9, launch->username, user);
        out[105] = (uint8_t)password; memcpy(out + 106, launch->password, password);
        out[210] = 2; out[211] = 34; bc_wire_write_be(out + 212, client_id, 4);
    }
    *written = size; return BC_OK;
}
bc_status bc_avocent_login_parse(uint32_t service, const uint8_t *data, uint32_t length,
    bc_avocent_login_result *out) {
    if (!out || (!data && length)) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out);
    if (service == BC_AVOCENT_MEDIA) {
        if (length != 111 || memcmp(data, "AVMP", 4) || bc_wire_read_be(data + 4, 4) != length ||
            bc_wire_read_be(data + 8, 2) != 0x8100 || data[10] || data[11] || data[14] > 96)
            return BC_PROTOCOL_ERROR;
        out->status = data[12]; out->flags = data[13];
    } else if (service == BC_AVOCENT_CONTROL) {
        if (length != 115 || memcmp(data, "BEEF", 4) || bc_wire_read_be(data + 4, 2) != 0x8305 ||
            bc_wire_read_be(data + 6, 2) != length || data[18] > 96) return BC_PROTOCOL_ERROR;
        out->status = data[8]; out->session_id = (uint32_t)bc_wire_read_be(data + 12, 4);
        out->flags = (uint32_t)bc_wire_read_be(data + 16, 2);
    } else return BC_UNSUPPORTED;
    return BC_OK;
}

bc_status bc_avocent_key_encode(uint32_t usage, uint32_t pressed, uint8_t out[16]) {
    if (!out || usage > 0xffff || pressed > 1) return BC_INVALID_ARGUMENT;
    memset(out, 0, 16);
    memcpy(out, "BEEF", 4);
    bc_wire_write_be(out + 4, 0x0200, 2);
    bc_wire_write_be(out + 6, 16, 2);
    out[9] = (uint8_t)!pressed;
    bc_wire_write_be(out + 10, usage, 2);
    return BC_OK;
}

#include "wire.h"
#include <string.h>

bc_status bc_ilo5_client_hello(bc_string token, uint8_t channel, uint8_t out[54]) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, 54);
    if (!token.data || token.length != 32) return BC_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < 32; ++i)
        if ((unsigned char)token.data[i] < 33 || (unsigned char)token.data[i] > 126)
            return BC_INVALID_ARGUMENT;
    out[17] = channel;
    memcpy(out + 22, token.data, 32);
    return BC_OK;
}
bc_status bc_ilo5_server_hello(const uint8_t *data, uint32_t length, uint8_t *status) {
    if (!data || !status) return BC_INVALID_ARGUMENT;
    *status = 255;
    if (length != 53) return BC_PROTOCOL_ERROR;
    *status = data[16];
    return BC_OK;
}
void bc_ilo5_keyboard(const uint8_t hid[8], uint8_t out[10]) {
    out[0] = 1; out[1] = 0;
    memcpy(out + 2, hid, 8);
}
void bc_ilo5_pointer(uint16_t x, uint16_t y, int8_t dx, int8_t dy,
    uint8_t buttons, int8_t wheel, uint8_t out[10]) {
    out[0] = 2; out[1] = 0;
    out[2] = (uint8_t)x; out[3] = (uint8_t)(x >> 8);
    out[4] = (uint8_t)y; out[5] = (uint8_t)(y >> 8);
    out[6] = (uint8_t)dx; out[7] = (uint8_t)dy;
    out[8] = buttons; out[9] = (uint8_t)wheel;
}

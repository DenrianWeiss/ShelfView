#ifndef BC_ILO_WIRE_H
#define BC_ILO_WIRE_H
#include "bcontrol/bcontrol.h"
/* iLO 5 WebSocket messages; callers own transport and session lifetime. */
bc_status bc_ilo5_client_hello(bc_string token, uint8_t channel, uint8_t out[54]);
bc_status bc_ilo5_server_hello(const uint8_t *data, uint32_t length, uint8_t *status);
void bc_ilo5_keyboard(const uint8_t hid[8], uint8_t out[10]);
void bc_ilo5_pointer(uint16_t x, uint16_t y, int8_t dx, int8_t dy,
    uint8_t buttons, int8_t wheel, uint8_t out[10]);
#endif

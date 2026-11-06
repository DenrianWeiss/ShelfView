#ifndef BCONTROL_ILOM_PROFILE_H
#define BCONTROL_ILOM_PROFILE_H
#include <stdint.h>
uint32_t bc_ilom_ipmi_capabilities(const uint8_t *, uint32_t);
int bc_ilom_padded_handshake(const uint8_t *, uint32_t, uint32_t);
#endif

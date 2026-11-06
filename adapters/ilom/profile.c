#include "profile.h"
#include "bcontrol/ipmi_session.h"
#include "bcontrol/wire.h"

uint32_t bc_ilom_ipmi_capabilities(const uint8_t *data, uint32_t length) {
    if (!data || length < 11 || bc_wire_read_le(data + 6, 3) != 42) return 0;
    uint32_t flags = BC_IPMI_CAPABILITY_ILOM_SERIAL_CANDIDATE;
    /* Known hardware profile is only used for graphical-console visibility. */
    if (bc_wire_read_le(data + 9, 2) == 0x4701)
        flags |= BC_IPMI_CAPABILITY_NO_GRAPHICAL_CONSOLE;
    return flags;
}
int bc_ilom_padded_handshake(const uint8_t *data, uint32_t length, uint32_t suite) {
    return data && length == 37 && suite == 3;
}

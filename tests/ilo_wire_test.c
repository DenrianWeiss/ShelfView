#include "../adapters/ilo/wire.h"
#include <assert.h>
#include <string.h>
int main(void) {
    uint8_t hello[54], reply[53] = {0}, status, packet[10];
    const char token[] = "0123456789abcdef0123456789abcdef";
    assert(bc_ilo5_client_hello((bc_string){token, 32}, 1, hello) == BC_OK);
    assert(hello[16] == 0 && hello[17] == 1 && hello[21] == 0);
    assert(memcmp(hello + 22, token, 32) == 0);
    assert(bc_ilo5_server_hello(reply, sizeof(reply), &status) == BC_OK && status == 0);
    reply[16] = 2;
    assert(bc_ilo5_server_hello(reply, sizeof(reply), &status) == BC_OK && status == 2);
    assert(bc_ilo5_server_hello(reply, 16, &status) == BC_PROTOCOL_ERROR && status == 255);
    assert(bc_ilo5_client_hello((bc_string){token, 31}, 0, hello) == BC_INVALID_ARGUMENT);
    for (unsigned i = 0; i < sizeof(hello); ++i) assert(hello[i] == 0);
    const uint8_t hid[8] = {5, 0, 76, 0, 0, 0, 0, 0};
    const uint8_t keyboard[10] = {1, 0, 5, 0, 76, 0, 0, 0, 0, 0};
    bc_ilo5_keyboard(hid, packet);
    assert(memcmp(packet, keyboard, sizeof(packet)) == 0);
    const uint8_t pointer[10] = {2, 0, 0x34, 0x12, 0xcd, 0xab, 255, 127, 3, 255};
    bc_ilo5_pointer(0x1234, 0xabcd, -1, 127, 3, -1, packet);
    assert(memcmp(packet, pointer, sizeof(packet)) == 0);
    return 0;
}

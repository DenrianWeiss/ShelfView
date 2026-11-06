#include "bcontrol/kvm.h"
#include "bcontrol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static uint8_t framebuffer[1920 * 1200 * 4];
static uint8_t output[8192];
static uint32_t output_length;

static void feed(bc_kvm *client, const void *data, size_t length) {
    bc_status status = bc_kvm_feed(client, data, (uint32_t)length);
    if (status != BC_OK) { fprintf(stderr, "feed failed %s at %zu bytes\n", bc_status_string(status), length); exit(1); }
}
static uint8_t *take_output_at(bc_kvm *client, uint32_t length, int line) {
    uint32_t written = 0;
    CHECK(bc_kvm_output(client, output, length, &written) == BC_OK);
    if (written != length) { fprintf(stderr, "%s:%d: output expected %u got %u\n", __FILE__, line, length, written); exit(1); }
    output_length = written;
    return output;
}
#define take_output(client, length) take_output_at((client), (length), __LINE__)
static bc_status extension(void *userdata, const uint8_t *data, uint32_t length,
    uint32_t *consumed, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (length < 2) return BC_OK;
    if (data[0] != 247 || data[1] != 179) return BC_UNSUPPORTED;
    if (capacity < 3) return BC_LIMIT_EXCEEDED;
    out[0] = 247; out[1] = 179; out[2] = 42;
    *consumed = 2; *written = 3;
    ++*(unsigned *)userdata;
    return BC_OK;
}
static void managed_framebuffer(void) {
    bc_kvm_options options = {.struct_size = sizeof(options), .abi_version = BC_ABI_VERSION};
    bc_kvm *client = NULL;
    CHECK(bc_kvm_create(&options, &client) == BC_OK);
    CHECK(!bc_kvm_frame_get(client)->pixels);
    const uint8_t hello[] = "RFB 003.008\n\1\1\0\0\0\0";
    feed(client, hello, sizeof(hello) - 1);
    take_output(client, 14);
    const uint8_t init[24] = {0, 2, 0, 2, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8};
    feed(client, init, sizeof(init)); take_output(client, 30);
    const uint8_t raw[] = {0,0,0,1, 0,0,0,0,0,2,0,2,0,0,0,0,
        0,0,255,0, 0,255,0,0, 255,0,0,0, 255,255,255,0};
    feed(client, raw, sizeof(raw)); take_output(client, 10);
    uint8_t resize[] = {0,0,0,1, 0,0,0,0, 0x0f,0,8,0x70, 0xff,0xff,0xff,0x21};
    feed(client, resize, sizeof(resize));
    CHECK(!memcmp(take_output(client, 10), "\3\0\0\0\0\0\x0f\0\x08\x70", 10));
    const bc_kvm_frame *frame = bc_kvm_frame_get(client);
    CHECK(frame->width == 3840 && frame->height == 2160 && frame->stride == 15360);
    CHECK(frame->pixels[0] == 255 && frame->pixels[5] == 255 && frame->pixels[frame->stride + 2] == 255);
    size_t last = (size_t)frame->stride * frame->height - 4;
    CHECK(!memcmp(frame->pixels + 8, "\0\0\0\0", 4) && !memcmp(frame->pixels + last, "\0\0\0\0", 4));
    const uint8_t edge[] = {0,0,0,1, 0x0e,0xff,8,0x6f,0,1,0,1,0,0,0,0, 6,7,8,0};
    feed(client, edge, sizeof(edge)); take_output(client, 10);
    CHECK(!memcmp(bc_kvm_frame_get(client)->pixels + last, "\10\7\6\xff", 4));
    bc_wire_write_be(resize + 8, 1, 2); bc_wire_write_be(resize + 10, 2, 2);
    feed(client, resize, sizeof(resize)); take_output(client, 10);
    frame = bc_kvm_frame_get(client);
    CHECK(frame->stride == 4 && !memcmp(frame->pixels, "\xff\0\0\xff\0\0\xff\xff", 8));
    bc_wire_write_be(resize + 8, 4096, 2); bc_wire_write_be(resize + 10, 4096, 2);
    CHECK(bc_kvm_feed(client, resize, sizeof(resize)) == BC_LIMIT_EXCEEDED);
    bc_kvm_destroy(client);
}
int main(void) {
    managed_framebuffer();
    bc_kvm_options options = {sizeof(options), BC_ABI_VERSION, 0, 0, 0, framebuffer, sizeof(framebuffer)};
    bc_kvm *extended = NULL;
    unsigned calls = 0;
    CHECK(bc_kvm_create(&options, &extended) == BC_OK);
    CHECK(bc_kvm_set_extension_handler(extended, 247, extension, &calls) == BC_OK);
    const uint8_t first[] = {247}; feed(extended, first, 1);
    CHECK(calls == 0);
    const uint8_t rest[] = {179, 'R','F','B',' ','0','0','3','.','0','0','8','\n'};
    feed(extended, rest, sizeof(rest));
    CHECK(calls == 1);
    CHECK(!memcmp(take_output(extended, 15), "\xf7\xb3\x2aRFB 003.008\n", 15));
    CHECK(bc_kvm_set_extension_handler(extended, 247, extension, &calls) == BC_INVALID_ARGUMENT);
    const uint8_t mixed[] = {247,179,1,1}; feed(extended, mixed, sizeof(mixed));
    CHECK(calls == 2);
    CHECK(take_output(extended, 4)[3] == 1);
    bc_kvm_destroy(extended);
    for (unsigned version = 3; version <= 7; version += 4) {
        bc_kvm *legacy = NULL;
        CHECK(bc_kvm_create(&options, &legacy) == BC_OK);
        const char *banner = version == 3 ? "RFB 003.003\n" : "RFB 003.007\n";
        for (unsigned i = 0; i < 12; ++i) feed(legacy, banner + i, 1);
        CHECK(!memcmp(take_output(legacy, 12), banner, 12));
        const uint8_t security_legacy[] = {0, 0, 0, 1};
        if (version == 3) {
            for (unsigned i = 0; i < 4; ++i) feed(legacy, security_legacy + i, 1);
            CHECK(*take_output(legacy, 1) == 1);
        } else {
            const uint8_t list[] = {1, 1}; feed(legacy, list, 2);
            CHECK(!memcmp(take_output(legacy, 2), "\x01\x01", 2));
        }
        const uint8_t legacy_init[24] = {0, 1, 0, 1, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8};
        feed(legacy, legacy_init, sizeof(legacy_init));
        CHECK(bc_kvm_frame_get(legacy)->flags & BC_KVM_READY);
        bc_kvm_destroy(legacy);
    }
    bc_kvm *client = NULL;
    CHECK(bc_kvm_create(&options, &client) == BC_OK);
    feed(client, "RFB 003.008\n", 12);
    CHECK(!memcmp(take_output(client, 12), "RFB 003.008\n", 12));
    const uint8_t security[] = {1, 1};
    feed(client, security, sizeof(security));
    CHECK(*take_output(client, 1) == 1);
    const uint8_t security_ok[] = {0, 0, 0, 0};
    feed(client, security_ok, sizeof(security_ok));
    CHECK(*take_output(client, 1) == 1);

    uint8_t init[24] = {0};
    init[1] = 2; init[3] = 2;
    init[4] = 32; init[5] = 24; init[7] = 1;
    init[8] = 0; init[9] = 255; init[10] = 0; init[11] = 255; init[12] = 0; init[13] = 255;
    init[14] = 16; init[15] = 8; init[16] = 0;
    init[23] = 3;
    feed(client, init, sizeof(init));
    feed(client, "kvm", 3);
    CHECK(!memcmp(take_output(client, 20), "\x02\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\xff\xff\xff\x21", 20));
    CHECK(take_output(client, 10)[0] == 3);
    const bc_kvm_frame *frame = bc_kvm_frame_get(client);
    CHECK(frame && (frame->flags & BC_KVM_READY) && !(frame->flags & BC_KVM_FRAME_READY) && frame->width == 2 && frame->height == 2);
    CHECK(frame->height == 2 && frame->stride == 8);
    CHECK(frame->name_length == 3 && !memcmp(frame->name.data, "kvm", 3));
    bc_kvm_ack_frame(client);

    uint8_t update[16] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0};
    feed(client, update, 8);
    feed(client, update + 8, 8);
    const uint8_t pixels[16] = {0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0};
    feed(client, pixels, 8);
    feed(client, pixels + 8, 8);
    CHECK(take_output(client, 10)[0] == 3);
    frame = bc_kvm_frame_get(client);
    CHECK(frame->flags & BC_KVM_FRAME_READY);
    CHECK(frame->pixels[0] == 255 && frame->pixels[1] == 0 && frame->pixels[2] == 0 && frame->pixels[3] == 255);
    CHECK(frame->pixels[4] == 0 && frame->pixels[5] == 255 && frame->pixels[6] == 0);
    CHECK(frame->pixels[8] == 0 && frame->pixels[9] == 0 && frame->pixels[10] == 255);
    CHECK(frame->pixels[12] == 255 && frame->pixels[13] == 255 && frame->pixels[14] == 255);
    bc_kvm_ack_frame(client);
    CHECK(!(bc_kvm_frame_get(client)->flags & BC_KVM_FRAME_READY));

    uint8_t copyrect[20] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1};
    feed(client, copyrect, 16); feed(client, copyrect + 16, 4);
    CHECK(take_output(client, 10)[0] == 3);
    frame = bc_kvm_frame_get(client);
    CHECK(frame->pixels[0] == 255 && frame->pixels[1] == 255 && frame->pixels[2] == 255);
    bc_kvm_ack_frame(client);

    uint8_t hextile[32] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 5};
    hextile[16] = 30;
    hextile[17] = 255; hextile[18] = 0; hextile[19] = 0; hextile[20] = 0;
    hextile[25] = 1;
    hextile[26] = 0; hextile[27] = 0; hextile[28] = 255; hextile[29] = 0;
    hextile[30] = 0; hextile[31] = 0x11;
    for (size_t i = 0; i < sizeof(hextile); ++i) feed(client, hextile + i, 1);
    CHECK(take_output(client, 10)[0] == 3);
    frame = bc_kvm_frame_get(client);
    CHECK(frame->pixels[0] == 255 && frame->pixels[1] == 0 && frame->pixels[2] == 0);
    CHECK(frame->pixels[4] == 255 && frame->pixels[5] == 0 && frame->pixels[6] == 0);
    bc_kvm_ack_frame(client);

    const uint8_t grow[16] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 16, 0, 32, 0xff, 0xff, 0xff, 0x21};
    feed(client, grow, sizeof(grow));
    CHECK(take_output(client, 10)[0] == 3);
    bc_kvm_ack_frame(client);
    /* Two 16x16 tiles: the second has subrects but specifies neither background
     * nor foreground, so it must reuse the previous tile's background. */
    const uint8_t subtiles[] = {
        0, 0, 0, 1,
        0, 0, 0, 0, 0, 16, 0, 32, 0, 0, 0, 5,
        0x0e, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 2, 0x00, 0x00, 0x11, 0x11,
        0x08, 2, 0x00, 0x00, 0x11, 0x11};
    for (size_t i = 0; i < sizeof(subtiles); ++i) feed(client, subtiles + i, 1);
    CHECK(take_output(client, 10)[0] == 3);
    frame = bc_kvm_frame_get(client);
    CHECK(frame->flags & BC_KVM_FRAME_READY);
    CHECK(frame->pixels[0] == 0 && frame->pixels[1] == 0 && frame->pixels[2] == 255);
    CHECK(frame->pixels[28] == 255 && frame->pixels[29] == 0 && frame->pixels[30] == 0);
    CHECK(frame->pixels[1108] == 255 && frame->pixels[1109] == 0 && frame->pixels[1110] == 0);
    CHECK(frame->pixels[1092] == 0 && frame->pixels[1093] == 0 && frame->pixels[1094] == 255);
    bc_kvm_ack_frame(client);

    CHECK(bc_kvm_key_event(client, 1, 0x61) == BC_OK);
    CHECK(bc_kvm_pointer_event(client, 1, 1, 0) == BC_OK);
    uint8_t *events = take_output(client, 14);
    CHECK(events[0] == 4 && events[1] == 1 && events[7] == 0x61);
    CHECK(events[8] == 5 && events[9] == 1 && events[10] == 0 && events[11] == 1);

    const uint8_t resize[16] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 1, 0xff, 0xff, 0xff, 0x21};
    feed(client, resize, sizeof(resize));
    frame = bc_kvm_frame_get(client);
    CHECK((frame->flags & BC_KVM_DESKTOP_RESIZED) && frame->width == 3 && frame->height == 1 && frame->stride == 12);
    CHECK(take_output(client, 10)[0] == 3);
    bc_kvm_destroy(client);

    bc_kvm *unsupported = NULL;
    CHECK(bc_kvm_create(&options, &unsupported) == BC_OK);
    feed(unsupported, "RFB 003.008\n", 12);
    take_output(unsupported, 12);
    const uint8_t vnc_auth[] = {1, 2};
    CHECK(bc_kvm_feed(unsupported, vnc_auth, sizeof(vnc_auth)) == BC_UNSUPPORTED);
    bc_kvm_destroy(unsupported);
    puts("kvm: RFB handshake, framebuffer conversion, resize and input passed");
    return 0;
}

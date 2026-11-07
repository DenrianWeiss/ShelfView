#include "bcontrol/avocent_media.h"
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
typedef struct { uint8_t input[512]; uint32_t length, offset, reads, sends; uint64_t now; } fixture;
static void append(fixture *f, const uint8_t *bytes, uint32_t length) {
    CHECK(length <= sizeof(f->input) - f->length);
    memcpy(f->input + f->length, bytes, length); f->length += length;
}
static void packet(fixture *f, uint32_t type, const uint8_t *body, uint32_t length) {
    uint8_t head[12] = {'A','V','M','P'};
    bc_wire_write_be(head + 4, 12 + length, 4); bc_wire_write_be(head + 8, type, 2);
    append(f, head, sizeof(head)); if (length) append(f, body, length);
}
static uint64_t clock_ms(void *user) { return ++((fixture *)user)->now; }
static bc_status receive(void *user, uint8_t *out, uint32_t capacity, uint32_t *written, uint32_t timeout) {
    fixture *f = user; (void)timeout;
    uint32_t n = f->length - f->offset;
    if (n > 3) n = 3;
    if (n > capacity) n = capacity;
    *written = n;
    if (!n) return BC_TIMEOUT;
    memcpy(out, f->input + f->offset, n); f->offset += n; return BC_OK;
}
static bc_status read_source(void *user, uint64_t offset, uint32_t size, uint8_t *out) {
    fixture *f = user; ++f->reads;
    CHECK(offset >= 7 * 2048 && offset + size <= 9 * 2048 && size == 2048);
    for (uint32_t i = 0; i < size; ++i) out[i] = (uint8_t)((offset + i) % 251);
    return BC_OK;
}
static bc_status emit(void *user, const uint8_t *b, uint32_t n) {
    fixture *f = user; ++f->sends;
    if (f->sends == 1) { CHECK(n == 68 && !memcmp(b, "APCP", 4) && b[11] == 3 && b[12] == 2); return BC_OK; }
    CHECK(n >= 12 && !memcmp(b, "AVMP", 4));
    uint32_t type = (uint32_t)bc_wire_read_be(b + 8, 2);
    if (type == 0x104) CHECK(n == 74 && !memcmp(b + 64, "userticket", 10));
    else if (type == 0x300) {
        CHECK(n == 2068);
        uint32_t start = (uint32_t)bc_wire_read_be(b + 12, 4);
        CHECK((start == 7 || start == 8) && bc_wire_read_be(b + 16, 4) == 1);
        for (uint32_t i = 0; i < 2048; ++i) CHECK(b[20 + i] == (start * 2048 + i) % 251);
    } else CHECK(type == 0x200 || type == 0x210 || type == 0x220 || type == 0x410);
    return BC_OK;
}
int main(void) {
    fixture f = {0};
    uint8_t setup[68] = {'A','P','C','P',0,0,0,68,0x81,0,1,3,1,14,0,0,4,4};
    append(&f, setup, sizeof(setup));
    uint8_t login[104] = {0}; packet(&f, 0x8100, login, sizeof(login));
    uint8_t slots[] = {0,1,2,0,0,1}, ok[4] = {0};
    packet(&f, 0x8200, slots, sizeof(slots)); packet(&f, 0x8410, ok, sizeof(ok));
    slots[3] = 1; packet(&f, 0x8200, slots, sizeof(slots));
    const uint8_t heartbeat[] = {'A','P','C','P',0,0,0,12,0x84,0,0,0}; append(&f, heartbeat, sizeof(heartbeat));
    uint8_t read[] = {0,0,0,7,0,0,0,2,0,0,0,1}; packet(&f, 0x8300, read, sizeof(read));
    uint32_t mounted_end = f.length;
    packet(&f, 0x8410, ok, sizeof(ok)); slots[3] = 0; packet(&f, 0x8200, slots, sizeof(slots));
    bc_avocent_launch ticket = {0}; ticket.struct_size = sizeof(ticket); ticket.service = BC_AVOCENT_MEDIA;
    ticket.apcp = BC_AVOCENT_APCP_WEBSOCKET_MEDIA; strcpy(ticket.username, "user"); strcpy(ticket.password, "ticket");
    bc_media_offer_info offer_info = {sizeof(offer_info), BC_MEDIA_OFFER_READY, 3900}; bc_media_offer *offer = NULL;
    CHECK(bc_media_offer_create(BC_MEDIA_OFFER_AVOCENT, &offer_info, &ticket, sizeof(ticket), &offer) == BC_OK);
    bc_media_source source = {sizeof(source), &f, 64 * 2048, read_source};
    bc_media_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.source = &source; options.offer = offer; options.user = &f; options.clock = clock_ms;
    options.emit = emit; options.receive = receive; options.timeout_ms = 10000; options.flags = BC_MEDIA_TRANSPORT_WEBSOCKET;
    bc_media_session *media = NULL; CHECK(bc_avocent_media_create(&options, &media) == BC_OK);
    CHECK(bc_media_session_control(media, BC_MEDIA_CONTROL_START) == BC_OK);
    while (f.offset < mounted_end) CHECK(bc_media_session_poll(media, 1) == BC_OK);
    bc_media_session_info info = {0}; info.struct_size = sizeof(info);
    CHECK(bc_media_session_info_get(media, &info) == BC_OK && (info.flags & BC_MEDIA_MOUNT_CONFIRMED));
    CHECK(info.bytes_read == 4096 && f.reads == 2);
    CHECK(bc_media_session_control(media, BC_MEDIA_CONTROL_CLOSE) == BC_OK);
    CHECK(bc_media_session_info_get(media, &info) == BC_OK && (info.flags & BC_MEDIA_REMOVAL_CONFIRMED));
    bc_media_session_destroy(media); bc_media_offer_destroy(offer); return 0;
}

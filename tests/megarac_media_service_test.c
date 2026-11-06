#include "bcontrol/megarac.h"
#include "bcontrol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

typedef struct {
    uint8_t input[256], last[2110];
    uint32_t length, offset, sends, fragment;
    uint64_t now;
    bc_status send_status;
} fixture;
static bc_status read_source(void *user, uint64_t offset, uint32_t length, uint8_t *out) {
    (void)user; (void)offset; memset(out, 0, length); return BC_OK;
}
static uint64_t clock_ms(void *user) { return ((fixture *)user)->now; }
static bc_status send_bytes(void *user, const uint8_t *data, uint32_t n) {
    fixture *f = user; CHECK(n <= sizeof(f->last)); memcpy(f->last, data, n); ++f->sends; return f->send_status;
}
static bc_status receive_bytes(void *user, uint8_t *data, uint32_t cap, uint32_t *n, uint32_t timeout) {
    fixture *f = user; *n = f->length - f->offset;
    if (!*n) { f->now += timeout; return BC_TIMEOUT; }
    if (*n > cap) *n = cap;
    if (f->fragment && *n > f->fragment) *n = f->fragment;
    memcpy(data, f->input + f->offset, *n); f->offset += *n; return BC_OK;
}
static void reply(fixture *f, uint8_t instance, uint8_t code) {
    memset(f->input, 0, sizeof(f->input)); f->offset = 0; f->length = 63;
    memcpy(f->input, "IUSB    ", 8); f->input[12] = 31; f->input[23] = instance;
    f->input[41] = 0xf1; f->input[62] = code;
}
static bc_megarac_media_service *create(fixture *f) {
    bc_megarac_cd_source source = {sizeof(source), NULL, 2048, read_source};
    bc_megarac_media_io io = {f, send_bytes, receive_bytes, clock_ms};
    bc_megarac_media_service_options o = {sizeof(o), BC_ABI_VERSION, &source,
        {"token", 5}, BC_MEGARAC_MEDIA_SEND_DISCONNECT, 0, 100};
    bc_megarac_media_service *s = NULL;
    CHECK(bc_megarac_media_service_create(&o, &io, &s) == BC_OK); return s;
}
static bc_status drain(bc_megarac_media_service *s, fixture *f) {
    bc_media_session *session = NULL;
    CHECK(bc_megarac_media_wrap(s, &session) == BC_OK);
    bc_status status;
    do { status = bc_media_session_poll(session, 10); } while (status == BC_OK && f->offset < f->length);
    if (status == BC_OK) status = bc_media_session_poll(session, 10);
    bc_media_session_destroy(session);
    return status;
}
int main(void) {
    fixture f = {0}; f.fragment = 1; reply(&f, 7, 1);
    bc_megarac_media_service *s = create(&f);
    CHECK(bc_megarac_media_service_start(s) == BC_OK && f.last[41] == 0xf2);
    CHECK(drain(s, &f) == BC_OK);
    bc_megarac_media_service_info info;
    CHECK(bc_megarac_media_service_info_get(s, &info) == BC_OK);
    CHECK(info.state == BC_MEGARAC_STATE_STREAMING && info.instance == 7);
    bc_media_session *session = NULL;
    CHECK(bc_megarac_media_wrap(s, &session) == BC_OK);
    bc_media_session_info common = {.struct_size = sizeof(common)};
    CHECK(bc_media_session_info_get(session, &common) == BC_OK);
    CHECK(common.flags & BC_MEDIA_CONNECTED);
    CHECK((common.flags & BC_MEDIA_BYTES_READ_VALID) && !common.bytes_read);
    CHECK(!(common.flags & BC_MEDIA_REMOVAL_CONFIRMED));
    CHECK(bc_service_profile_verified(bc_megarac_media_service_profile_get(s), BC_SERVICE_LOCAL_MEDIA));
    CHECK(bc_media_session_poll(session, 10) == BC_OK);
    memset(f.input, 0, sizeof(f.input));
    memcpy(f.input, "IUSB    ", 8);
    f.input[8] = 1; f.input[10] = 32; f.input[12] = 29;
    f.input[17] = 5; f.input[18] = 1; f.input[23] = 7;
    f.input[11] = bc_wire_checksum(f.input, 32);
    bc_wire_write_le(f.input + 32, 2048, 4);
    f.input[41] = 0x28; f.input[49] = 1;
    f.length = 61;
    for (unsigned i = 0; i < 2; ++i) {
        f.offset = 0;
        CHECK(drain(s, &f) == BC_OK);
    }
    CHECK(bc_media_session_info_get(session, &common) == BC_OK && common.bytes_read == 2048);
    reply(&f, 8, 1);
    CHECK(drain(s, &f) == BC_PROTOCOL_ERROR);
    CHECK(bc_megarac_media_service_close(s) == BC_OK && f.last[41] == 0xf7 && f.last[23] == 7);
    uint32_t sends = f.sends;
    CHECK(bc_megarac_media_service_close(s) == BC_OK && f.sends == sends);
    CHECK(bc_megarac_media_service_info_get(s, &info) == BC_OK && (info.flags & BC_MEGARAC_MEDIA_REMOVAL_UNCONFIRMED));
    bc_media_session_destroy(session);
    bc_megarac_media_service_destroy(s);

    memset(&f, 0, sizeof(f)); reply(&f, 9, 8); s = create(&f);
    CHECK(bc_megarac_media_service_start(s) == BC_OK);
    CHECK(drain(s, &f) == BC_BUSY);
    CHECK(bc_megarac_media_service_failure_get(s)->cause == BC_CONSOLE_CAUSE_BUSY);
    CHECK(bc_megarac_media_service_close(s) == BC_OK && f.sends == 1);
    bc_megarac_media_service_destroy(s);

    memset(&f, 0, sizeof(f)); s = create(&f);
    CHECK(bc_megarac_media_service_start(s) == BC_OK);
    CHECK(bc_megarac_media_service_poll(s, 200) == BC_TIMEOUT);
    CHECK(bc_megarac_media_service_info_get(s, &info) == BC_OK && info.state == BC_MEGARAC_STATE_ERROR);
    CHECK(bc_megarac_media_service_close(s) == BC_OK && f.sends == 1);
    bc_megarac_media_service_destroy(s);

    memset(&f, 0, sizeof(f)); reply(&f, 0, 1); f.input[41] = 0x25; f.input[12] = 30; f.length = 62;
    s = create(&f); CHECK(bc_megarac_media_service_start(s) == BC_OK);
    CHECK(drain(s, &f) == BC_PROTOCOL_ERROR);
    CHECK(bc_megarac_media_service_close(s) == BC_OK && f.sends == 1);
    bc_megarac_media_service_destroy(s);
    return 0;
}

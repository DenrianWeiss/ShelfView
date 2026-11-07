#include "bcontrol/nbd_media.h"
#include "bcontrol/media_provider.h"
#include "bcontrol/wire.h"
#include <stdlib.h>
#include <string.h>

#define LIMIT (1024u * 1024u)
#define OPTION_MAGIC UINT64_C(0x49484156454f5054)
#define REPLY_MAGIC UINT64_C(0x3e889045565a9)
typedef struct {
    bc_media_options io;
    bc_media_source source;
    bc_media_session_info info;
    bc_service_profile profile;
    uint8_t input[4120];
    uint32_t used, phase, client_flags, discard;
    uint8_t discard_handle[8];
} nbd;
enum { IDLE, FLAGS, OPTIONS, REQUESTS, CLOSED };
static bc_status emit(nbd *m, const uint8_t *data, uint32_t size) { return m->io.emit(m->io.user, data, size); }
static void drop(nbd *m, uint32_t n) { m->used -= n; memmove(m->input, m->input + n, m->used); }
static bc_status reply(nbd *m, uint32_t option, uint32_t type, const uint8_t *data, uint32_t size) {
    uint8_t b[40] = {0};
    if (size > sizeof(b) - 20) return BC_INVALID_ARGUMENT;
    bc_wire_write_be(b, REPLY_MAGIC, 8); bc_wire_write_be(b + 8, option, 4);
    bc_wire_write_be(b + 12, type, 4); bc_wire_write_be(b + 16, size, 4);
    if (size) memcpy(b + 20, data, size);
    return emit(m, b, 20 + size);
}
static void connected(nbd *m) {
    m->phase = REQUESTS;
    m->info.flags |= BC_MEDIA_CONNECTED | BC_MEDIA_READY | BC_MEDIA_REMOVAL_UNCONFIRMED;
    m->profile.evidence |= BC_SERVICE_EVIDENCE_HANDSHAKE;
}
static bc_status response(nbd *m, const uint8_t handle[8], uint32_t error, const uint8_t *data, uint32_t size) {
    uint8_t *b = malloc(16u + size); if (!b) return BC_NO_MEMORY;
    bc_wire_write_be(b, 0x67446698, 4); bc_wire_write_be(b + 4, error, 4); memcpy(b + 8, handle, 8);
    if (size) memcpy(b + 16, data, size);
    bc_status status = emit(m, b, 16 + size); free(b); return status;
}
static bc_status parse(nbd *m) {
    if (m->phase == FLAGS) {
        if (m->used < 4) return BC_OK;
        m->client_flags = (uint32_t)bc_wire_read_be(m->input, 4);
        if (m->client_flags & ~3u) return BC_PROTOCOL_ERROR;
        drop(m, 4); m->phase = OPTIONS;
    }
    if (m->phase == OPTIONS) {
        if (m->used < 16) return BC_OK;
        if (bc_wire_read_be(m->input, 8) != OPTION_MAGIC) return BC_PROTOCOL_ERROR;
        uint32_t option = (uint32_t)bc_wire_read_be(m->input + 8, 4), size = (uint32_t)bc_wire_read_be(m->input + 12, 4);
        if (size > 4096) return BC_LIMIT_EXCEEDED;
        if (m->used < size + 16) return BC_OK;
        bc_status status;
        if (option == 1) {
            uint8_t b[134] = {0}; bc_wire_write_be(b, m->source.size, 8); bc_wire_write_be(b + 8, 3, 2);
            status = emit(m, b, m->client_flags & 2 ? 10 : 134);
            if (status == BC_OK) connected(m);
        } else if (option == 2) {
            status = reply(m, option, 1, NULL, 0); m->phase = CLOSED;
        } else if (option == 6 || option == 7) {
            uint32_t name = size >= 6 ? (uint32_t)bc_wire_read_be(m->input + 16, 4) : UINT32_MAX;
            if (name > size || size - name < 6 ||
                (uint32_t)bc_wire_read_be(m->input + 20 + name, 2) * 2 != size - name - 6)
                status = reply(m, option, 0x80000003u, NULL, 0);
            else {
                uint8_t b[12] = {0}; bc_wire_write_be(b + 2, m->source.size, 8); bc_wire_write_be(b + 10, 3, 2);
                status = reply(m, option, 3, b, sizeof(b));
                if (status == BC_OK) status = reply(m, option, 1, NULL, 0);
                if (status == BC_OK && option == 7) connected(m);
            }
        } else status = reply(m, option, 0x80000001u, NULL, 0);
        drop(m, size + 16); return status;
    }
    if (m->phase != REQUESTS) return BC_OK;
    if (m->discard) {
        uint32_t n = m->used < m->discard ? m->used : m->discard;
        drop(m, n); m->discard -= n;
        return m->discard ? BC_OK : response(m, m->discard_handle, 1, NULL, 0);
    }
    if (m->used < 28) return BC_OK;
    const uint8_t *b = m->input;
    if (bc_wire_read_be(b, 4) != 0x25609513) return BC_PROTOCOL_ERROR;
    uint32_t flags = (uint32_t)bc_wire_read_be(b + 4, 2), command = (uint32_t)bc_wire_read_be(b + 6, 2);
    uint8_t handle[8]; memcpy(handle, b + 8, 8);
    uint64_t offset = bc_wire_read_be(b + 16, 8); uint32_t size = (uint32_t)bc_wire_read_be(b + 24, 4);
    drop(m, 28); ++m->info.requests;
    if (size > LIMIT) return BC_LIMIT_EXCEEDED;
    if (command == 2) { m->phase = CLOSED; m->info.flags &= ~(BC_MEDIA_CONNECTED | BC_MEDIA_READY); return BC_OK; }
    if (command == 1) {
        m->discard = size; memcpy(m->discard_handle, handle, 8);
        return size ? BC_OK : response(m, handle, 1, NULL, 0);
    }
    if (command != 0 || flags || offset > m->source.size || size > m->source.size - offset)
        return response(m, handle, 22, NULL, 0);
    uint8_t *data = malloc(size ? size : 1); if (!data) return BC_NO_MEMORY;
    bc_status read = m->source.read(m->source.userdata, offset, size, data);
    bc_status status = response(m, handle, read == BC_OK ? 0 : 5, data, read == BC_OK ? size : 0);
    if (read == BC_OK) { m->info.bytes_read += size; if (status == BC_OK) m->info.bytes_served += size; }
    free(data); return status;
}
static bc_status feed(void *user, bc_bytes bytes) {
    nbd *m = user;
    if (m->phase == IDLE || m->phase == CLOSED) return BC_SHUTTING_DOWN;
    const uint8_t *p = bytes.data; uint64_t left = bytes.length;
    while (left || m->used) {
        uint32_t n = left < sizeof(m->input) - m->used ? (uint32_t)left : (uint32_t)sizeof(m->input) - m->used;
        if (n) { memcpy(m->input + m->used, p, n); m->used += n; p += n; left -= n; }
        uint32_t before = m->used;
        bc_status status = parse(m);
        if (status != BC_OK) { m->info.status = status; m->info.flags |= BC_MEDIA_FAILED; return status; }
        if (m->phase == CLOSED) return left || m->used ? BC_PROTOCOL_ERROR : BC_OK;
        if (before == m->used) {
            if (!left) break;
            if (m->used == sizeof(m->input)) return BC_LIMIT_EXCEEDED;
        }
    }
    return BC_OK;
}
static bc_status poll(void *user, uint32_t timeout) {
    nbd *m = user; uint8_t data[65536]; uint32_t size = 0;
    bc_status status = m->io.receive(m->io.user, data, sizeof(data), &size, timeout);
    return status == BC_TIMEOUT ? BC_OK : status == BC_OK ? feed(m, (bc_bytes){data, size}) : status;
}
static bc_status control(void *user, uint32_t command) {
    nbd *m = user;
    if (command == BC_MEDIA_CONTROL_START) {
        if (m->phase != IDLE) return BC_BUSY;
        uint8_t b[18] = "NBDMAGIC"; bc_wire_write_be(b + 8, OPTION_MAGIC, 8); bc_wire_write_be(b + 16, 3, 2);
        m->phase = FLAGS; m->info.flags |= BC_MEDIA_REMOVAL_UNCONFIRMED;
        return emit(m, b, sizeof(b));
    }
    if (command == BC_MEDIA_CONTROL_CLOSE || command == BC_MEDIA_CONTROL_EJECT) {
        m->phase = CLOSED; m->info.flags &= ~(BC_MEDIA_READY | BC_MEDIA_CONNECTED | BC_MEDIA_SOURCE_ATTACHED);
        m->info.flags |= BC_MEDIA_EJECTING; return BC_OK;
    }
    return command == BC_MEDIA_CONTROL_KEEPALIVE ? BC_OK : BC_UNSUPPORTED;
}
static bc_status info(const void *user, bc_media_session_info *out) { *out = ((const nbd *)user)->info; return BC_OK; }
static const bc_service_profile *profile(const void *user) { return &((const nbd *)user)->profile; }
bc_status bc_nbd_media_create(const bc_media_options *io, bc_media_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!io || io->struct_size != sizeof(*io) || !io->source || !io->source->read || !io->source->size || !io->emit || !io->receive) return BC_INVALID_ARGUMENT;
    nbd *m = calloc(1, sizeof(*m)); if (!m) return BC_NO_MEMORY;
    m->io = *io; m->source = *io->source;
    m->info = (bc_media_session_info){.struct_size = sizeof(m->info), .flags = BC_MEDIA_SOURCE_ATTACHED | BC_MEDIA_BYTES_READ_VALID};
    m->profile = (bc_service_profile){sizeof(m->profile), BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_OPENBMC, BC_SERVICE_OPENBMC_MEDIA_NBD, BC_SERVICE_EVIDENCE_DESCRIPTOR};
    bc_media_provider p = {sizeof(p), feed, poll, control, info, NULL, free, profile, NULL};
    bc_status status = bc_media_session_wrap(&p, m, out); if (status != BC_OK) free(m); return status;
}

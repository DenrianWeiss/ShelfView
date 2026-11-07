#include "bcontrol/avocent_media.h"
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/media_provider.h"
#include "bcontrol/wire.h"
#include "../../core/log_internal.h"
#include <stdlib.h>
#include <string.h>
#define BLOCK 2048u
#define CAPACITY (128u * 1024u + 32u)
typedef struct {
    bc_media_options io;
    bc_media_source source;
    bc_avocent_launch ticket;
    bc_media_session_info info;
    bc_service_profile profile;
    uint8_t input[CAPACITY];
    uint32_t used, needed, slot, blocks, phase;
    uint64_t last, deadline, heartbeat;
    int owned, acknowledged, closed;
} media;
enum { CREATED, SETUP, LOGIN, ENUMERATE, MAPPING, MOUNTED, RELEASING, RELEASED };
static void wipe(void *p, size_t n) { volatile uint8_t *b = p; while (n--) *b++ = 0; }
static bc_status failed(media *m, bc_status status) {
    if (status != BC_OK) { m->info.status = status; m->info.flags |= BC_MEDIA_FAILED;
        m->info.flags &= ~(BC_MEDIA_CONNECTED | BC_MEDIA_READY);
        if (m->owned) m->info.flags |= BC_MEDIA_REMOVAL_UNCONFIRMED; }
    return status;
}
static bc_status clock_now(media *m, uint64_t *now) {
    *now = m->io.clock(m->io.user);
    if (*now < m->last) return BC_INVALID_ARGUMENT;
    m->last = *now; return BC_OK;
}
static bc_status send_packet(media *m, uint32_t type, uint32_t slot, uint8_t *b, uint32_t n) {
    memcpy(b, "AVMP", 4); bc_wire_write_be(b + 4, n, 4);
    bc_wire_write_be(b + 8, type, 2); bc_wire_write_be(b + 10, slot, 2);
    return m->io.emit(m->io.user, b, n);
}
static bc_status simple(media *m, uint32_t type, uint32_t slot) {
    uint8_t b[12] = {0}; return send_packet(m, type, slot, b, sizeof(b));
}
static bc_status result(media *m, uint32_t slot, uint32_t status) {
    uint8_t b[16] = {0}; bc_wire_write_be(b + 12, status, 4);
    return send_packet(m, 0x0410, slot, b, sizeof(b));
}
static bc_status map(media *m) {
    uint8_t b[44] = {0}; bc_wire_write_be(b + 12, BLOCK, 4);
    bc_wire_write_be(b + 16, m->blocks, 4); b[20] = 1; b[21] = m->blocks > 255 ? 255 : (uint8_t)m->blocks;
    b[23] = 20; b[25] = 18; b[26] = b[27] = 1;
    b[29] = b[37] = 0x14; b[30] = 1; b[38] = 0xaa;
    bc_wire_write_be(b + 40, m->blocks, 4);
    m->owned = 1; m->phase = MAPPING;
    m->info.flags |= BC_MEDIA_REMOVAL_UNCONFIRMED;
    return send_packet(m, 0x0210, m->slot, b, sizeof(b));
}
static bc_status release(media *m) {
    if (!m->owned || m->phase == RELEASING) return BC_OK;
    m->phase = RELEASING; m->acknowledged = 0;
    m->info.flags |= BC_MEDIA_EJECTING | BC_MEDIA_REMOVAL_UNCONFIRMED;
    m->info.flags &= ~BC_MEDIA_READY;
    return simple(m, 0x0220, m->slot);
}
static bc_status read_blocks(media *m, const uint8_t *b, uint32_t n, uint32_t slot) {
    if (n != 24 || slot != m->slot || !m->owned || m->phase == RELEASING) return BC_PROTOCOL_ERROR;
    uint32_t start = (uint32_t)bc_wire_read_be(b + 12, 4), count = (uint32_t)bc_wire_read_be(b + 16, 4);
    uint32_t factor = (uint32_t)bc_wire_read_be(b + 20, 4);
    if (!count || !factor || start >= m->blocks || count > m->blocks - start) return result(m, slot, 2);
    ++m->info.requests;
    uint8_t *out = malloc(20 + 32 * BLOCK); if (!out) return BC_NO_MEMORY;
    bc_status status = BC_OK;
    while (count && status == BC_OK) {
        uint64_t now; status = clock_now(m, &now);
        if (status == BC_OK && now >= m->deadline) status = BC_TIMEOUT;
        if (status != BC_OK) break;
        uint32_t chunk = count < factor ? count : factor; if (chunk > 32) chunk = 32;
        status = m->source.read(m->source.userdata, (uint64_t)start * BLOCK, chunk * BLOCK, out + 20);
        if (status != BC_OK) { status = result(m, slot, 2); break; }
        bc_wire_write_be(out + 12, start, 4); bc_wire_write_be(out + 16, chunk, 4);
        status = send_packet(m, 0x0300, slot, out, 20 + chunk * BLOCK);
        if (status == BC_OK) { m->info.bytes_read += (uint64_t)chunk * BLOCK; m->info.bytes_served += (uint64_t)chunk * BLOCK; }
        count -= chunk; start += chunk;
    }
    wipe(out, 20 + 32 * BLOCK); free(out);
    return status == BC_OK && !count ? result(m, slot, 0) : status;
}
static bc_status packet(media *m, const uint8_t *b, uint32_t n) {
    if (m->phase == SETUP) {
        bc_avocent_setup setup;
        bc_status status = bc_avocent_apcp_parse(b, n, &setup);
        if (status == BC_OK && (setup.major != 1 || setup.minor != 14)) status = BC_UNSUPPORTED;
        uint8_t login[256]; uint32_t size = 0;
        if (status == BC_OK) status = bc_avocent_media_login_v4_encode(
            (bc_string){m->ticket.username, strlen(m->ticket.username)},
            (bc_string){m->ticket.password, strlen(m->ticket.password)}, login, sizeof(login), &size);
        wipe(&m->ticket, sizeof(m->ticket));
        if (status == BC_OK) status = m->io.emit(m->io.user, login, size);
        wipe(login, sizeof(login)); m->phase = LOGIN;
        return status;
    }
    if (!memcmp(b, "APCP", 4))
        return (m->io.flags & BC_MEDIA_TRANSPORT_WEBSOCKET) && n == 12 &&
            bc_wire_read_be(b + 8, 2) == 0x8400 ? BC_OK : BC_PROTOCOL_ERROR;
    uint32_t type = (uint32_t)bc_wire_read_be(b + 8, 2), slot = (uint32_t)bc_wire_read_be(b + 10, 2);
    BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "avocent.media.packet", "phase=%u type=%u slot=%u length=%u", m->phase, type, slot, n);
    ++m->info.packets;
    if (m->phase == LOGIN) {
        bc_avocent_login_result login;
        bc_status status = bc_avocent_login_parse(BC_AVOCENT_MEDIA, b, n, &login);
        if (status != BC_OK) return status;
        m->info.device_code = login.status;
        if (login.status) return BC_AUTHENTICATION_FAILED;
        m->info.flags |= BC_MEDIA_CONNECTED; m->phase = ENUMERATE;
        m->profile.evidence |= BC_SERVICE_EVIDENCE_HANDSHAKE;
        return simple(m, 0x0200, 65535);
    }
    if (type == 0x8200) {
        if (n < 14) return BC_PROTOCOL_ERROR;
        uint32_t count = (uint32_t)bc_wire_read_be(b + 12, 2);
        if (!count || count > 256 || n != 14 + count * 4) return BC_PROTOCOL_ERROR;
        for (uint32_t i = 0; i < count; ++i) if (b[15 + 4*i] > 3) return BC_UNSUPPORTED;
        if (m->phase == ENUMERATE) {
            int busy = 0;
            for (uint32_t i = 0; i < count; ++i) if (b[14 + 4*i] == 2) {
                if (!b[15 + 4*i]) { m->slot = i; return map(m); }
                if (b[15 + 4*i] == 1) busy = 1;
            }
            return busy ? BC_BUSY : BC_UNSUPPORTED;
        }
        if (m->slot >= count || b[14 + 4*m->slot] != 2) return BC_PROTOCOL_ERROR;
        uint32_t state = b[15 + 4*m->slot];
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "avocent.media.slot", "slot=%u state=%u phase=%u acknowledged=%u", m->slot, state, m->phase, m->acknowledged);
        if (m->acknowledged && m->phase == MAPPING && state == 1) {
            m->phase = MOUNTED; m->info.flags |= BC_MEDIA_MOUNT_CONFIRMED | BC_MEDIA_READY;
        } else if (m->acknowledged && m->phase == RELEASING && state == 0) {
            m->phase = RELEASED; m->owned = 0;
            m->info.flags &= ~(BC_MEDIA_MOUNT_CONFIRMED | BC_MEDIA_SOURCE_ATTACHED | BC_MEDIA_EJECTING | BC_MEDIA_REMOVAL_UNCONFIRMED);
            m->info.flags |= BC_MEDIA_REMOVAL_CONFIRMED;
        } else if (m->phase == MOUNTED && state != 1) return BC_PROTOCOL_ERROR;
        return BC_OK;
    }
    if (type == 0x8410) {
        if (n != 16 || slot != m->slot) return BC_PROTOCOL_ERROR;
        m->info.device_code = (uint32_t)bc_wire_read_be(b + 12, 4);
        if (m->info.device_code) {
            if (m->phase == MAPPING && (m->info.device_code == 1 || m->info.device_code == 5 || m->info.device_code == 6 || m->info.device_code == 7)) {
                m->owned = 0; m->info.flags &= ~BC_MEDIA_REMOVAL_UNCONFIRMED;
            }
            return m->info.device_code == 5 ? BC_BUSY : BC_UNSUPPORTED;
        }
        if (m->phase == MAPPING || m->phase == RELEASING) { m->acknowledged = 1; return simple(m, 0x0200, 65535); }
        return BC_OK;
    }
    if (type == 0x8300) return read_blocks(m, b, n, slot);
    if (type == 0x8310) return n >= 20 && slot == m->slot ? result(m, slot, 3) : BC_PROTOCOL_ERROR;
    if (type == 0x8240) return n == 12 && slot == m->slot ? release(m) : BC_PROTOCOL_ERROR;
    if (type == 0x8110) return BC_IO_ERROR;
    return BC_UNSUPPORTED;
}
static bc_status poll(void *user, uint32_t timeout) {
    media *m = user; if (m->closed || m->phase == CREATED) return BC_INVALID_ARGUMENT;
    uint64_t now; bc_status status = clock_now(m, &now);
    if (status != BC_OK) return failed(m, status);
    if (m->phase == MOUNTED || m->phase == RELEASED) m->deadline = now + m->io.timeout_ms;
    if (now >= m->deadline) return failed(m, BC_TIMEOUT);
    if (m->phase >= ENUMERATE && now - m->heartbeat >= m->info.heartbeat_interval_ms) {
        status = simple(m, 0x0400, 0); m->heartbeat = now;
        if (status != BC_OK) return failed(m, status);
    }
    uint32_t budget = (uint32_t)(m->deadline - now); if (timeout < budget) budget = timeout;
    uint32_t received = 0;
    status = m->io.receive(m->io.user, m->input + m->used, m->needed - m->used, &received, budget);
    if (status == BC_TIMEOUT) return BC_OK;
    if (status != BC_OK) return failed(m, status);
    if (!received || received > m->needed - m->used) return failed(m, BC_PROTOCOL_ERROR);
    m->used += received;
    if (m->used == 12 && m->needed == 12) {
        uint32_t n = (uint32_t)bc_wire_read_be(m->input + 4, 4);
        int heartbeat = m->phase >= LOGIN && (m->io.flags & BC_MEDIA_TRANSPORT_WEBSOCKET) &&
            !memcmp(m->input, "APCP", 4) && n == 12 && bc_wire_read_be(m->input + 8, 2) == 0x8400;
        if ((!heartbeat && memcmp(m->input, m->phase == SETUP ? "APCP" : "AVMP", 4)) || n < 12 || n > CAPACITY) {
            BC_LOG_WARN(BC_LOG_CATEGORY_MEDIA, "avocent.media.header", "phase=%u magic=%u length=%u type=%u", m->phase,
                (uint32_t)bc_wire_read_be(m->input, 4), n, (uint32_t)bc_wire_read_be(m->input + 8, 2));
            return failed(m, BC_PROTOCOL_ERROR);
        }
        m->needed = n;
    }
    if (m->used == m->needed) {
        status = packet(m, m->input, m->used); wipe(m->input, m->used); m->used = 0; m->needed = 12;
    }
    return failed(m, status);
}
static bc_status control(void *user, uint32_t command) {
    media *m = user; uint64_t now; bc_status status = clock_now(m, &now);
    if (status != BC_OK) return failed(m, status);
    if (command == BC_MEDIA_CONTROL_START) {
        if (m->phase != CREATED || m->closed) return BC_INVALID_ARGUMENT;
        uint8_t b[153]; uint32_t n;
        if (m->io.flags & BC_MEDIA_TRANSPORT_WEBSOCKET) {
            status = bc_avocent_apcp_websocket_request(BC_AVOCENT_MEDIA, 0, b);
            n = BC_AVOCENT_APCP_EXTENDED_SIZE; m->phase = SETUP;
        } else {
            status = bc_avocent_login_encode(&m->ticket, 0, b, sizeof(b), &n);
            wipe(&m->ticket, sizeof(m->ticket)); m->phase = LOGIN;
        }
        m->deadline = now + m->io.timeout_ms; m->heartbeat = now;
        if (status == BC_OK) status = m->io.emit(m->io.user, b, n);
        wipe(b, sizeof(b)); return failed(m, status);
    }
    if (command == BC_MEDIA_CONTROL_KEEPALIVE) return m->closed ? BC_INVALID_ARGUMENT : simple(m, 0x0400, 0);
    if (command != BC_MEDIA_CONTROL_EJECT && command != BC_MEDIA_CONTROL_CLOSE) return BC_UNSUPPORTED;
    if (m->closed) return BC_OK;
    m->deadline = now + (m->io.timeout_ms < 5000 ? m->io.timeout_ms : 5000);
    status = release(m);
    while (status == BC_OK && m->owned) status = poll(m, 50);
    if (command == BC_MEDIA_CONTROL_CLOSE) { m->closed = 1; m->info.flags &= ~(BC_MEDIA_CONNECTED | BC_MEDIA_READY); }
    return failed(m, status);
}
static bc_status info(const void *user, bc_media_session_info *out) { const media *m = user; *out = m->info; out->state = m->phase; return BC_OK; }
static const bc_service_profile *profile(const void *user) { return &((const media *)user)->profile; }
static void destroy(void *user) { wipe(user, sizeof(media)); free(user); }
bc_status bc_avocent_media_create(const bc_media_options *o, bc_media_session **out) {
    if (!out) return BC_INVALID_ARGUMENT; *out = NULL;
    if (!o || o->struct_size != sizeof(*o) || o->abi_version != BC_ABI_VERSION || !o->source ||
        o->source->struct_size != sizeof(*o->source) || !o->source->read || !o->source->size ||
        o->source->size % BLOCK || o->source->size / BLOCK > UINT32_MAX || !o->clock || !o->emit ||
        !o->receive || !o->timeout_ms || (o->flags & ~BC_MEDIA_TRANSPORT_WEBSOCKET) || o->instance) return BC_INVALID_ARGUMENT;
    const bc_avocent_launch *ticket = bc_media_offer_payload(o->offer, BC_MEDIA_OFFER_AVOCENT, sizeof(*ticket));
    if (!ticket || ticket->service != BC_AVOCENT_MEDIA ||
        !memchr(ticket->username, 0, sizeof(ticket->username)) || !memchr(ticket->password, 0, sizeof(ticket->password)) ||
        (!!(o->flags & BC_MEDIA_TRANSPORT_WEBSOCKET) != (ticket->apcp == BC_AVOCENT_APCP_WEBSOCKET_MEDIA))) return BC_INVALID_ARGUMENT;
    media *m = calloc(1, sizeof(*m)); if (!m) return BC_NO_MEMORY;
    m->io = *o; m->source = *o->source; m->ticket = *ticket; m->blocks = (uint32_t)(m->source.size / BLOCK); m->needed = 12;
    m->last = o->clock(o->user); m->info.struct_size = sizeof(m->info);
    m->info.flags = BC_MEDIA_SOURCE_ATTACHED | BC_MEDIA_BYTES_READ_VALID;
    m->info.heartbeat_interval_ms = 1000;
    m->profile = (bc_service_profile){sizeof(m->profile), BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_AVOCENT, BC_SERVICE_AVOCENT_MEDIA_AVMP_CD, BC_SERVICE_EVIDENCE_DESCRIPTOR};
    if (o->flags & BC_MEDIA_TRANSPORT_WEBSOCKET) m->profile.variant = BC_SERVICE_AVOCENT_MEDIA_WEBSOCKET_114;
    bc_media_provider provider = {sizeof(provider), NULL, poll, control, info, NULL, destroy, profile, NULL};
    bc_status status = bc_media_session_wrap(&provider, m, out);
    if (status != BC_OK) destroy(m);
    return status;
}

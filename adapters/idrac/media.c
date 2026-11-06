#include "bcontrol/idrac_media.h"
#include "bcontrol/media_provider.h"
#include "../../core/log_internal.h"
#include <stdlib.h>
#include <string.h>

#define CD_BLOCK 2048u
#define MAX_READ (16u * 1024u * 1024u)
struct bc_idrac_media {
    bc_idrac_media_emit emit;
    void *userdata;
    uint32_t token;
    uint8_t key[24];
    uint32_t key_length;
    int has_key, removal_confirmed;
    bc_idrac_media_source source;
    bc_idrac_media_state state;
    bc_service_profile profile;
    bc_console_failure failure;
    int mount_requested;
};
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static bc_status words(bc_idrac_media *m, const uint32_t *values, uint32_t count) {
    uint8_t bytes[64];
    if (count > sizeof(bytes) / 4) return BC_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < count; ++i)
        for (uint32_t j = 0; j < 4; ++j) bytes[i * 4 + j] = (uint8_t)(values[i] >> (j * 8));
    return m->emit(m->userdata, bytes, count * 4);
}
static bc_status read_blocks(bc_idrac_media *m, uint32_t start, uint32_t count) {
    uint64_t offset = (uint64_t)start * CD_BLOCK, length = (uint64_t)count * CD_BLOCK;
    if (!m->source.read || !count || length > MAX_READ || offset > m->source.size ||
        length > m->source.size - offset) return BC_INVALID_ARGUMENT;
    uint8_t *buffer = malloc((size_t)length);
    if (!buffer) return BC_NO_MEMORY;
    bc_status status = m->source.read(m->source.userdata, offset, (uint32_t)length, buffer);
    uint32_t header[] = {1, 1, 28, m->token, start, count, start + count, CD_BLOCK, (uint32_t)length};
    if (status == BC_OK) status = words(m, header, 9);
    if (status == BC_OK) status = m->emit(m->userdata, buffer, (uint32_t)length);
    if (status == BC_OK) m->state.bytes_read += length;
    free(buffer);
    return status;
}
bc_status bc_idrac_media_create(bc_idrac_media_emit emit, void *userdata, bc_string key, bc_idrac_media **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!emit || !key.data || !key.length || key.length > sizeof(((bc_idrac_media *)0)->key)) return BC_INVALID_ARGUMENT;
    for (uint64_t i = 0; i < key.length; ++i)
        if ((unsigned char)key.data[i] < 33 || (unsigned char)key.data[i] > 126) return BC_INVALID_ARGUMENT;
    bc_idrac_media *m = calloc(1, sizeof(*m));
    if (!m) return BC_NO_MEMORY;
    m->profile = (bc_service_profile){sizeof(m->profile), BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_IDRAC, BC_SERVICE_IDRAC_MEDIA_EHTML5, 0};
    memcpy(m->key, key.data, (size_t)key.length);
    m->key_length = (uint32_t)key.length;
    m->has_key = 1;
    m->emit = emit; m->userdata = userdata; *out = m;
    return BC_OK;
}
static bc_status feed_message(bc_idrac_media *m, const uint8_t *p, uint32_t length) {
    if (!m || !p || length < 16 || length % 4) return BC_INVALID_ARGUMENT;
    uint32_t type = le32(p), image = le32(p + 4), size = le32(p + 8), token = le32(p + 12);
    BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "idrac.media.feed", "type=%u image=%u size=%u len=%u", type, image, size, length);
    if (type == 16) {
        if (length < 40 || m->state.attached || m->state.ejecting) return BC_PROTOCOL_ERROR;
        m->token = token; memcpy(m->key, p + 16, sizeof(m->key)); m->has_key = 1; m->key_length = 24;
        m->state.connected = 1;
        m->profile.evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR | BC_SERVICE_EVIDENCE_HANDSHAKE;
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "idrac.media.authenticated", "len=%u", length);
        return BC_OK;
    }
    if (!m->has_key) return BC_PROTOCOL_ERROR;
    /* The device's own client only validates the token for read requests. Status
     * and eject notifications may carry 0 or a freshly issued token. */
    switch (type) {
    case 8192: {
        if (image || size) return BC_UNSUPPORTED;
        m->token = token;
        uint32_t reply[12] = {8192, 0, 32, m->token};
        for (uint32_t i = 0; i < 6; ++i) reply[4 + i] = le32(m->key + i * 4);
        bc_status status = words(m, reply, 12);
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "idrac.media.key2",
            "type=%u image=%u size=%u key_len=%u token_zero=%d emitted=%d",
            reply[0], reply[1], reply[2], m->key_length, m->token == 0, status == BC_OK);
        if (status == BC_OK) { m->state.ready = 1; }
        if (status == BC_OK) m->profile.evidence |= BC_SERVICE_EVIDENCE_DESCRIPTOR;
        return status;
    }
    case 1:
        if (m->token && token != m->token) return BC_PROTOCOL_ERROR;
        if (image != 1) return BC_UNSUPPORTED;
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "idrac.media.read_request",
            "len=%u msgLen=%u start=%u req=%u word6=%u word7=%u",
            length, size, length >= 20 ? le32(p + 16) : 0, length >= 24 ? le32(p + 20) : 0,
            length >= 28 ? le32(p + 24) : 0, length >= 32 ? le32(p + 28) : 0);
        if (length < 28 || length % 4 || size < 12) return BC_PROTOCOL_ERROR;
        return read_blocks(m, le32(p + 16), le32(p + 20));
    case 8:
        if (image != 1 || length != 16) return BC_UNSUPPORTED;
        return bc_idrac_media_eject(m);
    case 256:
        if (length != 20) return BC_PROTOCOL_ERROR;
        m->state.server_status = le32(p + 16);
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "idrac.media.status", "status=%u", m->state.server_status);
        if (image == 1 && m->state.server_status == 25) {
            memset(&m->source, 0, sizeof(m->source));
            m->state.attached = m->state.mounted = m->state.ejecting = 0;
            m->removal_confirmed = 1;
        }
        if (m->state.server_status == 0 || m->state.server_status == 38 || m->state.server_status == 70)
            m->state.connected = 1;
        if (image == 1 && m->state.server_status == 70) {
            m->state.mounted = 1;
            m->removal_confirmed = 0; m->mount_requested = 1;
        }
        switch (m->state.server_status) {
        case 0: case 25: case 38: case 70: return BC_OK;
        default: {
            uint32_t code = m->state.server_status;
            bc_status status = code == 39 || code == 84 || code == 89 ? BC_AUTHENTICATION_FAILED :
                code == 41 || code == 42 ? BC_BUSY : BC_IO_ERROR;
            uint32_t cause = code == 39 || code == 84 ? BC_CONSOLE_CAUSE_ACCESS_DENIED :
                code == 89 ? BC_CONSOLE_CAUSE_SESSION_REJECTED : status == BC_BUSY ?
                BC_CONSOLE_CAUSE_BUSY : BC_CONSOLE_CAUSE_UNKNOWN;
            m->failure = (bc_console_failure){sizeof(m->failure), status, BC_CONSOLE_PHASE_MEDIA,
                cause, BC_SERVICE_IDRAC_MEDIA_EHTML5, 0, code <= INT32_MAX ? (int32_t)code : 0,
                BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_IDRAC};
            return status;
        }
        }
    default: return BC_UNSUPPORTED;
    }
}
bc_status bc_idrac_media_feed_message(bc_idrac_media *m, const uint8_t *p, uint32_t length) {
    if (!m) return BC_INVALID_ARGUMENT;
    memset(&m->failure, 0, sizeof(m->failure));
    bc_status status = feed_message(m, p, length);
    if (status != BC_OK && m->failure.status == BC_OK)
        m->failure = (bc_console_failure){sizeof(m->failure), status, BC_CONSOLE_PHASE_MEDIA,
            status == BC_PROTOCOL_ERROR || status == BC_UNSUPPORTED ? BC_CONSOLE_CAUSE_PROTOCOL :
            BC_CONSOLE_CAUSE_UNKNOWN, BC_SERVICE_IDRAC_MEDIA_EHTML5, 0, 0,
            BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_IDRAC};
    return status;
}
const bc_service_profile *bc_idrac_media_profile_get(const bc_idrac_media *m) { return m ? &m->profile : NULL; }
const bc_console_failure *bc_idrac_media_failure_get(const bc_idrac_media *m) {
    return m && m->failure.status != BC_OK ? &m->failure : NULL;
}
bc_status bc_idrac_media_attach_cd(bc_idrac_media *m, const bc_idrac_media_source *source) {
    if (!m || !source || !source->read || !source->size || source->size % CD_BLOCK ||
        source->size / CD_BLOCK > UINT32_MAX) return BC_INVALID_ARGUMENT;
    if (!m->state.ready || !bc_service_profile_verified(&m->profile, BC_SERVICE_LOCAL_MEDIA)) return BC_UNSUPPORTED;
    if (m->state.attached || m->state.ejecting) return BC_BUSY;
    uint32_t blocks = (uint32_t)(source->size / CD_BLOCK);
    /* Inquiry TOC is counted but absent from the device browser's wire payload. */
    BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "idrac.media.attach", "blocks=%u", blocks);
    uint32_t inquiry[] = {32, 1, 28, m->token, blocks, CD_BLOCK, 0, 0, 0, 1, 20};
    m->source = *source;
    m->removal_confirmed = 0; m->mount_requested = 1;
    bc_status status = words(m, inquiry, 11);
    if (status != BC_OK) { memset(&m->source, 0, sizeof(m->source)); return status; }
    m->state.attached = 1;
    return read_blocks(m, 0, blocks < 32 ? blocks : 32);
}
bc_status bc_idrac_media_eject(bc_idrac_media *m) {
    if (!m) return BC_INVALID_ARGUMENT;
    if (!m->state.ready) return BC_UNSUPPORTED;
    if (m->state.ejecting) return BC_BUSY;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "idrac.media.eject_request", "attached=%u", m->state.attached);
    uint32_t header[] = {8, 1, 0, m->token};
    bc_status status = words(m, header, 4);
    if (status == BC_OK) m->state.ejecting = 1;
    return status;
}
bc_status bc_idrac_media_unmap(bc_idrac_media *m) {
    if (!m) return BC_INVALID_ARGUMENT;
    if (!m->state.ready || !m->has_key) return BC_UNSUPPORTED;
    uint32_t message[] = {1024, 0, 0, m->token};
    BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "idrac.media.unmap", "attached=%u", m->state.attached);
    return words(m, message, 4);
}

bc_status bc_idrac_media_heartbeat(bc_idrac_media *m) {
    if (!m) return BC_INVALID_ARGUMENT;
    if (!m->state.ready) return BC_UNSUPPORTED;
    uint32_t header[] = {2048, 0, 0, m->token};
    return words(m, header, 4);
}
const bc_idrac_media_state *bc_idrac_media_state_get(const bc_idrac_media *m) { return m ? &m->state : NULL; }
void bc_idrac_media_destroy(bc_idrac_media *m) {
    if (!m) return;
    volatile uint8_t *key = m->key;
    for (size_t i = 0; i < sizeof(m->key); ++i) key[i] = 0;
    free(m);
}
static bc_status media_feed(void *context, bc_bytes bytes) {
    return bc_idrac_media_feed_message(context, bytes.data, (uint32_t)bytes.length);
}
static bc_status media_control(void *context, uint32_t command) {
    if (command == BC_MEDIA_CONTROL_START) return BC_OK;
    if (command == BC_MEDIA_CONTROL_KEEPALIVE) return bc_idrac_media_heartbeat(context);
    if (command == BC_MEDIA_CONTROL_CLOSE) return bc_idrac_media_unmap(context);
    return bc_idrac_media_eject(context);
}
static bc_status media_info(const void *context, bc_media_session_info *out) {
    const bc_idrac_media_state *state = bc_idrac_media_state_get(context);
    out->flags = BC_MEDIA_BYTES_READ_VALID | (state->ready && state->connected ? BC_MEDIA_CONNECTED : 0) |
        (state->attached ? BC_MEDIA_SOURCE_ATTACHED : 0) |
        (state->mounted ? BC_MEDIA_MOUNT_CONFIRMED : 0) |
        (((const bc_idrac_media *)context)->removal_confirmed ? BC_MEDIA_REMOVAL_CONFIRMED : 0);
    out->bytes_read = state->bytes_read;
    out->state = state->ready && state->connected ? 2 : 1;
    out->status = ((const bc_idrac_media *)context)->failure.status;
    out->device_code = state->server_status;
    out->heartbeat_interval_ms = 20000;
    if (state->ready) out->flags |= BC_MEDIA_READY;
    if (state->ejecting) out->flags |= BC_MEDIA_EJECTING;
    if (((const bc_idrac_media *)context)->mount_requested && !((const bc_idrac_media *)context)->removal_confirmed) out->flags |= BC_MEDIA_REMOVAL_UNCONFIRMED;
    if (out->status != BC_OK) { out->state = 4; out->flags |= BC_MEDIA_FAILED; }
    return BC_OK;
}
static bc_status media_attach(void *context, const bc_media_source *source) {
    bc_idrac_media_source value = {source->size, source->userdata, source->read};
    return bc_idrac_media_attach_cd(context, &value);
}
static void media_destroy(void *context) { bc_idrac_media_destroy(context); }
static const bc_service_profile *media_profile(const void *context) { return bc_idrac_media_profile_get(context); }
static const bc_console_failure *media_failure(const void *context) { return bc_idrac_media_failure_get(context); }
bc_status bc_idrac_media_wrap(bc_idrac_media *media, bc_media_session **out) {
    const bc_media_provider provider = {sizeof(provider), media_feed, NULL, media_control, media_info, media_attach, media_destroy, media_profile, media_failure};
    return bc_media_session_wrap(&provider, media, out);
}

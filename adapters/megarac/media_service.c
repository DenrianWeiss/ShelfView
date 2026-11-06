#include "bcontrol/media_provider.h"
#include "bcontrol/megarac.h"
#include "bcontrol/wire.h"
#include <stdlib.h>
#include <string.h>

#define MEDIA_LIMIT (1024u * 1024u + 62u)
struct bc_megarac_media_service {
    bc_megarac_media_io io;
    bc_megarac_cd *cd;
    bc_megarac_cd_source source;
    bc_megarac_media_service_info info;
    bc_service_profile profile;
    bc_console_failure failure;
    uint32_t flags, received, timeout, auth_length;
    uint64_t started, last_time, bytes_read;
    uint8_t auth[160];
    uint8_t *input, *output;
    int prefix, closed;
    bc_status close_status;
};
static bc_status fail(bc_megarac_media_service *s, bc_status status) {
    s->info.state = BC_MEGARAC_STATE_ERROR;
    if (s->failure.status == BC_OK) s->failure = (bc_console_failure){sizeof(s->failure), status,
        BC_CONSOLE_PHASE_MEDIA, BC_CONSOLE_CAUSE_UNKNOWN, 0, 0, 0,
        BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_MEGARAC};
    return status;
}
static bc_status read_source(void *user, uint64_t offset, uint32_t length, uint8_t *out) {
    bc_megarac_media_service *s = user;
    bc_status status = s->source.read(s->source.userdata, offset, length, out);
    if (status == BC_OK) s->bytes_read += length;
    return status;
}
bc_status bc_megarac_media_service_create(const bc_megarac_media_service_options *o,
    const bc_megarac_media_io *io, bc_megarac_media_service **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!o || o->struct_size != sizeof(*o) || o->abi_version != BC_ABI_VERSION ||
        !io || !io->send || !io->recv || !io->clock_ms || o->instance > 255 ||
        !o->source || o->source->struct_size != sizeof(*o->source) || !o->source->read ||
        (o->flags & ~(BC_MEGARAC_MEDIA_SEND_DISCONNECT | BC_MEGARAC_MEDIA_TUNNEL_PREFIX))) return BC_INVALID_ARGUMENT;
    bc_megarac_media_service *s = calloc(1, sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    s->io = *io; s->flags = o->flags; s->prefix = !!(o->flags & BC_MEGARAC_MEDIA_TUNNEL_PREFIX);
    s->timeout = o->authentication_timeout_ms ? o->authentication_timeout_ms : 5000;
    s->info = (bc_megarac_media_service_info){sizeof(s->info), BC_MEGARAC_STATE_IDLE, 0, o->instance, 0, 0, 0};
    s->input = malloc(MEDIA_LIMIT); s->output = malloc(MEDIA_LIMIT);
    s->source = *o->source;
    bc_megarac_cd_source counted = {sizeof(counted), s, s->source.size, read_source};
    bc_status status = s->input && s->output ? bc_megarac_cd_create(&counted, &s->cd) : BC_NO_MEMORY;
    if (status == BC_OK) status = bc_megarac_media_auth(o->token, (uint8_t)o->instance, s->auth, sizeof(s->auth), &s->auth_length);
    if (status != BC_OK) { bc_megarac_media_service_destroy(s); return status; }
    *out = s; return BC_OK;
}
bc_status bc_megarac_media_service_start(bc_megarac_media_service *s) {
    if (!s) return BC_INVALID_ARGUMENT;
    if (s->info.state != BC_MEGARAC_STATE_IDLE) return BC_BUSY;
    s->started = s->last_time = s->io.clock_ms(s->io.userdata);
    s->info.state = BC_MEGARAC_STATE_AUTH;
    s->info.flags |= BC_MEGARAC_MEDIA_REMOVAL_UNCONFIRMED;
    bc_status status = s->io.send(s->io.userdata, s->auth, s->auth_length);
    volatile uint8_t *p = s->auth; for (size_t i = 0; i < sizeof(s->auth); ++i) p[i] = 0;
    return status == BC_OK ? status : fail(s, status);
}
static bc_status budget(bc_megarac_media_service *s, uint32_t *timeout) {
    uint64_t now = s->io.clock_ms(s->io.userdata);
    if (now < s->last_time) return fail(s, BC_INVALID_ARGUMENT);
    s->last_time = now;
    if (s->info.state == BC_MEGARAC_STATE_AUTH) {
        uint64_t elapsed = now - s->started;
        if (elapsed >= s->timeout) return fail(s, BC_TIMEOUT);
        if (*timeout > s->timeout - elapsed) *timeout = (uint32_t)(s->timeout - elapsed);
    }
    return BC_OK;
}
bc_status bc_megarac_media_service_poll(bc_megarac_media_service *s, uint32_t timeout) {
    if (!s) return BC_INVALID_ARGUMENT;
    if (s->info.state != BC_MEGARAC_STATE_AUTH && s->info.state != BC_MEGARAC_STATE_STREAMING) return BC_BUSY;
    bc_status status = budget(s, &timeout);
    if (status != BC_OK) return status;
    uint32_t target = 32;
    if (s->received >= 32) {
        if (memcmp(s->input, "IUSB    ", 8)) return fail(s, BC_PROTOCOL_ERROR);
        uint32_t payload = (uint32_t)bc_wire_read_le(s->input + 12, 4);
        if (payload > MEDIA_LIMIT - 32) return fail(s, BC_LIMIT_EXCEEDED);
        target += payload;
    }
    if (s->received < target) {
        uint32_t count = 0;
        status = s->io.recv(s->io.userdata, s->input + s->received, target - s->received, &count, timeout);
        bc_status elapsed = budget(s, &timeout);
        if (elapsed != BC_OK) return elapsed;
        if (status == BC_TIMEOUT) return status;
        if (status != BC_OK) return fail(s, status);
        if (!count || count > target - s->received) return fail(s, BC_PROTOCOL_ERROR);
        if (s->prefix) {
            s->prefix = 0;
            if (!s->input[0]) { memmove(s->input, s->input + 1, count - 1); --count; }
        }
        s->received += count;
        return BC_OK;
    }
    bc_service_profile profile; bc_megarac_media_packet packet;
    status = bc_megarac_media_discover(s->input, s->received, &profile, &s->failure);
    if (status != BC_OK) return fail(s, status);
    status = bc_megarac_media_packet_decode(s->input, s->received, &packet);
    if (status != BC_OK) return fail(s, status);
    ++s->info.packets;
    if (profile.evidence & BC_SERVICE_EVIDENCE_HANDSHAKE) {
        if ((s->info.flags & BC_MEGARAC_MEDIA_AUTHENTICATED) && packet.instance != s->info.instance)
            return fail(s, BC_PROTOCOL_ERROR);
        s->info.instance = packet.instance; s->profile = profile;
        s->info.flags |= BC_MEGARAC_MEDIA_AUTHENTICATED;
        s->info.state = BC_MEGARAC_STATE_STREAMING;
    } else {
        if (!(s->info.flags & BC_MEGARAC_MEDIA_AUTHENTICATED)) return fail(s, BC_PROTOCOL_ERROR);
        /* Legacy requests omit the instance; versioned requests must belong to this session. */
        if (!(packet.flags & (BC_MEGARAC_MEDIA_LEGACY_CONTROL | BC_MEGARAC_MEDIA_LEGACY_SCSI)) &&
            packet.instance != s->info.instance) return fail(s, BC_PROTOCOL_ERROR);
        uint32_t written = 0;
        status = bc_megarac_cd_handle(s->cd, s->input, s->received, s->output, MEDIA_LIMIT, &written);
        if (status == BC_OK && written) status = s->io.send(s->io.userdata, s->output, written);
        if (status != BC_OK) return fail(s, status);
        ++s->info.requests;
        if (written >= 61) s->info.bytes += bc_wire_read_le(s->output + 57, 4);
    }
    s->received = 0;
    return BC_OK;
}
bc_status bc_megarac_media_service_close(bc_megarac_media_service *s) {
    if (!s) return BC_INVALID_ARGUMENT;
    if (s->closed) return s->close_status;
    s->closed = 1;
    bc_status status = BC_OK;
    if ((s->info.flags & BC_MEGARAC_MEDIA_AUTHENTICATED) && (s->flags & BC_MEGARAC_MEDIA_SEND_DISCONNECT)) {
        uint32_t n = 0;
        status = bc_megarac_media_disconnect((uint8_t)s->info.instance, s->output, MEDIA_LIMIT, &n);
        if (status == BC_OK) status = s->io.send(s->io.userdata, s->output, n);
    }
    s->close_status = status;
    if (status != BC_OK) return fail(s, status);
    s->info.state = BC_MEGARAC_STATE_CLOSED; return BC_OK;
}
bc_status bc_megarac_media_service_info_get(const bc_megarac_media_service *s, bc_megarac_media_service_info *out) {
    if (!s || !out) return BC_INVALID_ARGUMENT;
    *out = s->info; return BC_OK;
}
const bc_service_profile *bc_megarac_media_service_profile_get(const bc_megarac_media_service *s) { return s ? &s->profile : NULL; }
const bc_console_failure *bc_megarac_media_service_failure_get(const bc_megarac_media_service *s) { return s ? &s->failure : NULL; }
void bc_megarac_media_service_destroy(bc_megarac_media_service *s) {
    if (!s) return;
    bc_megarac_cd_destroy(s->cd); free(s->input); free(s->output);
    volatile uint8_t *p = (uint8_t *)s; for (size_t i = 0; i < sizeof(*s); ++i) p[i] = 0;
    free(s);
}

static bc_status media_session_poll(void *context, uint32_t timeout) {
    bc_megarac_media_service *media = context;
    bc_status status = bc_megarac_media_service_poll(media, timeout);
    return status == BC_TIMEOUT && media->info.state != BC_MEGARAC_STATE_ERROR ? BC_OK : status;
}
static bc_status media_session_control(void *context, uint32_t command) {
    if (command == BC_MEDIA_CONTROL_START) return bc_megarac_media_service_start(context);
    return command == BC_MEDIA_CONTROL_KEEPALIVE ? BC_UNSUPPORTED : bc_megarac_media_service_close(context);
}
static bc_status media_session_info(const void *context, bc_media_session_info *out) {
    const bc_megarac_media_service *media = context;
    bc_megarac_cd_info cd = {0}; cd.struct_size = sizeof(cd);
    bc_status status = bc_megarac_cd_info_get(media->cd, &cd);
    if (status != BC_OK) return status;
    if (media->info.state == BC_MEGARAC_STATE_STREAMING) {
        out->flags = BC_MEDIA_CONNECTED;
        if (cd.flags & BC_MEGARAC_CD_PRESENT) out->flags |= BC_MEDIA_SOURCE_ATTACHED;
    }
    out->state = media->info.state;
    out->packets = media->info.packets; out->requests = media->info.requests;
    out->bytes_served = media->info.bytes;
    out->bytes_read = media->bytes_read;
    out->flags |= BC_MEDIA_BYTES_READ_VALID;
    out->status = media->failure.status;
    if (media->info.flags & BC_MEGARAC_MEDIA_AUTHENTICATED) out->flags |= BC_MEDIA_READY;
    if (media->info.flags & BC_MEGARAC_MEDIA_REMOVAL_UNCONFIRMED) out->flags |= BC_MEDIA_REMOVAL_UNCONFIRMED;
    if (media->info.state == BC_MEGARAC_STATE_ERROR) out->flags |= BC_MEDIA_FAILED;
    return BC_OK;
}
static void media_destroy(void *context) { bc_megarac_media_service_destroy(context); }
static const bc_service_profile *media_profile(const void *context) { return bc_megarac_media_service_profile_get(context); }
static const bc_console_failure *media_failure(const void *context) { return bc_megarac_media_service_failure_get(context); }
bc_status bc_megarac_media_wrap(bc_megarac_media_service *media, bc_media_session **out) {
    const bc_media_provider provider = {sizeof(provider), NULL, media_session_poll, media_session_control, media_session_info, NULL, media_destroy, media_profile, media_failure};
    return bc_media_session_wrap(&provider, media, out);
}

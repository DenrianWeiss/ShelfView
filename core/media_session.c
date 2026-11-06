#include "bcontrol/media_provider.h"
#include <stdlib.h>
#include "bcontrol/media_output_provider.h"
struct bc_media_session { bc_media_provider provider; void *context; int owned, observed; uint64_t heartbeat; int clock_started; bc_media_output *output; };
bc_status bc_media_session_wrap(const bc_media_provider *p, void *context, bc_media_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!p || p->struct_size != sizeof(*p) || !context || !p->control || !p->info) return BC_INVALID_ARGUMENT;
    bc_media_session *s = malloc(sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    *s = (bc_media_session){.provider = *p, .context = context}; *out = s;
    return BC_OK;
}
bc_status bc_media_session_feed(bc_media_session *s, bc_bytes bytes) {
    if (!s || (bytes.length && !bytes.data) || bytes.length > UINT32_MAX) return BC_INVALID_ARGUMENT;
    return s->provider.feed ? s->provider.feed(s->context, bytes) : BC_UNSUPPORTED;
}
bc_status bc_media_session_poll(bc_media_session *s, uint32_t timeout) {
    if (!s) return BC_INVALID_ARGUMENT;
    return s->provider.poll ? s->provider.poll(s->context, timeout) : BC_UNSUPPORTED;
}
bc_status bc_media_session_control(bc_media_session *s, uint32_t command) {
    if (!s) return BC_INVALID_ARGUMENT;
    if (command < BC_MEDIA_CONTROL_EJECT || command > BC_MEDIA_CONTROL_START) return BC_UNSUPPORTED;
    return s->provider.control(s->context, command);
}
bc_status bc_media_session_info_get(const bc_media_session *s, bc_media_session_info *info) {
    if (!s || !info || info->struct_size != sizeof(*info)) return BC_INVALID_ARGUMENT;
    bc_media_session_info value = {0}; value.struct_size = sizeof(value);
    bc_status status = s->provider.info(s->context, &value);
    if (status == BC_OK) {
        if (s->observed > 0) value.flags |= BC_MEDIA_MOUNT_CONFIRMED;
        if (s->observed < 0) {
            value.flags &= ~(BC_MEDIA_MOUNT_CONFIRMED | BC_MEDIA_REMOVAL_UNCONFIRMED);
            value.flags |= BC_MEDIA_REMOVAL_CONFIRMED;
        }
        *info = value;
    }
    return status;
}
bc_status bc_media_session_attach(bc_media_session *s, const bc_media_source *source) {
    if (!s || !source || source->struct_size != sizeof(*source) || !source->read) return BC_INVALID_ARGUMENT;
    if (!s->provider.attach) return BC_UNSUPPORTED;
    s->observed = 0;
    return s->provider.attach(s->context, source);
}
bc_status bc_media_session_observe_mount(bc_media_session *s, int inserted) {
    if (!s || (inserted != 0 && inserted != 1)) return BC_INVALID_ARGUMENT;
    s->observed = inserted ? 1 : -1;
    return BC_OK;
}
bc_status bc_media_session_tick(bc_media_session *s, uint64_t now) {
    bc_media_session_info info = {0}; info.struct_size = sizeof(info);
    bc_status status = bc_media_session_info_get(s, &info);
    if (status != BC_OK) return status;
    if (!info.heartbeat_interval_ms || !(info.flags & BC_MEDIA_CONNECTED)) return BC_OK;
    if (!s->clock_started || now < s->heartbeat) {
        s->heartbeat = now; s->clock_started = 1; return BC_OK;
    }
    if (now - s->heartbeat < info.heartbeat_interval_ms) return BC_OK;
    status = bc_media_session_control(s, BC_MEDIA_CONTROL_KEEPALIVE);
    if (status == BC_OK) s->heartbeat = now;
    return status;
}
const bc_service_profile *bc_media_session_profile_get(const bc_media_session *s) {
    return s && s->provider.profile ? s->provider.profile(s->context) : NULL;
}
const bc_console_failure *bc_media_session_failure_get(const bc_media_session *s) {
    return s && s->provider.failure ? s->provider.failure(s->context) : NULL;
}
void bc_media_session_bind_output(bc_media_session *s, bc_media_output *out) { s->output = out; }
bc_status bc_media_session_output(bc_media_session *s, uint8_t *bytes, uint32_t capacity, uint32_t *written) {
    if (!s || !written) return BC_INVALID_ARGUMENT;
    *written = 0;
    return s->output ? bc_media_output_take(s->output, bytes, capacity, written) : BC_UNSUPPORTED;
}
void bc_media_session_own(bc_media_session *s) { if (s) s->owned = 1; }
void bc_media_session_destroy(bc_media_session *s) {
    if (!s) return;
    if (s->owned && s->provider.destroy) s->provider.destroy(s->context);
    bc_media_output_destroy(s->output);
    free(s);
}

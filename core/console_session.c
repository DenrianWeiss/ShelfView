#include "bcontrol/console_provider.h"
#include <stdlib.h>
#include <string.h>
struct bc_console_session { bc_console_provider provider; void *context; };
bc_status bc_console_session_wrap(const bc_console_provider *p, void *context, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!p || p->struct_size != sizeof(*p) || !context || !p->input ||
        (p->display_modes && !p->ack_display) || (p->display_modes & ~(BC_DISPLAY_TILE | BC_DISPLAY_MEDIA_STREAM)) ||
        (p->input_capabilities & ~BC_CONSOLE_INPUT_HAS_SCROLL) ||
        ((p->display_modes & BC_DISPLAY_TILE) && !p->tile) ||
        ((p->display_modes & BC_DISPLAY_MEDIA_STREAM) && !p->media)) return BC_INVALID_ARGUMENT;
    if ((p->controls & ~(BC_CONSOLE_CONTROL_REFRESH | BC_CONSOLE_CONTROL_HEARTBEAT |
        BC_CONSOLE_CONTROL_QUERY_INPUT_STATE | BC_CONSOLE_CONTROL_CLOSE | BC_CONSOLE_CONTROL_START |
        BC_CONSOLE_CONTROL_MEDIA_ENABLE | BC_CONSOLE_CONTROL_MEDIA_DISABLE |
        BC_CONSOLE_CONTROL_SOURCE_ATTACH | BC_CONSOLE_CONTROL_SOURCE_DETACH)) ||
        (p->controls && !p->control)) return BC_INVALID_ARGUMENT;
    bc_console_session *session = malloc(sizeof(*session));
    if (!session) return BC_NO_MEMORY;
    *session = (bc_console_session){*p, context}; *out = session; return BC_OK;
}
bc_status bc_console_session_input(bc_console_session *s, const bc_console_input *event) {
    if (!s || !event || event->struct_size != sizeof(*event)) return BC_INVALID_ARGUMENT;
    if (event->type == BC_CONSOLE_INPUT_KEY) {
        if (event->down > 1) return BC_INVALID_ARGUMENT;
    } else if (event->type == BC_CONSOLE_INPUT_POINTER || event->type == BC_CONSOLE_INPUT_SCROLL) {
        if ((event->buttons & ~7u) || !event->width || !event->height || event->width > 65536 ||
            event->height > 65536 || event->x >= event->width || event->y >= event->height ||
            event->wheel < -127 || event->wheel > 127) return BC_INVALID_ARGUMENT;
        if (event->type == BC_CONSOLE_INPUT_SCROLL && !(s->provider.input_capabilities & BC_CONSOLE_INPUT_HAS_SCROLL))
            return BC_UNSUPPORTED;
        if (event->type == BC_CONSOLE_INPUT_POINTER && event->wheel) return BC_INVALID_ARGUMENT;
    } else return BC_UNSUPPORTED;
    return s->provider.input(s->context, event);
}
bc_status bc_console_session_chord(bc_console_session *s, const uint32_t *keys, uint32_t count) {
    if (!s || !keys || !count || count > 8) return BC_INVALID_ARGUMENT;
    bc_console_input event = {0}; event.struct_size = sizeof(event); event.type = BC_CONSOLE_INPUT_KEY;
    bc_status status = BC_OK; uint32_t pressed = 0;
    while (pressed < count) {
        event.down = 1; event.keysym = keys[pressed++];
        status = bc_console_session_input(s, &event);
        if (status != BC_OK) break;
    }
    while (pressed) {
        event.down = 0; event.keysym = keys[--pressed];
        bc_status released = bc_console_session_input(s, &event);
        if (status == BC_OK) status = released;
    }
    return status;
}
uint32_t bc_console_session_input_capabilities(const bc_console_session *s) { return s ? s->provider.input_capabilities : 0; }
uint32_t bc_console_session_display_modes(const bc_console_session *s) { return s ? s->provider.display_modes : 0; }
bc_status bc_console_session_tile(bc_console_session *s, bc_display_tile *tile) {
    if (!s || !tile || tile->struct_size != sizeof(*tile)) return BC_INVALID_ARGUMENT;
    if (!(s->provider.display_modes & BC_DISPLAY_TILE)) return BC_UNSUPPORTED;
    bc_status status = s->provider.tile(s->context, tile);
    return status == BC_OK ? bc_display_tile_validate(tile) : status;
}
bc_status bc_console_session_media(bc_console_session *s, bc_display_stream_packet *packet) {
    if (!s || !packet || packet->struct_size != sizeof(*packet)) return BC_INVALID_ARGUMENT;
    return s->provider.display_modes & BC_DISPLAY_MEDIA_STREAM ? s->provider.media(s->context, packet) : BC_UNSUPPORTED;
}
void bc_console_session_ack_display(bc_console_session *s) { if (s && s->provider.ack_display) s->provider.ack_display(s->context); }
void bc_console_session_destroy(bc_console_session *s) {
    if (!s) return;
    if (s->provider.destroy) s->provider.destroy(s->context);
    free(s);
}

bc_status bc_console_session_feed(bc_console_session *s, uint32_t channel, const uint8_t *data, uint32_t length) {
    if (!s || (!data && length)) return BC_INVALID_ARGUMENT;
    return s->provider.feed ? s->provider.feed(s->context, channel, data, length) : BC_UNSUPPORTED;
}
bc_status bc_console_session_output(bc_console_session *s, uint32_t channel, uint8_t *data, uint32_t capacity, uint32_t *written) {
    if (!written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (!s || (!data && capacity)) return BC_INVALID_ARGUMENT;
    return s->provider.output ? s->provider.output(s->context, channel, data, capacity, written) : BC_UNSUPPORTED;
}

uint32_t bc_console_session_controls(const bc_console_session *s) { return s ? s->provider.controls : 0; }
bc_status bc_console_session_control(bc_console_session *s, uint32_t control) {
    if (!s || !control || (control & (control - 1))) return BC_INVALID_ARGUMENT;
    if (!(s->provider.controls & control)) return BC_UNSUPPORTED;
    return s->provider.control(s->context, control);
}

bc_status bc_console_session_info_get(const bc_console_session *s, bc_console_info *out) {
    if (!s || !out || out->struct_size != sizeof(*out)) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out);
    return s->provider.info ? s->provider.info(s->context, out) : BC_UNSUPPORTED;
}

bc_status bc_console_session_feed_some(bc_console_session *s, uint32_t channel, const uint8_t *data,
    uint32_t length, uint32_t *consumed) {
    if (!consumed) return BC_INVALID_ARGUMENT;
    *consumed = 0;
    if (!s || (!data && length)) return BC_INVALID_ARGUMENT;
    if (s->provider.feed_some) return s->provider.feed_some(s->context, channel, data, length, consumed);
    bc_status status = bc_console_session_feed(s, channel, data, length);
    if (status == BC_OK) *consumed = length;
    return status;
}

bc_status bc_console_session_name(const bc_console_session *s, uint8_t *data, uint32_t capacity, uint32_t *written) {
    if (!written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (!s || (!data && capacity)) return BC_INVALID_ARGUMENT;
    if (!s->provider.name) return BC_UNSUPPORTED;
    bc_string name = s->provider.name(s->context);
    if (name.length > UINT32_MAX || (!name.data && name.length)) return BC_LIMIT_EXCEEDED;
    *written = (uint32_t)name.length;
    if (name.length > capacity) return BC_LIMIT_EXCEEDED;
    if (name.length) memcpy(data, name.data, (size_t)name.length);
    return BC_OK;
}

bc_status bc_console_session_poll(bc_console_session *s, uint32_t timeout_ms) {
    if (!s) return BC_INVALID_ARGUMENT;
    return s->provider.poll ? s->provider.poll(s->context, timeout_ms) : BC_UNSUPPORTED;
}
bc_status bc_console_session_tick(bc_console_session *s, uint64_t now_ms) {
    if (!s) return BC_INVALID_ARGUMENT;
    return s->provider.tick ? s->provider.tick(s->context, now_ms) : BC_UNSUPPORTED;
}

bc_status bc_console_session_statistics_get(const bc_console_session *s, bc_console_statistics *out) {
    if (!s || !out || out->struct_size != sizeof(*out)) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out);
    return s->provider.statistics ? s->provider.statistics(s->context, out) : BC_UNSUPPORTED;
}

bc_status bc_console_session_media_offer(const bc_console_session *s, bc_media_offer **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!s) return BC_INVALID_ARGUMENT;
    return s->provider.media_offer ? s->provider.media_offer(s->context, out) : BC_UNSUPPORTED;
}

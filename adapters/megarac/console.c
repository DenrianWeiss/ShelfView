#include "megarac.h"
#include "bcontrol/megarac_session.h"
#include "bcontrol/console_provider.h"
#include "bcontrol/keyboard.h"
#include <stdlib.h>
#include "bcontrol/decode_provider.h"
#include "../../core/log_internal.h"
#include <string.h>
typedef struct {
    bc_megarac_session *protocol;
    bc_kvm_frame *frame, owned_frame;
    uint32_t pressed[32];
    bc_megarac_video *ast;
    bc_megarac_soc_video *soc;
    uint8_t *pixels, *compressed;
    uint32_t capacity;
    uint64_t queued_cursor_revision;
    int jviewer_cursor_blend;
    bc_megarac_cursor cursor;
    struct {
        uint32_t x, y, width, height;
        uint8_t pixels[BC_MEGARAC_CURSOR_SIDE * BC_MEGARAC_CURSOR_SIDE * 4];
    } cursor_background;
    bc_decode_submit submit;
    void *submit_user;
} megarac_console;
typedef struct {
    megarac_console *console;
    bc_megarac_video_header header;
    int cursor_changed;
} video_job;

static void restore_cursor_background(megarac_console *s) {
    uint32_t width = s->cursor_background.width;
    if (!width) return;
    for (uint32_t row = 0; row < s->cursor_background.height; ++row) {
        size_t offset = (size_t)(s->cursor_background.y + row) * s->frame->stride + s->cursor_background.x * 4;
        memcpy(s->pixels + offset, s->cursor_background.pixels + row * width * 4, width * 4);
    }
    s->cursor_background.width = 0;
}

static uint8_t blend_cursor_channel(int background, int color, int alpha, int jviewer) {
    if (jviewer) {
        /* JViewer divides each signed Java byte contribution before adding. */
        if (background >= 128) background -= 256;
        if (color >= 128) color -= 256;
        return (uint8_t)(((15 - alpha) * background) / 15 + (alpha * color) / 15);
    }
    return (uint8_t)(((15 - alpha) * background + alpha * color + 7) / 15);
}

static void draw_cursor(megarac_console *s) {
    const bc_megarac_cursor *cursor = &s->cursor;
    const uint32_t side = BC_MEGARAC_CURSOR_SIDE;
    if (!cursor->visible || cursor->x_offset >= side || cursor->y_offset >= side ||
        cursor->x >= s->frame->width || cursor->y >= s->frame->height) return;
    uint32_t width = s->frame->width - cursor->x, height = s->frame->height - cursor->y;
    if (width > side - cursor->x_offset) width = side - cursor->x_offset;
    if (height > side - cursor->y_offset) height = side - cursor->y_offset;
    s->cursor_background.x = cursor->x;
    s->cursor_background.y = cursor->y;
    s->cursor_background.width = width;
    s->cursor_background.height = height;
    for (uint32_t row = 0; row < height; ++row) {
        uint8_t *pixel = s->pixels + (size_t)(cursor->y + row) * s->frame->stride + cursor->x * 4;
        const uint16_t *pattern = cursor->pattern + (cursor->y_offset + row) * side + cursor->x_offset;
        memcpy(s->cursor_background.pixels + row * width * 4, pixel, width * 4);
        for (uint32_t col = 0; col < width; ++col, pixel += 4) {
            uint16_t value = pattern[col];
            if (!cursor->color && (value & 0x8000)) {
                if (value & 0x4000) for (unsigned c = 0; c < 3; ++c) pixel[c] ^= 255;
                continue;
            }
            int alpha = cursor->color ? value >> 12 : 15;
            for (unsigned c = 0; c < 3; ++c) {
                int color = ((value >> (4 * (2 - c))) & 15) << 4;
                pixel[c] = blend_cursor_channel(pixel[c], color, alpha, s->jviewer_cursor_blend);
            }
        }
    }
}

static bc_status decode_video(video_job *job, const uint8_t *bytes, uint32_t length) {
    megarac_console *s = job->console;
    uint32_t width = job->header.width, height = job->header.height;
    bc_status status;
    if (job->header.flags & BC_MEGARAC_VIDEO_SOC) {
        status = bc_megarac_soc_frame_size(bytes, length, &width, &height);
        if (status != BC_OK) return status;
    }
    if (!width || !height || width > 4096 || height > 4096) return BC_LIMIT_EXCEEDED;
    uint32_t size = width * height * 4;
    if (size > s->capacity) {
        uint8_t *pixels = realloc(s->pixels, size);
        if (!pixels) return BC_NO_MEMORY;
        s->pixels = pixels; s->capacity = size;
        s->frame->pixels = pixels;
    }
    if (width != s->frame->width || height != s->frame->height) memset(s->pixels, 0, size);
    if (job->header.flags & BC_MEGARAC_VIDEO_SOC)
        status = bc_megarac_soc_video_decode(s->soc, bytes, length, s->pixels, s->capacity, &width, &height);
    else
        status = bc_megarac_video_decode_payload(s->ast, &job->header, bytes, length, s->pixels, s->capacity, &width, &height);
    if (status != BC_OK) {
        BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "megarac.video.rejected", "width=%u height=%u bytes=%u flags=%u jpeg=%u status=%s",
            width, height, length, job->header.flags, length >= 2 && bytes[0] == 0xff && bytes[1] == 0xd8,
            bc_status_string(status));
        return status;
    }
    if (!s->frame->width)
        BC_LOG_INFO(BC_LOG_CATEGORY_KVM, "megarac.video.first_frame", "width=%u height=%u bytes=%u", width, height, length);
    s->frame->width = width; s->frame->height = height; s->frame->stride = width * 4;
    return BC_OK;
}

static bc_status decode(void *user, const uint8_t *bytes, uint32_t length) {
    video_job *job = user;
    megarac_console *s = job->console;
    restore_cursor_background(s);
    if (job->cursor_changed) memcpy(&s->cursor, job + 1, sizeof(s->cursor));
    bc_status status = length ? decode_video(job, bytes, length) : BC_OK;
    if (status == BC_OK && s->frame->width) {
        draw_cursor(s);
        s->frame->flags = BC_KVM_FRAME_READY | BC_KVM_READY;
    }
    return status;
}

static bc_status submit_frame(megarac_console *s) {
    const bc_megarac_video_header *header = bc_megarac_session_frame(s->protocol);
    const bc_megarac_cursor *cursor = bc_megarac_session_cursor(s->protocol);
    int cursor_changed = cursor->revision != s->queued_cursor_revision;
    if (!header && !cursor_changed) return BC_OK;
    video_job *context = malloc(sizeof(*context) + (cursor_changed ? sizeof(*cursor) : 0));
    if (!context) return BC_NO_MEMORY;
    *context = (video_job){s, {0}, cursor_changed};
    if (header) context->header = *header;
    if (cursor_changed) memcpy(context + 1, cursor, sizeof(*cursor));
    bc_decode_job *job = NULL;
    bc_status status = bc_decode_job_create(bc_megarac_session_pixels(s->protocol), context->header.compressed_size,
        decode, free, context, &job);
    if (status != BC_OK) free(context);
    else {
        status = s->submit(s->submit_user, job);
        if (status != BC_OK) bc_decode_job_destroy(job);
        else s->queued_cursor_revision = cursor->revision;
    }
    if (header) bc_megarac_session_ack_frame(s->protocol);
    return status;
}
static void destroy(void *user) {
    megarac_console *s = user;
    bc_megarac_video_destroy(s->ast); bc_megarac_soc_video_destroy(s->soc);
    if (s->compressed) { bc_megarac_session_destroy(s->protocol); free(s->compressed); }
    free(s->pixels); free(s);
}
static uint16_t scale(uint32_t pixel, uint32_t extent) { return extent <= 1 ? 0 : (uint16_t)(pixel * 32767 / (extent - 1)); }
static bc_status input(void *user, const bc_console_input *event) {
    megarac_console *s = user;
    if (event->type == BC_CONSOLE_INPUT_KEY) {
        if (!event->keysym && !event->down) {
            memset(s->pressed, 0, sizeof(s->pressed));
            return bc_megarac_session_keyboard_release(s->protocol);
        }
        uint8_t report[8];
        bc_status status = bc_keyboard_report(s->pressed, event->keysym, (int)event->down, report);
        return status == BC_OK ? bc_megarac_session_keyboard(s->protocol, report[0], report + 2) : status;
    }
    if (event->type == BC_CONSOLE_INPUT_SCROLL && !event->wheel) return BC_OK;
    return bc_megarac_session_mouse(s->protocol, (uint8_t)event->buttons,
        scale(event->x, event->width), scale(event->y, event->height), (int8_t)event->wheel);
}
static uint32_t media_controls(const megarac_console *s) {
    if (bc_megarac_session_is_irmc(s->protocol))
        return BC_CONSOLE_CONTROL_SOURCE_ATTACH | BC_CONSOLE_CONTROL_SOURCE_DETACH;
    const bc_service_profile *profile = bc_megarac_session_profile_get(s->protocol);
    if (!profile || (profile->variant != BC_SERVICE_MEGARAC_KVM_JVIEWER_195 &&
        profile->variant != BC_SERVICE_MEGARAC_KVM_H5_438 && profile->variant != BC_SERVICE_MEGARAC_KVM_H5_373)) return 0;
    return BC_CONSOLE_CONTROL_MEDIA_ENABLE | BC_CONSOLE_CONTROL_MEDIA_DISABLE |
        BC_CONSOLE_CONTROL_SOURCE_ATTACH | BC_CONSOLE_CONTROL_SOURCE_DETACH;
}
static bc_status control(void *user, uint32_t operation) {
    switch (operation) {
    case BC_CONSOLE_CONTROL_MEDIA_ENABLE: return bc_megarac_session_media_mode(((megarac_console *)user)->protocol, 1);
    case BC_CONSOLE_CONTROL_MEDIA_DISABLE: return bc_megarac_session_media_mode(((megarac_console *)user)->protocol, 0);
    case BC_CONSOLE_CONTROL_SOURCE_ATTACH: return bc_megarac_session_media_state(((megarac_console *)user)->protocol, 1);
    case BC_CONSOLE_CONTROL_SOURCE_DETACH: return bc_megarac_session_media_state(((megarac_console *)user)->protocol, 0);
    case BC_CONSOLE_CONTROL_START: return bc_megarac_session_start(((megarac_console *)user)->protocol);
    case BC_CONSOLE_CONTROL_HEARTBEAT: return bc_megarac_session_keepalive(((megarac_console *)user)->protocol);
    case BC_CONSOLE_CONTROL_CLOSE: return bc_megarac_session_close(((megarac_console *)user)->protocol);
    default: return BC_UNSUPPORTED;
    }
}
static bc_status info(void *user, bc_console_info *out) {
    megarac_console *s = user;
    uint32_t state = bc_megarac_session_state(s->protocol);
    out->tick_interval_ms = (bc_megarac_session_flags(s->protocol) & BC_MEGARAC_KEYBOARD_AUTOBREAK) ? 25 : 0;
    out->flags = BC_CONSOLE_INFO_READY_KNOWN | ((state == BC_MEGARAC_STATE_STREAMING) ? BC_CONSOLE_INFO_READY : 0);
    if (state == BC_MEGARAC_STATE_CLOSED) out->flags |= BC_CONSOLE_INFO_CLOSED;
    if (state == BC_MEGARAC_STATE_ERROR) out->flags |= BC_CONSOLE_INFO_FAILED;
    const bc_service_profile *profile = bc_megarac_session_profile_get(s->protocol);
    if (profile) { out->profile = *profile; out->flags |= BC_CONSOLE_INFO_PROFILE_VALID; }
    if (media_controls(s)) {
        out->flags |= BC_CONSOLE_INFO_MEDIA_STATE_VALID | bc_megarac_session_media_flags(s->protocol);
        if (bc_megarac_session_media_removal_unconfirmed(s->protocol))
            out->flags |= BC_CONSOLE_INFO_MEDIA_REMOVAL_UNCONFIRMED;
    }
    const bc_console_failure *failure = bc_megarac_session_failure_get(s->protocol);
    if (failure) { out->failure = *failure; out->flags |= BC_CONSOLE_INFO_FAILURE_VALID; }
    return BC_OK;
}
static bc_status feed_some(void *user, uint32_t channel, const uint8_t *data, uint32_t length, uint32_t *consumed) {
    if (channel) return BC_INVALID_ARGUMENT;
    megarac_console *s = user;
    bc_status status = bc_megarac_session_feed_frame(s->protocol, data, length, consumed);
    return status == BC_OK && s->submit ? submit_frame(s) : status;
}
static bc_status output(void *user, uint32_t channel, uint8_t *data, uint32_t capacity, uint32_t *written) {
    if (channel) return BC_INVALID_ARGUMENT;
    return bc_megarac_session_output(((megarac_console *)user)->protocol, data, capacity, written);
}
static bc_status tick(void *user, uint64_t now_ms) {
    return bc_megarac_session_tick(((megarac_console *)user)->protocol, now_ms);
}
static bc_status media_offer(void *user, bc_media_offer **out) {
    return bc_megarac_session_media_offer(((megarac_console *)user)->protocol, out);
}
static bc_status tile(void *user, bc_display_tile *out) {
    return bc_display_tile_from_frame(((megarac_console *)user)->frame, out);
}
static void ack(void *user) { ((megarac_console *)user)->frame->flags &= ~BC_KVM_FRAME_READY; }
static uint32_t protocol_controls(bc_megarac_session *protocol) {
    uint32_t controls = BC_CONSOLE_CONTROL_START | BC_CONSOLE_CONTROL_CLOSE;
    if (bc_megarac_session_profile_get(protocol)->variant != BC_SERVICE_MEGARAC_KVM_JVIEWER_195 ||
        bc_megarac_session_is_irmc(protocol)) controls |= BC_CONSOLE_CONTROL_HEARTBEAT;
    return controls;
}
bc_status bc_megarac_console_wrap(bc_megarac_session *protocol, bc_kvm_frame *frame, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!protocol || !frame || frame->struct_size != sizeof(*frame)) return BC_INVALID_ARGUMENT;
    megarac_console *s = calloc(1, sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    s->protocol = protocol; s->frame = frame;
    bc_console_provider provider = {sizeof(provider), BC_DISPLAY_TILE, BC_CONSOLE_INPUT_HAS_SCROLL,
        input, tile, NULL, ack, destroy, NULL, output, protocol_controls(protocol), control, info, feed_some, NULL, NULL, tick, NULL, media_offer};
    provider.controls |= media_controls(s);
    bc_status status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) free(s);
    return status;
}

static bc_status video_wrap(bc_megarac_session *protocol, bc_decode_submit submit, void *user, uint8_t *compressed, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!protocol || !submit) return BC_INVALID_ARGUMENT;
    megarac_console *s = calloc(1, sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    s->protocol = protocol; s->frame = &s->owned_frame;
    s->owned_frame.struct_size = sizeof(s->owned_frame);
    s->jviewer_cursor_blend = bc_megarac_session_profile_get(protocol)->variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_373
        && !bc_megarac_session_is_irmc(protocol);
    s->submit = submit; s->submit_user = user;
    bc_status status = bc_megarac_video_create(&s->ast);
    if (status == BC_OK) status = bc_megarac_soc_video_create(&s->soc);
    if (status != BC_OK) { destroy(s); return status; }
    bc_console_provider provider = {sizeof(provider), BC_DISPLAY_TILE, BC_CONSOLE_INPUT_HAS_SCROLL,
        input, tile, NULL, ack, destroy, NULL, output,
        protocol_controls(protocol),
        control, info, feed_some, NULL, NULL, tick, NULL, media_offer};
    provider.controls |= media_controls(s);
    status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) destroy(s);
    else s->compressed = compressed;
    return status;
}

bc_status bc_megarac_console_video_wrap(bc_megarac_session *protocol, bc_decode_submit submit, void *user, bc_console_session **out) {
    return video_wrap(protocol, submit, user, NULL, out);
}
bc_status bc_megarac_console_create(const bc_megarac_session_options *options, uint32_t keyboard_mode,
    bc_decode_submit submit, void *user, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || !options->frame_capacity || !submit) return BC_INVALID_ARGUMENT;
    uint8_t *compressed = malloc(options->frame_capacity);
    if (!compressed) return BC_NO_MEMORY;
    bc_megarac_session_options owned = *options; owned.frame_buffer = compressed;
    bc_megarac_session *protocol = NULL;
    bc_status status = bc_megarac_session_create(&owned, &protocol);
    if (status == BC_OK) status = bc_megarac_session_keyboard_mode(protocol, keyboard_mode);
    if (status == BC_OK) status = video_wrap(protocol, submit, user, compressed, out);
    if (status != BC_OK) { bc_megarac_session_destroy(protocol); free(compressed); }
    return status;
}

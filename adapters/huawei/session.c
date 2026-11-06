#include "bcontrol/huawei_session.h"
#include "bcontrol/console_provider.h"
#include <stdlib.h>
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/decode_provider.h"
typedef struct {
    bc_huawei_kvm_session *protocol;
    bc_kvm_frame *frame;
    bc_kvm_frame owned_frame;
    bc_huawei_video_decoder *video;
    bc_decode_submit submit;
    void *submit_user;
    uint8_t *owned_pixels;
} huawei_console;
typedef struct { huawei_console *console; uint32_t width, height, quantization; } video_job;
static bc_status decode(void *user, const uint8_t *bytes, uint32_t length) {
    video_job *job = user;
    huawei_console *s = job->console;
    bc_status status = bc_huawei_video_decoder_draw(s->video, bytes, length, job->width, job->height, job->quantization);
    if (status != BC_OK) return status;
    s->frame->width = job->width; s->frame->height = job->height;
    s->frame->stride = job->width * 4;
    s->frame->flags = BC_KVM_FRAME_READY | BC_KVM_READY;
    return BC_OK;
}
static bc_status submit_video(void *user, const uint8_t *bytes, uint32_t length,
    uint32_t width, uint32_t height, uint32_t quantization, uint32_t sequence, uint32_t flags) {
    (void)sequence; (void)flags;
    huawei_console *s = user;
    video_job *context = malloc(sizeof(*context));
    if (!context) return BC_NO_MEMORY;
    *context = (video_job){s, width, height, quantization};
    bc_decode_job *job = NULL;
    bc_status status = bc_decode_job_create(bytes, length, decode, free, context, &job);
    if (status != BC_OK) { free(context); return status; }
    status = s->submit(s->submit_user, job);
    if (status != BC_OK) bc_decode_job_destroy(job);
    return status;
}
static void destroy(void *user) {
    huawei_console *s = user;
    if (s->owned_pixels) bc_huawei_kvm_session_destroy(s->protocol);
    bc_huawei_video_decoder_destroy(s->video);
    free(s->owned_pixels);
    free(s);
}
static bc_status input(void *user, const bc_console_input *event) {
    huawei_console *s = user;
    if (event->type == BC_CONSOLE_INPUT_KEY)
        return bc_huawei_kvm_session_key(s->protocol, event->keysym, event->down);
    return bc_huawei_kvm_session_pointer_device(s->protocol,
        (uint16_t)bc_huawei_kvm_pointer_scale(event->x, event->width),
        (uint16_t)bc_huawei_kvm_pointer_scale(event->y, event->height), (uint8_t)event->buttons);
}
static bc_status info(void *user, bc_console_info *out) {
    huawei_console *s = user;
    uint32_t state;
    bc_status status = bc_huawei_kvm_session_state(s->protocol, &state);
    if (status != BC_OK) return status;
    out->flags = BC_CONSOLE_INFO_READY_KNOWN | ((state == BC_HUAWEI_KVM_STATE_STREAMING) ? BC_CONSOLE_INFO_READY : 0);
    if (state == BC_HUAWEI_KVM_STATE_CLOSED) out->flags |= BC_CONSOLE_INFO_CLOSED;
    if (state == BC_HUAWEI_KVM_STATE_ERROR) out->flags |= BC_CONSOLE_INFO_FAILED;
    const bc_service_profile *profile = bc_huawei_kvm_session_profile_get(s->protocol);
    if (profile) { out->profile = *profile; out->flags |= BC_CONSOLE_INFO_PROFILE_VALID; }
    const bc_console_failure *failure = bc_huawei_kvm_session_failure_get(s->protocol);
    if (failure) { out->failure = *failure; out->flags |= BC_CONSOLE_INFO_FAILURE_VALID; }
    return BC_OK;
}
static bc_status media_offer(void *user, bc_media_offer **out) {
    bc_huawei_vmm_info info = {0}; info.struct_size = sizeof(info);
    bc_status status = bc_huawei_kvm_session_vmm_info(((huawei_console *)user)->protocol, &info);
    if (status != BC_OK) return status;
    status = bc_huawei_media_offer_create(&info, out);
    volatile unsigned char *bytes = (volatile unsigned char *)&info;
    for (size_t i = 0; i < sizeof(info); ++i) bytes[i] = 0;
    return status;
}
static bc_status statistics(void *user, bc_console_statistics *out) {
    bc_huawei_kvm_stats stats = {0}; stats.struct_size = sizeof(stats); stats.abi_version = BC_ABI_VERSION;
    bc_status status = bc_huawei_kvm_session_stats(((huawei_console *)user)->protocol, &stats);
    if (status != BC_OK) return status;
    out->received_bytes = stats.received_bytes; out->image_packets = stats.image_packets;
    out->heartbeats = stats.heartbeats; out->dropped_frames = stats.dropped_frames;
    return BC_OK;
}
static bc_status control(void *user, uint32_t operation) {
    huawei_console *s = user;
    switch (operation) {
    case BC_CONSOLE_CONTROL_START: return bc_huawei_kvm_session_start(s->protocol);
    case BC_CONSOLE_CONTROL_MEDIA_ENABLE: return bc_huawei_kvm_session_vmm_request(s->protocol);
    default: return BC_UNSUPPORTED;
    }
}
static bc_status poll(void *user, uint32_t timeout_ms) {
    return bc_huawei_kvm_session_poll(((huawei_console *)user)->protocol, timeout_ms);
}
static bc_status tile(void *user, bc_display_tile *out) {
    return bc_display_tile_from_frame(((huawei_console *)user)->frame, out);
}
static void ack(void *user) { ((huawei_console *)user)->frame->flags &= ~BC_KVM_FRAME_READY; }
bc_status bc_huawei_console_wrap(bc_huawei_kvm_session *protocol, bc_kvm_frame *frame, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!protocol || !frame || frame->struct_size != sizeof(*frame)) return BC_INVALID_ARGUMENT;
    huawei_console *s = calloc(1, sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    s->protocol = protocol; s->frame = frame;
    bc_console_provider provider = {sizeof(provider), BC_DISPLAY_TILE, 0, input, tile, NULL, ack, destroy, NULL, NULL, BC_CONSOLE_CONTROL_START | BC_CONSOLE_CONTROL_MEDIA_ENABLE, control, info, NULL, NULL, poll, NULL, statistics, media_offer};
    bc_status status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) free(s);
    return status;
}

static bc_status video_wrap(bc_huawei_kvm_session *protocol, uint8_t *pixels, uint32_t capacity,
    bc_decode_submit submit, void *user, int owned, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!protocol || !pixels || !capacity || !submit) return BC_INVALID_ARGUMENT;
    huawei_console *s = calloc(1, sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    s->protocol = protocol; s->frame = &s->owned_frame;
    s->owned_frame.struct_size = sizeof(s->owned_frame); s->owned_frame.pixels = pixels;
    s->submit = submit; s->submit_user = user;
    bc_status status = bc_huawei_video_decoder_create(pixels, capacity, &s->video);
    if (status != BC_OK) { destroy(s); return status; }
    bc_console_provider provider = {sizeof(provider), BC_DISPLAY_TILE, 0, input, tile, NULL, ack, destroy,
        NULL, NULL, BC_CONSOLE_CONTROL_START | BC_CONSOLE_CONTROL_MEDIA_ENABLE, control, info, NULL, NULL, poll, NULL, statistics, media_offer};
    status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) { destroy(s); return status; }
    status = bc_huawei_kvm_session_set_video_sink(protocol, submit_video, s);
    if (status != BC_OK) { bc_console_session_destroy(*out); *out = NULL; }
    else if (owned) s->owned_pixels = pixels;
    return status;
}

bc_status bc_huawei_media_create_offer(const bc_media_offer *offer, const bc_huawei_media_options *options,
    const bc_huawei_io *io, bc_huawei_media **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options)) return BC_INVALID_ARGUMENT;
    const bc_huawei_vmm_info *info = bc_media_offer_payload(offer, BC_MEDIA_OFFER_HUAWEI, sizeof(*info));
    if (!info) return BC_INVALID_ARGUMENT;
    bc_huawei_media_options bound = *options; bound.info = info;
    return bc_huawei_media_create(&bound, io, out);
}

bc_status bc_huawei_media_offer_create(const bc_huawei_vmm_info *info, bc_media_offer **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!info || info->struct_size != sizeof(*info)) return BC_INVALID_ARGUMENT;
    if (info->state != BC_HUAWEI_VMM_STATE_ENABLED || !info->port) return BC_BUSY;
    if (info->port > UINT16_MAX) return BC_INVALID_ARGUMENT;
    bc_media_offer_info metadata = {sizeof(metadata), BC_MEDIA_OFFER_READY, info->port};
    return bc_media_offer_create(BC_MEDIA_OFFER_HUAWEI, &metadata, info, sizeof(*info), out);
}

bc_status bc_huawei_console_video_wrap(bc_huawei_kvm_session *protocol, uint8_t *pixels, uint32_t capacity,
    bc_decode_submit submit, void *user, bc_console_session **out) {
    return video_wrap(protocol, pixels, capacity, submit, user, 0, out);
}
bc_status bc_huawei_console_create(const bc_huawei_kvm_params *params, const bc_huawei_io *io,
    const bc_huawei_kvm_options *options, bc_decode_submit submit, void *user, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || !options->frame_capacity || !submit) return BC_INVALID_ARGUMENT;
    uint8_t *pixels = malloc(options->frame_capacity);
    if (!pixels) return BC_NO_MEMORY;
    bc_huawei_kvm_options owned = *options; owned.frame_buffer = pixels;
    bc_huawei_kvm_session *protocol = NULL;
    bc_status status = bc_huawei_kvm_session_create(params, io, &owned, &protocol);
    if (status == BC_OK) status = video_wrap(protocol, pixels, options->frame_capacity, submit, user, 1, out);
    if (status != BC_OK) { bc_huawei_kvm_session_destroy(protocol); free(pixels); }
    return status;
}

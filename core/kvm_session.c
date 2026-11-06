#include "bcontrol/kvm_session.h"
#include "bcontrol/console_provider.h"
#include <stdlib.h>
typedef struct { bc_kvm *decoder; bc_console_emit emit; void *user; int owned; } rfb_session;
static bc_status pointer(rfb_session *s, const bc_console_input *event, uint8_t buttons) {
    uint8_t bytes[BC_KVM_POINTER_EVENT_SIZE];
    bc_status status = bc_kvm_pointer_encode(buttons, (uint16_t)event->x, (uint16_t)event->y,
        event->width, event->height, bytes, sizeof(bytes));
    return status == BC_OK ? s->emit(s->user, bytes, sizeof(bytes)) : status;
}
static bc_status input(void *user, const bc_console_input *event) {
    rfb_session *s = user;
    if (event->type == BC_CONSOLE_INPUT_KEY) {
        uint8_t bytes[BC_KVM_KEY_EVENT_SIZE];
        bc_status status = bc_kvm_key_encode((int)event->down, event->keysym, bytes, sizeof(bytes));
        return status == BC_OK ? s->emit(s->user, bytes, sizeof(bytes)) : status;
    }
    uint8_t buttons = (uint8_t)((event->buttons & 1) | ((event->buttons & 2) << 1) | ((event->buttons & 4) >> 1));
    if (event->type == BC_CONSOLE_INPUT_POINTER) return pointer(s, event, buttons);
    if (!event->wheel) return BC_OK;
    bc_status status = pointer(s, event, (uint8_t)(buttons | (event->wheel > 0 ? 8 : 16)));
    bc_status released = pointer(s, event, buttons);
    return status != BC_OK ? status : released;
}
static bc_status feed(void *user, uint32_t channel, const uint8_t *data, uint32_t length) {
    if (channel) return BC_INVALID_ARGUMENT;
    return bc_kvm_feed(((rfb_session *)user)->decoder, data, length);
}
static bc_status output(void *user, uint32_t channel, uint8_t *data, uint32_t capacity, uint32_t *written) {
    if (channel) return BC_INVALID_ARGUMENT;
    return bc_kvm_output(((rfb_session *)user)->decoder, data, capacity, written);
}
static bc_status control(void *user, uint32_t operation) {
    switch (operation) {
    case BC_CONSOLE_CONTROL_CLOSE: return bc_kvm_close(((rfb_session *)user)->decoder);
    default: return BC_UNSUPPORTED;
    }
}
static bc_status info(void *user, bc_console_info *out) {
    rfb_session *s = user;
    out->flags = BC_CONSOLE_INFO_READY_KNOWN | ((bc_kvm_handshake_complete(s->decoder)) ? BC_CONSOLE_INFO_READY : 0);
    return BC_OK;
}
static bc_string name(void *user) {
    const bc_kvm_frame *frame = bc_kvm_frame_get(((rfb_session *)user)->decoder);
    return frame ? frame->name : (bc_string){0};
}
static bc_status tile(void *user, bc_display_tile *out) {
    return bc_display_tile_from_frame(bc_kvm_frame_get(((rfb_session *)user)->decoder), out);
}
static void ack(void *user) { bc_kvm_ack_frame(((rfb_session *)user)->decoder); }
static void destroy(void *user) {
    rfb_session *s = user;
    if (s->owned) bc_kvm_destroy(s->decoder);
    free(s);
}
static bc_status wrap(bc_kvm *decoder, bc_console_emit emit, void *user, int owned, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!decoder || !emit) return BC_INVALID_ARGUMENT;
    rfb_session *s = malloc(sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    *s = (rfb_session){decoder, emit, user, owned};
    bc_console_provider provider = {sizeof(provider), BC_DISPLAY_TILE, BC_CONSOLE_INPUT_HAS_SCROLL,
        input, tile, NULL, ack, destroy, feed, output, BC_CONSOLE_CONTROL_CLOSE, control, info, NULL, name, NULL, NULL, NULL, NULL};
    bc_status status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) free(s);
    return status;
}
bc_status bc_kvm_input_wrap(bc_console_emit emit, void *user, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!emit) return BC_INVALID_ARGUMENT;
    rfb_session *s = malloc(sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    *s = (rfb_session){NULL, emit, user, 0};
    bc_console_provider provider = {sizeof(provider), 0, BC_CONSOLE_INPUT_HAS_SCROLL,
        input, NULL, NULL, NULL, free, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    bc_status status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) free(s);
    return status;
}

bc_status bc_kvm_session_wrap(bc_kvm *decoder, bc_console_emit emit, void *user, bc_console_session **out) {
    return wrap(decoder, emit, user, 0, out);
}
bc_status bc_kvm_session_create(const bc_kvm_options *options, bc_console_emit emit, void *user, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!emit) return BC_INVALID_ARGUMENT;
    bc_kvm *decoder = NULL;
    bc_status status = bc_kvm_create(options, &decoder);
    if (status == BC_OK) status = wrap(decoder, emit, user, 1, out);
    if (status != BC_OK) bc_kvm_destroy(decoder);
    return status;
}

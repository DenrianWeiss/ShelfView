#include "bcontrol/idrac_session.h"
#include "bcontrol/console_provider.h"
#include <stdlib.h>
typedef struct { bc_idrac_kvm *decoder; bc_console_emit emit; bc_idrac_led_snapshot leds; void *user; int owned; } idrac_session;
static bc_status pointer(idrac_session *s, const bc_console_input *event, uint8_t buttons) {
    uint8_t bytes[BC_KVM_POINTER_EVENT_SIZE];
    bc_status status = bc_kvm_pointer_encode(buttons, (uint16_t)event->x, (uint16_t)event->y,
        event->width, event->height, bytes, sizeof(bytes));
    return status == BC_OK ? s->emit(s->user, bytes, sizeof(bytes)) : status;
}
static bc_status input(void *user, const bc_console_input *event) {
    idrac_session *s = user;
    if (event->type == BC_CONSOLE_INPUT_KEY) {
        uint8_t bytes[BC_KVM_KEY_EVENT_SIZE];
        bc_status status = bc_idrac_kvm_key_encode((int)event->down, event->keysym, s->leds(s->user), bytes, sizeof(bytes));
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
    return bc_idrac_kvm_feed_message(((idrac_session *)user)->decoder, data, length);
}
static bc_status output(void *user, uint32_t channel, uint8_t *data, uint32_t capacity, uint32_t *written) {
    if (channel) return BC_INVALID_ARGUMENT;
    return bc_idrac_kvm_output(((idrac_session *)user)->decoder, data, capacity, written);
}
static bc_status control(void *user, uint32_t operation) {
    switch (operation) {
    case BC_CONSOLE_CONTROL_HEARTBEAT: return bc_idrac_kvm_heartbeat(((idrac_session *)user)->decoder);
    case BC_CONSOLE_CONTROL_QUERY_INPUT_STATE: return bc_idrac_kvm_query_led(((idrac_session *)user)->decoder);
    case BC_CONSOLE_CONTROL_CLOSE: return bc_idrac_kvm_close_session(((idrac_session *)user)->decoder);
    default: return BC_UNSUPPORTED;
    }
}
static bc_status info(void *user, bc_console_info *out) {
    idrac_session *s = user;
    out->flags = BC_CONSOLE_INFO_READY_KNOWN | ((bc_idrac_kvm_ready(s->decoder)) ? BC_CONSOLE_INFO_READY : 0);
    const bc_service_profile *profile = bc_idrac_kvm_profile_get(s->decoder);
    if (profile) { out->profile = *profile; out->flags |= BC_CONSOLE_INFO_PROFILE_VALID; }
    const bc_console_failure *failure = bc_idrac_kvm_failure_get(s->decoder);
    if (failure) { out->failure = *failure; out->flags |= BC_CONSOLE_INFO_FAILURE_VALID; }
    if (bc_idrac_kvm_led_known(s->decoder)) {
        out->keyboard_leds = (uint32_t)bc_idrac_kvm_led_status(s->decoder);
        out->flags |= BC_CONSOLE_INFO_LEDS_VALID;
    }
    return BC_OK;
}
static bc_string name(void *user) {
    const bc_kvm_frame *frame = bc_idrac_kvm_frame_get(((idrac_session *)user)->decoder);
    return frame ? frame->name : (bc_string){0};
}
static bc_status tile(void *user, bc_display_tile *out) {
    return bc_display_tile_from_frame(bc_idrac_kvm_frame_get(((idrac_session *)user)->decoder), out);
}
static void ack(void *user) { bc_idrac_kvm_ack_frame(((idrac_session *)user)->decoder); }
static void destroy(void *user) {
    idrac_session *s = user;
    if (s->owned) bc_idrac_kvm_destroy(s->decoder);
    free(s);
}
static bc_status wrap(bc_idrac_kvm *decoder, bc_console_emit emit, bc_idrac_led_snapshot leds, void *user, int owned, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!decoder || !emit || !leds) return BC_INVALID_ARGUMENT;
    idrac_session *s = malloc(sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    *s = (idrac_session){decoder, emit, leds, user, owned};
    bc_console_provider provider = {sizeof(provider), BC_DISPLAY_TILE, BC_CONSOLE_INPUT_HAS_SCROLL,
        input, tile, NULL, ack, destroy, feed, output, BC_CONSOLE_CONTROL_HEARTBEAT | BC_CONSOLE_CONTROL_QUERY_INPUT_STATE | BC_CONSOLE_CONTROL_CLOSE, control, info, NULL, name, NULL, NULL, NULL, NULL};
    bc_status status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) free(s);
    return status;
}

bc_status bc_idrac_session_wrap(bc_idrac_kvm *decoder, bc_console_emit emit,
    bc_idrac_led_snapshot leds, void *user, bc_console_session **out) {
    return wrap(decoder, emit, leds, user, 0, out);
}
bc_status bc_idrac_session_create(const bc_kvm_options *options, bc_string key,
    bc_console_emit emit, bc_idrac_led_snapshot leds, void *user, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!emit || !leds) return BC_INVALID_ARGUMENT;
    bc_idrac_kvm *decoder = NULL;
    bc_status status = bc_idrac_kvm_create(options, key, &decoder);
    if (status == BC_OK) status = wrap(decoder, emit, leds, user, 1, out);
    if (status != BC_OK) bc_idrac_kvm_destroy(decoder);
    return status;
}

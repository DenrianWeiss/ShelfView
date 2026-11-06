#include "bcontrol/ilo_session.h"
#include "bcontrol/console_provider.h"
#include <stdlib.h>
typedef struct { bc_ilo_kvm *decoder; bc_ilo_input *input; bc_console_emit emit; void *user; int owned; } ilo_session;
static bc_status input(void *user, const bc_console_input *event) {
    ilo_session *s = user;
    uint8_t bytes[10];
    bc_status status;
    if (event->type == BC_CONSOLE_INPUT_KEY)
        status = bc_ilo_input_key(s->input, event->keysym, (int)event->down, bytes, sizeof(bytes));
    else {
        if (event->type == BC_CONSOLE_INPUT_SCROLL && !event->wheel) return BC_OK;
        status = bc_ilo_input_pointer(s->input, (uint16_t)event->x, (uint16_t)event->y,
            event->width, event->height, (uint8_t)event->buttons, (int8_t)event->wheel, bytes, sizeof(bytes));
    }
    return status == BC_OK ? s->emit(s->user, bytes, sizeof(bytes)) : status;
}
static bc_status feed(void *user, uint32_t channel, const uint8_t *data, uint32_t length) {
    return bc_ilo_kvm_feed(((ilo_session *)user)->decoder, channel, data, length);
}
static bc_status output(void *user, uint32_t channel, uint8_t *data, uint32_t capacity, uint32_t *written) {
    return bc_ilo_kvm_output(((ilo_session *)user)->decoder, channel, data, capacity, written);
}
static bc_status control(void *user, uint32_t operation) {
    switch (operation) {
    case BC_CONSOLE_CONTROL_REFRESH: return bc_ilo_kvm_refresh(((ilo_session *)user)->decoder);
    default: return BC_UNSUPPORTED;
    }
}
static bc_status info(void *user, bc_console_info *out) {
    ilo_session *s = user;
    out->flags = BC_CONSOLE_INFO_READY_KNOWN | ((bc_ilo_kvm_ready(s->decoder)) ? BC_CONSOLE_INFO_READY : 0);
    return BC_OK;
}
static bc_status tile(void *user, bc_display_tile *out) {
    return bc_display_tile_from_frame(bc_ilo_kvm_frame(((ilo_session *)user)->decoder), out);
}
static void ack(void *user) { bc_ilo_kvm_ack_frame(((ilo_session *)user)->decoder); }
static void destroy(void *user) {
    ilo_session *s = user;
    if (s->owned) { bc_ilo_input_destroy(s->input); bc_ilo_kvm_destroy(s->decoder); }
    free(s);
}
static bc_status wrap(bc_ilo_kvm *decoder, bc_ilo_input *state,
    bc_console_emit emit, void *user, int owned, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!decoder || !state || !emit) return BC_INVALID_ARGUMENT;
    ilo_session *s = malloc(sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    *s = (ilo_session){decoder, state, emit, user, owned};
    bc_console_provider provider = {sizeof(provider), BC_DISPLAY_TILE, BC_CONSOLE_INPUT_HAS_SCROLL,
        input, tile, NULL, ack, destroy, feed, output, BC_CONSOLE_CONTROL_REFRESH, control, info, NULL, NULL, NULL, NULL, NULL, NULL};
    bc_status status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) free(s);
    return status;
}

bc_status bc_ilo_session_wrap(bc_ilo_kvm *decoder, bc_ilo_input *state,
    bc_console_emit emit, void *user, bc_console_session **out) {
    return wrap(decoder, state, emit, user, 0, out);
}
bc_status bc_ilo_session_create(uint32_t generation, bc_string token, uint32_t max_width,
    uint32_t max_height, bc_console_emit emit, void *user, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!emit) return BC_INVALID_ARGUMENT;
    bc_ilo_kvm *decoder = NULL; bc_ilo_input *state = NULL;
    bc_status status = bc_ilo_kvm_create(generation, token, max_width, max_height, &decoder);
    if (status == BC_OK) status = bc_ilo_input_create(&state);
    if (status == BC_OK) status = wrap(decoder, state, emit, user, 1, out);
    if (status != BC_OK) { bc_ilo_input_destroy(state); bc_ilo_kvm_destroy(decoder); }
    return status;
}

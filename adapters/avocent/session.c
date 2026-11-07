#include "bcontrol/avocent_session.h"
#include "bcontrol/console_provider.h"
#include "bcontrol/keyboard.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    bc_avocent_kvm *kvm;
    bc_console_emit emit;
    void *user;
    uint32_t pressed[32];
    uint8_t report[8];
} session;
static bc_status key(session *s, uint32_t usage, uint32_t down) {
    uint8_t bytes[16];
    bc_status status = bc_avocent_key_encode(usage, down, bytes);
    return status == BC_OK ? s->emit(s->user, bytes, sizeof(bytes)) : status;
}
static int contains(const uint8_t report[8], uint8_t usage) {
    for (unsigned i = 2; i < 8; ++i) if (report[i] == usage) return 1;
    return 0;
}
static bc_status input(void *user, const bc_console_input *event) {
    session *s = user;
    if (event->type == BC_CONSOLE_INPUT_KEY) {
        uint32_t pressed[32]; uint8_t report[8];
        memcpy(pressed, s->pressed, sizeof(pressed));
        bc_status status = bc_keyboard_report(pressed, event->keysym, event->down, report);
        if (status != BC_OK) return status;
        for (unsigned i = 2; i < 8 && status == BC_OK; ++i)
            if (s->report[i] && !contains(report, s->report[i])) status = key(s, s->report[i], 0);
        for (unsigned i = 0; i < 8 && status == BC_OK; ++i)
            if ((s->report[0] ^ report[0]) & (1u << i)) status = key(s, 0xe0 + i, !!(report[0] & (1u << i)));
        for (unsigned i = 2; i < 8 && status == BC_OK; ++i)
            if (report[i] && !contains(s->report, report[i])) status = key(s, report[i], 1);
        if (status == BC_OK) {
            memcpy(s->pressed, pressed, sizeof(pressed)); memcpy(s->report, report, sizeof(report));
        }
        return status;
    }
    uint8_t bytes[16];
    bc_status status = bc_avocent_pointer_encode(event->x, event->y, event->buttons,
        event->type == BC_CONSOLE_INPUT_POINTER ? 0 : event->wheel, bytes);
    return status == BC_OK ? s->emit(s->user, bytes, sizeof(bytes)) : status;
}
static bc_status feed(void *user, uint32_t channel, const uint8_t *data, uint32_t length) {
    return bc_avocent_kvm_feed(((session *)user)->kvm, channel, data, length);
}
static bc_status output(void *user, uint32_t channel, uint8_t *out, uint32_t capacity, uint32_t *written) {
    return bc_avocent_kvm_output(((session *)user)->kvm, channel, out, capacity, written);
}
static bc_status tile(void *user, bc_display_tile *out) {
    return bc_display_tile_from_frame(bc_avocent_kvm_frame(((session *)user)->kvm), out);
}
static void ack(void *user) { bc_avocent_kvm_ack(((session *)user)->kvm); }
static bc_status info(void *user, bc_console_info *out) {
    const bc_kvm_frame *frame = bc_avocent_kvm_frame(((session *)user)->kvm);
    out->flags = BC_CONSOLE_INFO_READY_KNOWN;
    if (frame && (frame->flags & BC_KVM_READY)) {
        out->flags |= BC_CONSOLE_INFO_READY | BC_CONSOLE_INFO_PROFILE_VALID;
        out->profile = (bc_service_profile){sizeof(bc_service_profile), BC_SERVICE_KVM,
            BC_SERVICE_FAMILY_AVOCENT, BC_SERVICE_AVOCENT_KVM_WEBSOCKET_241, BC_SERVICE_EVIDENCE_HANDSHAKE};
    }
    return BC_OK;
}
static bc_status control(void *user, uint32_t operation) {
    return operation == BC_CONSOLE_CONTROL_HEARTBEAT ?
        bc_avocent_kvm_heartbeat(((session *)user)->kvm) : BC_UNSUPPORTED;
}
static void destroy(void *user) {
    session *s = user; bc_avocent_kvm_destroy(s->kvm); free(s);
}
bc_status bc_avocent_session_create(bc_string username, bc_string password, uint32_t client_id,
    uint32_t width, uint32_t height, bc_console_emit emit, void *user, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!emit) return BC_INVALID_ARGUMENT;
    session *s = calloc(1, sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    s->emit = emit; s->user = user;
    bc_status status = bc_avocent_kvm_create(username, password, client_id, width, height, &s->kvm);
    if (status != BC_OK) { free(s); return status; }
    bc_console_provider provider = {0};
    provider.struct_size = sizeof(provider); provider.display_modes = BC_DISPLAY_TILE;
    provider.input_capabilities = BC_CONSOLE_INPUT_HAS_SCROLL;
    provider.input = input; provider.tile = tile; provider.ack_display = ack; provider.destroy = destroy;
    provider.feed = feed; provider.output = output; provider.info = info;
    provider.controls = BC_CONSOLE_CONTROL_HEARTBEAT; provider.control = control;
    status = bc_console_session_wrap(&provider, s, out);
    if (status != BC_OK) destroy(s);
    return status;
}

#include "bcontrol/idrac_kvm.h"
#include "../../core/log_internal.h"
#include <stdlib.h>
#include <string.h>

struct bc_idrac_kvm {
    bc_kvm *rfb;
    uint8_t key[256];
    uint32_t key_length;
    bc_status failure;
    int heartbeat;
    uint8_t led_status;
    int led_known;
    uint8_t pending[8 * 10];
    uint32_t pending_length;
    bc_service_profile profile;
    bc_console_failure detail;
};
static void failure(bc_idrac_kvm *client, bc_status status, uint32_t cause, int32_t code) {
    client->detail = (bc_console_failure){sizeof(client->detail), status, BC_CONSOLE_PHASE_VALIDATION,
        cause, BC_SERVICE_IDRAC_KVM_EHTML5, 0, code, BC_SERVICE_KVM, BC_SERVICE_FAMILY_IDRAC};
}
static bc_status extension(void *userdata, const uint8_t *data, uint32_t length,
    uint32_t *consumed, uint8_t *out, uint32_t capacity, uint32_t *written) {
    bc_idrac_kvm *client = userdata;
    if (length < 2) return BC_OK;
    if (data[1] == 179) {
        uint32_t size = client->key_length + 10;
        if (capacity < size) return BC_LIMIT_EXCEEDED;
        out[0] = 247; out[1] = 179;
        memcpy(out + 2, client->key, client->key_length);
        memset(out + 2 + client->key_length, 0, 8);
        *consumed = 2; *written = size;
        client->profile.evidence |= BC_SERVICE_EVIDENCE_DESCRIPTOR;
        return BC_OK;
    }
    uint32_t notification = 0;
    switch (data[1]) {
    case 166: case 168: notification = 3; break;
    case 170: notification = 8; break;
    case 171: notification = 4; break;
    case 173: notification = 6; break;
    case 174: notification = 2; break;
    case 175: notification = 114; break;
    case 177: notification = 9; break;
    case 164: case 165:
        failure(client, BC_BUSY, BC_CONSOLE_CAUSE_BUSY, data[1]);
        return BC_BUSY; /* Do not approve sharing or take over. */
    default: break;
    }
    if (notification) {
        if (length < notification) return BC_OK;
        *consumed = notification; return BC_OK;
    }
    if (data[1] == 161 || data[1] == 167 || data[1] == 169 || data[1] == 178) {
        if (length < 3) return BC_OK;
        *consumed = 3;
        if (data[1] == 178) { client->led_status = data[2]; client->led_known = 1; BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "idrac.led", "status=%u", data[2]); }
        if (data[1] != 169) return BC_OK;
        if (data[2] == 15) {
            if (capacity < 3) return BC_LIMIT_EXCEEDED;
            out[0] = 247; out[1] = 0; out[2] = 246; *written = 3;
            return BC_OK;
        }
        bc_status status = data[2] == 2 || data[2] == 8 ? BC_AUTHENTICATION_FAILED : BC_IO_ERROR;
        failure(client, status, status == BC_AUTHENTICATION_FAILED ? BC_CONSOLE_CAUSE_SESSION_REJECTED :
            BC_CONSOLE_CAUSE_UNKNOWN, data[2]);
        return status;
    }
    BC_LOG_WARN(BC_LOG_CATEGORY_KVM, "idrac.message_unsupported", "type=%u", data[1]);
    failure(client, BC_UNSUPPORTED, BC_CONSOLE_CAUSE_PROTOCOL, data[1]);
    return BC_UNSUPPORTED;
}
static bc_status initialize_auth(bc_idrac_kvm *client, bc_string key) {
    if (!key.data || !key.length || key.length > sizeof(client->key)) return BC_INVALID_ARGUMENT;
    for (uint64_t i = 0; i < key.length; ++i)
        if ((unsigned char)key.data[i] < 33 || (unsigned char)key.data[i] > 126) return BC_INVALID_ARGUMENT;
    client->profile = (bc_service_profile){sizeof(client->profile), BC_SERVICE_KVM,
        BC_SERVICE_FAMILY_IDRAC, BC_SERVICE_IDRAC_KVM_EHTML5, 0};
    memcpy(client->key, key.data, (size_t)key.length); client->key_length = (uint32_t)key.length;
    return BC_OK;
}
bc_status bc_idrac_kvm_create(const bc_kvm_options *options, bc_string key, bc_idrac_kvm **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    bc_idrac_kvm *client = calloc(1, sizeof(*client));
    if (!client) return BC_NO_MEMORY;
    bc_status status = initialize_auth(client, key);
    if (status == BC_OK) status = bc_kvm_create(options, &client->rfb);
    if (status == BC_OK) status = bc_kvm_set_extension_handler(client->rfb, 247, extension, client);
    if (status != BC_OK) { bc_idrac_kvm_destroy(client); return status; }
    *out = client; return BC_OK;
}
bc_status bc_idrac_kvm_feed_message(bc_idrac_kvm *client, const uint8_t *data, uint32_t length) {
    if (!client || !data || !length) return BC_INVALID_ARGUMENT;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "idrac.message", "bytes=%u", length);
    if (client->failure != BC_OK) return client->failure;
    /* Dell's client discards the complete client-list notification. Do not infer
     * a fixed wire length from one firmware's name/address field padding. */
    if (bc_kvm_extension_boundary(client->rfb) && length >= 2 && data[0] == 247 && data[1] == 172) {
        if (length < 38 || length > 65536) {
            failure(client, BC_PROTOCOL_ERROR, BC_CONSOLE_CAUSE_PROTOCOL, 172);
            return client->failure = BC_PROTOCOL_ERROR;
        }
        client->profile.evidence |= BC_SERVICE_EVIDENCE_DESCRIPTOR;
        if (bc_kvm_handshake_complete(client->rfb)) client->profile.evidence |= BC_SERVICE_EVIDENCE_HANDSHAKE;
        return BC_OK;
    }
    bc_status status = client->failure = bc_kvm_feed(client->rfb, data, length);
    if (status == BC_OK && client->profile.evidence && bc_kvm_handshake_complete(client->rfb))
        client->profile.evidence |= BC_SERVICE_EVIDENCE_HANDSHAKE;
    if (status != BC_OK && client->detail.status == BC_OK)
        failure(client, status, status == BC_PROTOCOL_ERROR || status == BC_UNSUPPORTED ?
            BC_CONSOLE_CAUSE_PROTOCOL : status == BC_AUTHENTICATION_FAILED ?
            BC_CONSOLE_CAUSE_SESSION_REJECTED : BC_CONSOLE_CAUSE_UNKNOWN, 0);
    return status;
}
const bc_service_profile *bc_idrac_kvm_profile_get(const bc_idrac_kvm *client) { return client ? &client->profile : NULL; }
const bc_console_failure *bc_idrac_kvm_failure_get(const bc_idrac_kvm *client) {
    return client && client->detail.status != BC_OK ? &client->detail : NULL;
}
bc_status bc_idrac_kvm_output(bc_idrac_kvm *client, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!client || !written || (capacity && !out)) return BC_INVALID_ARGUMENT;
    uint32_t count = client->pending_length < capacity ? client->pending_length : capacity;
    if (count) memcpy(out, client->pending, count);
    memmove(client->pending, client->pending + count, client->pending_length - count);
    client->pending_length -= count;
    uint32_t device_written = 0;
    bc_status status = bc_kvm_output(client->rfb, out + count, capacity - count, &device_written);
    *written = count + device_written;
    if (status == BC_OK && *written) BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "idrac.output", "bytes=%u", *written);
    if (status == BC_OK && client->heartbeat && capacity - *written >= 3) {
        const uint8_t message[3] = {247, 0, 246};
        memcpy(out + *written, message, 3); *written += 3; client->heartbeat = 0;
    }
    return status;
}
const bc_kvm_frame *bc_idrac_kvm_frame_get(const bc_idrac_kvm *client) {
    return client ? bc_kvm_frame_get(client->rfb) : NULL;
}
void bc_idrac_kvm_ack_frame(bc_idrac_kvm *client) { if (client) bc_kvm_ack_frame(client->rfb); }
bc_status bc_idrac_kvm_key_encode(int down, uint32_t keysym, uint8_t led, uint8_t *out, uint32_t capacity) {
    bc_status status = bc_kvm_key_encode(down, keysym, out, capacity);
    if (status == BC_OK) { out[0] = 246; out[3] = led; }
    return status;
}
bc_status bc_idrac_kvm_key_event(bc_idrac_kvm *client, int down, uint32_t keysym) {
    if (!client) return BC_INVALID_ARGUMENT;
    if (!bc_kvm_handshake_complete(client->rfb)) return BC_BUSY;
    /* The device's own client sends a Dell key event (type 246) with the current
     * keyboard LED byte instead of standard RFB key events (type 4). */
    if (client->pending_length + 8 > sizeof(client->pending)) return BC_LIMIT_EXCEEDED;
    uint8_t *event = client->pending + client->pending_length;
    bc_status status = bc_idrac_kvm_key_encode(down, keysym, client->led_status, event, 8);
    if (status != BC_OK) return status;
    client->pending_length += 8;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "idrac.key", "down=%d led=%u", down ? 1 : 0, client->led_status);
    return BC_OK;
}
bc_status bc_idrac_kvm_pointer_event(bc_idrac_kvm *client, uint8_t buttons, uint16_t x, uint16_t y) {
    return client ? bc_kvm_pointer_event(client->rfb, buttons, x, y) : BC_INVALID_ARGUMENT;
}
int bc_idrac_kvm_ready(const bc_idrac_kvm *client) { return client && bc_kvm_handshake_complete(client->rfb); }
int bc_idrac_kvm_led_known(const bc_idrac_kvm *client) { return client && client->led_known; }
int bc_idrac_kvm_led_status(const bc_idrac_kvm *client) { return client ? client->led_status : 0; }

bc_status bc_idrac_kvm_query_led(bc_idrac_kvm *client) {
    if (!client) return BC_INVALID_ARGUMENT;
    if (!bc_kvm_handshake_complete(client->rfb)) return BC_BUSY;
    if (client->pending_length + 3 > sizeof(client->pending)) return BC_LIMIT_EXCEEDED;
    uint8_t *message = client->pending + client->pending_length;
    message[0] = 247; message[1] = 0; message[2] = 178;
    client->pending_length += 3;
    return BC_OK;
}

bc_status bc_idrac_kvm_close_session(bc_idrac_kvm *client) {
    if (!client) return BC_INVALID_ARGUMENT;
    if (!bc_kvm_handshake_complete(client->rfb)) return BC_BUSY;
    if (client->pending_length + 3 > sizeof(client->pending)) return BC_LIMIT_EXCEEDED;
    uint8_t *message = client->pending + client->pending_length;
    message[0] = 247; message[1] = 0; message[2] = 249;
    client->pending_length += 3;
    return BC_OK;
}

bc_status bc_idrac_kvm_heartbeat(bc_idrac_kvm *client) {
    if (!client) return BC_INVALID_ARGUMENT;
    const bc_kvm_frame *frame = bc_kvm_frame_get(client->rfb);
    if (!frame || !(frame->flags & BC_KVM_READY)) return BC_UNSUPPORTED;
    client->heartbeat = 1; return BC_OK;
}
void bc_idrac_kvm_destroy(bc_idrac_kvm *client) {
    if (!client) return;
    bc_kvm_destroy(client->rfb);
    volatile uint8_t *key = client->key;
    for (size_t i = 0; i < sizeof(client->key); ++i) key[i] = 0;
    free(client);
}

struct bc_idrac_console_auth {
    bc_idrac_kvm protocol;
    uint8_t output[266], media_key[24];
    uint32_t output_length, media_key_length, replied, closed;
};
bc_status bc_idrac_console_auth_create(bc_string key, bc_idrac_console_auth **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    bc_idrac_console_auth *auth = calloc(1, sizeof(*auth));
    if (!auth) return BC_NO_MEMORY;
    bc_status status = initialize_auth(&auth->protocol, key);
    if (status != BC_OK) { bc_idrac_console_auth_destroy(auth); return status; }
    *out = auth; return BC_OK;
}
bc_status bc_idrac_console_auth_feed_message(bc_idrac_console_auth *auth, const uint8_t *data, uint32_t length) {
    if (!auth || !data || !length) return BC_INVALID_ARGUMENT;
    if (auth->closed) return BC_SHUTTING_DOWN;
    bc_idrac_kvm *client = &auth->protocol;
    if (client->failure != BC_OK) return client->failure;
    if (auth->output_length) return BC_BUSY;
    if (length == 12 && (!memcmp(data, "RFB 003.008\n", 12) || !memcmp(data, "RFB 003.007\n", 12) ||
        !memcmp(data, "RFB 003.003\n", 12))) return BC_OK;
    bc_status status = BC_PROTOCOL_ERROR;
    if (length >= 2 && data[0] == 247) {
        if (data[1] == 172) {
            if (!auth->replied || auth->media_key_length || length < 38 || length > 65536) goto failed;
            for (uint32_t i = 6; i < 38; ++i) {
                if (!data[i]) continue;
                if (data[i] < 33 || data[i] > 126) goto failed;
                if (auth->media_key_length < sizeof(auth->media_key))
                    auth->media_key[auth->media_key_length++] = data[i];
            }
            if (!auth->media_key_length) goto failed;
            volatile uint8_t *key = client->key;
            for (size_t i = 0; i < sizeof(client->key); ++i) key[i] = 0;
            client->key_length = 0;
            return BC_OK;
        }
        if (auth->media_key_length || (data[1] == 179 && auth->replied)) goto failed;
        uint32_t consumed = 0, written = 0;
        status = extension(client, data, length, &consumed, auth->output, sizeof(auth->output), &written);
        if (status == BC_OK && consumed != length) status = BC_PROTOCOL_ERROR;
        if (status == BC_OK) {
            auth->output_length = written;
            if (data[1] == 179) auth->replied = 1;
            return BC_OK;
        }
    }
failed:
    if (client->detail.status == BC_OK) failure(client, status, BC_CONSOLE_CAUSE_PROTOCOL, length > 1 ? data[1] : 0);
    memset(auth->media_key, 0, sizeof(auth->media_key)); auth->media_key_length = 0;
    return client->failure = status;
}
bc_status bc_idrac_console_auth_output(bc_idrac_console_auth *auth, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!auth || !written || (capacity && !out)) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (capacity < auth->output_length) return BC_LIMIT_EXCEEDED;
    if (auth->output_length) memcpy(out, auth->output, auth->output_length);
    *written = auth->output_length;
    memset(auth->output, 0, auth->output_length); auth->output_length = 0;
    return BC_OK;
}
bc_string bc_idrac_console_auth_key_get(const bc_idrac_console_auth *auth) {
    return auth && !auth->closed && auth->protocol.failure == BC_OK ?
        (bc_string){(const char *)auth->media_key, auth->media_key_length} : (bc_string){NULL, 0};
}
const bc_console_failure *bc_idrac_console_auth_failure_get(const bc_idrac_console_auth *auth) {
    return auth ? bc_idrac_kvm_failure_get(&auth->protocol) : NULL;
}
bc_status bc_idrac_console_auth_close_session(bc_idrac_console_auth *auth) {
    if (!auth) return BC_INVALID_ARGUMENT;
    if (auth->closed) return BC_OK;
    if (auth->output_length) return BC_BUSY;
    auth->output[0] = 247; auth->output[1] = 0; auth->output[2] = 249;
    auth->output_length = 3; auth->closed = 1;
    memset(auth->media_key, 0, sizeof(auth->media_key)); auth->media_key_length = 0;
    return BC_OK;
}
void bc_idrac_console_auth_destroy(bc_idrac_console_auth *auth) {
    if (!auth) return;
    volatile uint8_t *bytes = (volatile uint8_t *)auth;
    for (size_t i = 0; i < sizeof(*auth); ++i) bytes[i] = 0;
    free(auth);
}

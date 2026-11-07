#include "bcontrol/avocent.h"
#include "bcontrol/wire.h"
#include <stdlib.h>
#include <string.h>

struct bc_avocent_kvm {
    bc_avocent_video *video;
    uint8_t pending[2][1024];
    uint32_t pending_length[2], state[2], client_id, appliance_id;
    char username[97], password[97];
    uint32_t username_length, password_length;
    uint8_t incoming[2][65536];
    uint32_t incoming_length[2];
    bc_status failure;
};
static void erase(void *data, size_t length) {
    volatile uint8_t *p = data;
    while (length--) *p++ = 0;
}
static bc_status queue(bc_avocent_kvm *s, uint32_t channel, const uint8_t *data, uint32_t length) {
    if (length > sizeof(s->pending[channel]) - s->pending_length[channel]) return BC_LIMIT_EXCEEDED;
    memcpy(s->pending[channel] + s->pending_length[channel], data, length);
    s->pending_length[channel] += length;
    return BC_OK;
}
static bc_status command(bc_avocent_kvm *s, uint32_t channel, uint32_t type, uint32_t first, uint32_t second) {
    uint8_t data[16] = {'B','E','E','F'};
    bc_wire_write_be(data + 4, type, 2); bc_wire_write_be(data + 6, 16, 2);
    bc_wire_write_be(data + 8, first, 4); bc_wire_write_be(data + 12, second, 4);
    return queue(s, channel, data, sizeof(data));
}
bc_status bc_avocent_kvm_create(bc_string username, bc_string password, uint32_t client_id,
    uint32_t max_width, uint32_t max_height, bc_avocent_kvm **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!username.data || !password.data || !username.length || username.length > 96 ||
        !password.length || password.length > 96) return BC_INVALID_ARGUMENT;
    bc_avocent_kvm *s = calloc(1, sizeof(*s));
    if (!s) return BC_NO_MEMORY;
    bc_status status = bc_avocent_video_create(max_width, max_height, &s->video);
    if (status != BC_OK) { free(s); return status; }
    memcpy(s->username, username.data, (size_t)username.length);
    memcpy(s->password, password.data, (size_t)password.length);
    s->username_length = (uint32_t)username.length; s->password_length = (uint32_t)password.length;
    s->client_id = client_id;
    bc_avocent_apcp_websocket_request(BC_AVOCENT_CONTROL, 0, s->pending[0]);
    s->pending_length[0] = BC_AVOCENT_APCP_EXTENDED_SIZE;
    *out = s;
    return BC_OK;
}
void bc_avocent_kvm_destroy(bc_avocent_kvm *s) {
    if (!s) return;
    bc_avocent_video_destroy(s->video); erase(s, sizeof(*s)); free(s);
}
bc_status bc_avocent_kvm_output(bc_avocent_kvm *s, uint32_t channel, uint8_t *out,
    uint32_t capacity, uint32_t *written) {
    if (!written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (!s || channel > 1 || !out) return BC_INVALID_ARGUMENT;
    uint32_t length = s->pending_length[channel];
    if (length) length = !memcmp(s->pending[channel], "APCP", 4) ?
        (uint32_t)bc_wire_read_be(s->pending[channel] + 4, 4) :
        (uint32_t)bc_wire_read_be(s->pending[channel] + 6, 2);
    if (capacity < length) return BC_LIMIT_EXCEEDED;
    *written = length;
    memcpy(out, s->pending[channel], *written);
    s->pending_length[channel] -= length;
    memmove(s->pending[channel], s->pending[channel] + length, s->pending_length[channel]);
    erase(s->pending[channel] + s->pending_length[channel], length);
    return BC_OK;
}
static bc_status message(bc_avocent_kvm *s, uint32_t channel, const uint8_t *data, uint32_t length) {
    if (!s || channel > 1 || !data) return BC_INVALID_ARGUMENT;
    if (!s->state[channel]) {
        if (channel && s->state[0] != 2) return BC_BUSY;
        bc_avocent_setup setup;
        bc_status status = bc_avocent_apcp_parse(data, length, &setup);
        if (status != BC_OK) return status;
        if (setup.major != 2 || setup.minor != 41) return BC_UNSUPPORTED;
        if (!channel) {
            uint8_t login[256]; uint32_t written;
            status = bc_avocent_login_v4_encode((bc_string){s->username, s->username_length},
                (bc_string){s->password, s->password_length}, s->client_id, login, sizeof(login), &written);
            if (status == BC_OK) status = queue(s, 0, login, written);
            erase(login, sizeof(login));
        } else {
            status = command(s, 1, 1, s->client_id, s->appliance_id);
            if (status == BC_OK) status = command(s, 0, 0x208, 0x01000000, 0);
            if (status == BC_OK) status = command(s, 0, 0x30e, 0x01010000, 0);
            if (status == BC_OK) status = command(s, 0, 0x301, 0, 0);
        }
        if (status == BC_OK) s->state[channel] = 1;
        return status;
    }
    if (!channel && s->state[0] == 1) {
        bc_avocent_login_result result;
        bc_status status = bc_avocent_login_parse(BC_AVOCENT_CONTROL, data, length, &result);
        if (status != BC_OK) return status;
        erase(s->username, sizeof(s->username)); erase(s->password, sizeof(s->password));
        if (result.status) return BC_AUTHENTICATION_FAILED;
        s->appliance_id = result.session_id;
        bc_avocent_apcp_websocket_request(BC_AVOCENT_VIDEO, 0, s->pending[1]);
        s->pending_length[1] = BC_AVOCENT_APCP_EXTENDED_SIZE; s->state[0] = 2;
        return BC_OK;
    }
    if (channel) {
        uint32_t type = (uint32_t)bc_wire_read_be(data + 4, 2);
        if (type == 0x84 && length == 16) return data[8] ? BC_AUTHENTICATION_FAILED : BC_OK;
        if (type != 0x8b) return BC_UNSUPPORTED;
        bc_status status = bc_avocent_video_feed(s->video, data, length);
        if (status == BC_UNSUPPORTED && length >= 12 && (data[8] == 7 || data[8] == 8)) status = BC_OK;
        if (status == BC_OK) status = command(s, 1, 0, 0x01000000, 0);
        return status;
    }
    return BC_OK;
}
bc_status bc_avocent_kvm_feed(bc_avocent_kvm *s, uint32_t channel, const uint8_t *data, uint32_t length) {
    if (!s || channel > 1 || (!data && length)) return BC_INVALID_ARGUMENT;
    if (s->failure != BC_OK) return s->failure;
    while (length) {
        uint32_t have = s->incoming_length[channel], needed = 8;
        uint8_t *buffer = s->incoming[channel];
        if (have >= 8) {
            if (!memcmp(buffer, "APCP", 4)) needed = (uint32_t)bc_wire_read_be(buffer + 4, 4);
            else needed = (uint32_t)bc_wire_read_be(buffer + 6, 2);
            if (needed < 8 || needed > sizeof(s->incoming[channel])) {
                s->failure = BC_PROTOCOL_ERROR; return s->failure;
            }
        }
        uint32_t take = needed - have;
        if (take > length) take = length;
        memcpy(buffer + have, data, take);
        data += take; length -= take; have += take; s->incoming_length[channel] = have;
        if (have < 8) continue;
        needed = !memcmp(buffer, "APCP", 4) ? (uint32_t)bc_wire_read_be(buffer + 4, 4) :
            (uint32_t)bc_wire_read_be(buffer + 6, 2);
        if (needed < 8 || needed > sizeof(s->incoming[channel])) {
            s->failure = BC_PROTOCOL_ERROR; return s->failure;
        }
        if (have == needed) {
            bc_status status = message(s, channel, buffer, have);
            erase(buffer, have); s->incoming_length[channel] = 0;
            if (status != BC_OK) { s->failure = status; return status; }
        }
    }
    return BC_OK;
}
bc_status bc_avocent_kvm_heartbeat(bc_avocent_kvm *s) {
    if (!s) return BC_INVALID_ARGUMENT;
    if (s->failure != BC_OK) return s->failure;
    if (s->state[0] != 2) return BC_BUSY;
    return command(s, 0, 0x400, 0, 0);
}
const bc_kvm_frame *bc_avocent_kvm_frame(const bc_avocent_kvm *s) {
    return s ? bc_avocent_video_frame(s->video) : NULL;
}
void bc_avocent_kvm_ack(bc_avocent_kvm *s) { if (s) bc_avocent_video_ack(s->video); }

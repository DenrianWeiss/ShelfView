#include "bcontrol/keyboard.h"
#include "huawei_kvm_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HUAWEI_DEFAULT_HANDSHAKE_MS 8000u
#define HUAWEI_DEFAULT_HEARTBEAT_MS 5000u
#define HUAWEI_HANDSHAKE_STEP_MS 100u
#define HUAWEI_RECONNECT_SIZE 128u

#define CMD_IMAGE 0x02u
#define CMD_KEYBOARD 0x03u
#define CMD_MOUSE 0x05u
#define CMD_CONNECT 0x06u
#define CMD_HEARTBEAT 0x09u
#define CMD_MOUSE_MODE 0x24u
#define CMD_VMM_CODEKEY 0x31u
#define CMD_VMM_PORT 0x35u
#define CMD_VMM_STATE 0x47u
#define CMD_GET_SUITE 0x42u
#define CMD_RSP_SUITE 0x43u
#define CMD_SET_SUITE 0x44u
#define HCMD_IMAGE 0x02u
#define HCMD_CONNECT_STATE 0x08u
#define HCMD_VMM_CODEKEY 0x32u
#define HCMD_VMM_PORT 0x36u
#define HCMD_VMM_STATE 0x48u
#define HCMD_REPORT_KVMKEY 0x40u

static void set_error(char *buffer, uint32_t capacity, const char *message) {
    if (!buffer || !capacity) return;
    snprintf(buffer, capacity, "%s", message ? message : "");
}

struct bc_huawei_kvm_session {
    bc_service_profile profile;
    bc_console_failure failure;
    int auth_sent;
    bc_huawei_kvm_params params;
    bc_huawei_io io;
    bc_huawei_kvm_options options;
    uint32_t state;
    char error[BC_HUAWEI_ERROR_MAX];
    huawei_reader reader;
    bc_huawei_kvm_keys keys;
    huawei_image_assembler assembler;
    huawei_renderer renderer;
    bc_huawei_kvm_frame frame;
    uint32_t frame_ready;
    bc_huawei_kvm_stats stats;
    uint8_t pressed[16];
    uint8_t pressed_modifiers[16];
    uint8_t pressed_count;
    uint8_t last_key_report[8];
    uint8_t last_key_report_valid;
    uint8_t pointer_buttons;
    uint32_t absolute_mode;
    uint64_t last_heartbeat;
    uint32_t heartbeat_ticks;
    bc_huawei_vmm_info vmm;
    uint32_t vmm_stage;
    uint64_t vmm_next_ms;
    uint32_t frame_width;
    uint32_t frame_height;
    bc_huawei_video_sink video_sink;
    void *video_user;
};

static void session_error(bc_huawei_kvm_session *session, bc_status status, uint32_t phase, const char *message) {
    if (!session->failure.status) {
        set_error(session->error, sizeof(session->error), message);
        session->failure = (bc_console_failure){sizeof(session->failure), status, phase,
            status == BC_PROTOCOL_ERROR || status == BC_UNSUPPORTED ? BC_CONSOLE_CAUSE_PROTOCOL : BC_CONSOLE_CAUSE_UNKNOWN,
            BC_SERVICE_HUAWEI_KVM_NEGOTIATED, 0, 0, BC_SERVICE_KVM, BC_SERVICE_FAMILY_HUAWEI};
    }
    session->state = BC_HUAWEI_KVM_STATE_ERROR;
}

static uint32_t read_u16_le(const uint8_t *data) { return (uint32_t)data[0] | ((uint32_t)data[1] << 8); }
static uint32_t read_u16_be(const uint8_t *data) { return ((uint32_t)data[0] << 8) | data[1]; }
static uint32_t read_u32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
}

/* ---------------------------------------------------------------------------------------------
 * JNLP parsing (dependency-free scan for <param name="..." value="...">).
 * ------------------------------------------------------------------------------------------- */

static int jnlp_attribute(const char *element, uint32_t length, const char *name, char *out, uint32_t capacity) {
    size_t name_length = strlen(name);
    for (uint32_t i = 0; i + name_length + 2 < length; ++i) {
        if (memcmp(element + i, name, name_length) != 0) continue;
        if (i > 0 && element[i - 1] != ' ' && element[i - 1] != '\t' && element[i - 1] != '\n') continue;
        uint32_t at = i + (uint32_t)name_length;
        while (at < length && (element[at] == ' ' || element[at] == '\t' || element[at] == '\n')) ++at;
        if (at >= length || element[at] != '=') continue;
        ++at;
        while (at < length && (element[at] == ' ' || element[at] == '\t' || element[at] == '\n')) ++at;
        if (at >= length || element[at] != '"') continue;
        ++at;
        uint32_t start = at;
        while (at < length && element[at] != '"') ++at;
        if (at >= length || at == start || at - start + 1 > capacity) return 0;
        memcpy(out, element + start, at - start);
        out[at - start] = 0;
        return 1;
    }
    return 0;
}

static int jnlp_param(const char *xml, uint32_t length, const char *name, char *out, uint32_t capacity) {
    const char *cursor = xml;
    const char *end = xml + length;
    while (cursor < end) {
        const char *open = cursor;
        while (open + 5 < end && memcmp(open, "<param", 6) != 0) ++open;
        if (open + 5 >= end) break;
        const char *close = open;
        while (close < end && *close != '>') ++close;
        char param_name[64];
        if (jnlp_attribute(open, (uint32_t)(close - open), "name", param_name, sizeof(param_name)) &&
            strcmp(param_name, name) == 0) {
            return jnlp_attribute(open, (uint32_t)(close - open), "value", out, capacity);
        }
        cursor = close + 1;
    }
    return 0;
}

bc_status bc_huawei_kvm_params_from_jnlp(const uint8_t *data, uint64_t length, bc_huawei_kvm_params *params,
                                         char *error, uint32_t error_capacity) {
    if (!data || !params || length == 0 || length > 1024 * 1024) return BC_INVALID_ARGUMENT;
    if (params->struct_size != sizeof(*params) || params->abi_version != BC_ABI_VERSION) return BC_INVALID_ARGUMENT;
    memset(params, 0, sizeof(*params));
    params->struct_size = sizeof(*params);
    params->abi_version = BC_ABI_VERSION;
    const char *xml = (const char *)data;
    (void)jnlp_param(xml, (uint32_t)length, "IPA", params->host, sizeof(params->host));
    char value[64];
    if (!params->host[0]) { set_error(error, error_capacity, "missing IPA"); return BC_PROTOCOL_ERROR; }
    if (!jnlp_param(xml, (uint32_t)length, "port", value, sizeof(value)) || atoi(value) <= 0 || atoi(value) > 65535) {
        set_error(error, error_capacity, "missing or invalid port");
        return BC_PROTOCOL_ERROR;
    }
    params->port = (uint16_t)atoi(value);
    if (jnlp_param(xml, (uint32_t)length, "vmmPort", value, sizeof(value))) params->vmm_port = (uint16_t)atoi(value);
    if (jnlp_param(xml, (uint32_t)length, "privilege", value, sizeof(value))) params->privilege = (uint32_t)atoi(value);
    if (jnlp_param(xml, (uint32_t)length, "compress", value, sizeof(value))) params->compress = (uint32_t)atoi(value);
    if (!jnlp_param(xml, (uint32_t)length, "verifyValue", params->verify_value, sizeof(params->verify_value))) {
        set_error(error, error_capacity, "missing verifyValue");
        return BC_PROTOCOL_ERROR;
    }
    if (!jnlp_param(xml, (uint32_t)length, "decrykey", params->decrykey, sizeof(params->decrykey))) {
        set_error(error, error_capacity, "missing decrykey");
        return BC_PROTOCOL_ERROR;
    }
    uint8_t key_bytes[32];
    if (huawei_hex_decode(params->decrykey, key_bytes, sizeof(key_bytes)) != 32) {
        set_error(error, error_capacity, "decrykey must be 64 hex characters");
        return BC_PROTOCOL_ERROR;
    }
    (void)jnlp_param(xml, (uint32_t)length, "verifyValueExt", params->verify_value_ext,
                     sizeof(params->verify_value_ext));
    if (params->verify_value_ext[0]) {
        uint8_t extended[16];
        if (huawei_hex_decode(params->verify_value_ext, extended, sizeof(extended)) != 16) {
            set_error(error, error_capacity, "verifyValueExt must be 32 hex characters");
            return BC_PROTOCOL_ERROR;
        }
    }
    (void)jnlp_param(xml, (uint32_t)length, "title", params->title, sizeof(params->title));
    return BC_OK;
}

/* ---------------------------------------------------------------------------------------------
 * Security and packet builders
 * ------------------------------------------------------------------------------------------- */

static int params_negotiation(const bc_huawei_kvm_params *params, uint8_t key[16], uint8_t iv[16]) {
    uint8_t bytes[32];
    if (huawei_hex_decode(params->decrykey, bytes, sizeof(bytes)) != 32) return 0;
    memcpy(key, bytes, 16);
    memcpy(iv, bytes + 16, 16);
    return 1;
}

bc_status bc_huawei_kvm_auth_code(const bc_huawei_kvm_params *params, uint32_t hmac, uint32_t iterations,
                                  uint8_t out[BC_HUAWEI_AUTH_MAX]) {
    if (!params || !out || (hmac != 2 && hmac != 3) || !iterations) return BC_INVALID_ARGUMENT;
    uint8_t key[16], iv[16];
    if (!params_negotiation(params, key, iv)) return BC_INVALID_ARGUMENT;
    (void)key;
    const uint8_t *password = (const uint8_t *)(params->verify_value_ext[0] ? params->verify_value_ext
                                                                           : params->verify_value);
    size_t password_length = strlen((const char *)password);
    if (!password_length) return BC_INVALID_ARGUMENT;
    if (huawei_pbkdf2(password, password_length, iv, sizeof(iv), iterations, hmac == 3, out,
                      BC_HUAWEI_AUTH_MAX) != BC_OK) return BC_NO_MEMORY;
    huawei_swap_groups(out, BC_HUAWEI_AUTH_MAX);
    return BC_OK;
}

bc_status bc_huawei_kvm_content_keys(const uint8_t *negotiation, uint32_t length,
                                     const bc_huawei_kvm_params *params, uint32_t hmac, uint32_t iterations,
                                     bc_huawei_kvm_keys *keys) {
    if (!negotiation || !params || !keys || length != 48 || (hmac != 2 && hmac != 3) || !iterations)
        return BC_INVALID_ARGUMENT;
    uint8_t key[16], iv[16], plain[48], derived[48];
    if (!params_negotiation(params, key, iv)) return BC_INVALID_ARGUMENT;
    if (huawei_aes_cbc(key, iv, negotiation, length, plain, 0) != BC_OK) return BC_INVALID_ARGUMENT;
    uint8_t utf8[64];
    uint32_t utf8_length = huawei_latin1_to_utf8(plain, 32, utf8, sizeof(utf8));
    if (!utf8_length) return BC_NO_MEMORY;
    if (huawei_pbkdf2(utf8, utf8_length, plain + 32, 16, iterations, hmac == 3, derived, sizeof(derived)) != BC_OK)
        return BC_NO_MEMORY;
    huawei_swap_groups(derived, sizeof(derived));
    memcpy(keys->key, derived, 16);
    memcpy(keys->key_ext, derived + 16, 16);
    memcpy(keys->iv, derived + 32, 16);
    keys->hmac = hmac;
    keys->iterations = iterations;
    keys->flags |= BC_HUAWEI_KEY_CONTENT;
    return BC_OK;
}

static bc_status make_packet(const bc_huawei_kvm_params *params, const uint8_t *payload, uint32_t length,
                             uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!params || length > HUAWEI_MAX_PACKET - 2) return BC_INVALID_ARGUMENT;
    uint32_t total = length + 10;
    if (!out || capacity < total) return BC_LIMIT_EXCEEDED;
    uint32_t tag = (uint32_t)strtoul(params->verify_value, NULL, 10);
    uint32_t framed = length + 2;
    out[0] = HUAWEI_FRAME_MAGIC0; out[1] = HUAWEI_FRAME_MAGIC1;
    out[2] = (uint8_t)(framed >> 8); out[3] = (uint8_t)framed;
    out[4] = (uint8_t)(tag >> 24); out[5] = (uint8_t)(tag >> 16);
    out[6] = (uint8_t)(tag >> 8); out[7] = (uint8_t)tag;
    out[8] = 0; out[9] = 0;
    if (length) memcpy(out + 10, payload, length);
    if (written) *written = total;
    return BC_OK;
}

static bc_status make_authenticated_packet(const uint8_t auth[BC_HUAWEI_AUTH_MAX], const uint8_t *payload,
                                           uint32_t length, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!auth || length > 0x7FFF) return BC_INVALID_ARGUMENT;
    uint32_t total = 30 + length;
    if (!out || capacity < total) return BC_LIMIT_EXCEEDED;
    uint32_t framed = (0x80u << 8) | length;
    out[0] = HUAWEI_FRAME_MAGIC0; out[1] = HUAWEI_FRAME_MAGIC1;
    out[2] = (uint8_t)((framed + 2) >> 8); out[3] = (uint8_t)(framed + 2);
    memcpy(out + 4, auth, BC_HUAWEI_AUTH_MAX);
    out[28] = 0; out[29] = 0;
    if (length) memcpy(out + 30, payload, length);
    if (written) *written = total;
    return BC_OK;
}

bc_status bc_huawei_kvm_get_suite_packet(const bc_huawei_kvm_params *params, uint8_t *out, uint32_t capacity,
                                         uint32_t *written) {
    if (!params) return BC_INVALID_ARGUMENT;
    const uint8_t payload[2] = {CMD_GET_SUITE, 0};
    return make_packet(params, payload, sizeof(payload), out, capacity, written);
}

bc_status bc_huawei_kvm_set_suite_packet(const bc_huawei_kvm_params *params, uint32_t hmac, uint32_t iterations,
                                         uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!params) return BC_INVALID_ARGUMENT;
    const uint8_t payload[7] = {CMD_SET_SUITE, 0, (uint8_t)hmac, (uint8_t)(iterations >> 24),
                                (uint8_t)(iterations >> 16), (uint8_t)(iterations >> 8), (uint8_t)iterations};
    return make_packet(params, payload, sizeof(payload), out, capacity, written);
}

bc_status bc_huawei_kvm_connect_packet(const bc_huawei_kvm_params *params, const uint8_t auth[BC_HUAWEI_AUTH_MAX],
                                       const uint8_t *reconnect, uint32_t reconnect_length, uint8_t *out,
                                       uint32_t capacity, uint32_t *written) {
    if (!params || !auth || (reconnect_length && reconnect_length != HUAWEI_RECONNECT_SIZE))
        return BC_INVALID_ARGUMENT;
    uint8_t payload[5 + HUAWEI_RECONNECT_SIZE];
    payload[0] = CMD_CONNECT; payload[1] = 0; payload[2] = 0; payload[3] = 1; payload[4] = 1;
    uint32_t length = 5;
    if (reconnect_length) { memcpy(payload + 5, reconnect, reconnect_length); length += reconnect_length; }
    return make_authenticated_packet(auth, payload, length, out, capacity, written);
}

bc_status bc_huawei_kvm_heartbeat_packet(const bc_huawei_kvm_params *params, uint8_t *out, uint32_t capacity,
                                         uint32_t *written) {
    if (!params) return BC_INVALID_ARGUMENT;
    const uint8_t payload[2] = {CMD_HEARTBEAT, 0};
    return make_packet(params, payload, sizeof(payload), out, capacity, written);
}

bc_status bc_huawei_kvm_input_packet(const bc_huawei_kvm_params *params, const bc_huawei_kvm_keys *keys,
                                     uint32_t command, const uint8_t *payload, uint32_t length, uint8_t *out,
                                     uint32_t capacity, uint32_t *written) {
    if (!params || !keys || !payload || !length || length > HUAWEI_AES_BLOCK) return BC_INVALID_ARGUMENT;
    if ((keys->flags & BC_HUAWEI_KEY_CONTENT) == 0) return BC_INVALID_ARGUMENT;
    if (command != CMD_KEYBOARD && command != CMD_MOUSE) return BC_UNSUPPORTED;
    uint8_t padded[HUAWEI_AES_BLOCK], encrypted[HUAWEI_AES_BLOCK], packet_payload[2 + HUAWEI_AES_BLOCK];
    memset(padded, 0, sizeof(padded));
    memcpy(padded, payload, length);
    if (huawei_aes_cbc(keys->key_ext, keys->iv, padded, HUAWEI_AES_BLOCK, encrypted, 1) != BC_OK)
        return BC_INVALID_ARGUMENT;
    packet_payload[0] = (uint8_t)command;
    packet_payload[1] = 0;
    memcpy(packet_payload + 2, encrypted, HUAWEI_AES_BLOCK);
    return make_packet(params, packet_payload, sizeof(packet_payload), out, capacity, written);
}

bc_status bc_huawei_kvm_mouse_mode_packet(const bc_huawei_kvm_params *params, uint32_t absolute, uint8_t *out,
                                          uint32_t capacity, uint32_t *written) {
    if (!params) return BC_INVALID_ARGUMENT;
    const uint8_t payload[5] = {CMD_MOUSE_MODE, 0, (uint8_t)(absolute ? 1 : 0), 0, 0};
    return make_packet(params, payload, sizeof(payload), out, capacity, written);
}

/* ---------------------------------------------------------------------------------------------
 * Keysym mapping
 * ------------------------------------------------------------------------------------------- */

uint32_t bc_huawei_kvm_keysym_to_usage(uint32_t keysym, uint8_t *modifiers) {
    return bc_keyboard_keysym_to_usage(keysym, modifiers);
}

/* ---------------------------------------------------------------------------------------------
 * Session
 * ------------------------------------------------------------------------------------------- */

static uint64_t session_clock(const bc_huawei_kvm_session *session) {
    if (session->options.clock && session->options.clock_user)
        return session->options.clock(session->options.clock_user);
    return 0;
}

static uint64_t session_timeout(const bc_huawei_kvm_session *session, uint32_t fallback) {
    uint32_t timeout = session->options.handshake_timeout_ms;
    return timeout ? timeout : fallback;
}

static bc_status session_send(bc_huawei_kvm_session *session, const uint8_t *data, uint32_t length) {
    if (!session->io.send) return BC_INVALID_ARGUMENT;
    return session->io.send(session->io.user, data, length);
}

static bc_status session_send_payload(bc_huawei_kvm_session *session, const uint8_t *payload, uint32_t length) {
    uint8_t packet[16];
    uint32_t written = 0;
    if (length > 6) return BC_LIMIT_EXCEEDED;
    bc_status status = make_packet(&session->params, payload, length, packet, sizeof(packet), &written);
    if (status != BC_OK) return status;
    return session_send(session, packet, written);
}

static void session_send_heartbeat(bc_huawei_kvm_session *session) {
    uint8_t packet[16];
    uint32_t written = 0;
    if (bc_huawei_kvm_heartbeat_packet(&session->params, packet, sizeof(packet), &written) != BC_OK) return;
    if (session_send(session, packet, written) == BC_OK) ++session->stats.heartbeats;
}

static bc_status session_send_auth_and_connect(bc_huawei_kvm_session *session) {
    uint8_t auth[BC_HUAWEI_AUTH_MAX], packet[64];
    uint32_t written = 0;
    bc_status status = bc_huawei_kvm_auth_code(&session->params, session->keys.hmac, session->keys.iterations, auth);
    if (status != BC_OK) return status;
    memcpy(session->keys.auth, auth, sizeof(auth));
    session->keys.flags |= BC_HUAWEI_KEY_AUTH;
    status = bc_huawei_kvm_connect_packet(&session->params, auth, NULL, 0, packet, sizeof(packet), &written);
    if (status != BC_OK) return status;
    status = session_send(session, packet, written);
    if (status == BC_OK) session->auth_sent = 1;
    return status;
}

static bc_status session_select_suite(const uint8_t *payload, uint32_t length, uint32_t *hmac, uint32_t *iterations) {
    if (length < 3 || payload[0] != CMD_RSP_SUITE) return BC_PROTOCOL_ERROR;
    uint32_t count = payload[2];
    if (length != 3 + count * 5) return BC_PROTOCOL_ERROR;
    uint32_t best_hmac = 0, best_iterations = 0;
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t at = 3 + index * 5;
        uint32_t identifier = payload[at];
        uint32_t value = read_u32_be(payload + at + 1);
        if (!value) continue;
        if (identifier == 3) { *hmac = 3; *iterations = value; return BC_OK; }
        if (identifier == 2 && !best_hmac) { best_hmac = 2; best_iterations = value; }
    }
    if (best_hmac) { *hmac = best_hmac; *iterations = best_iterations; return BC_OK; }
    return BC_UNSUPPORTED;
}

static void session_note_error(bc_huawei_kvm_session *session, bc_status status) {
    if (status == BC_OK) return;
    if (!session->error[0]) {
        const char *text = bc_status_string(status);
        set_error(session->error, sizeof(session->error), text ? text : "protocol error");
    }
}

static void session_process_image(bc_huawei_kvm_session *session, const uint8_t *payload, uint32_t length) {
    if (length < 5) return;
    uint32_t offset = read_u16_be(payload + 2);
    uint32_t sequence = payload[4];
    if (offset == 0) {
        if (length < 19) return;
        uint32_t byte_length = read_u32_be(payload + 5);
        uint32_t width = read_u16_be(payload + 9) & 0x7FFFu;
        uint32_t height = read_u16_be(payload + 11);
        if (!byte_length) { huawei_assembler_reset(&session->assembler); return; }
        bc_status status = huawei_assembler_begin(&session->assembler, width, height, byte_length,
                                                  payload[18] & 0x0Fu, (payload[18] >> 7) & 1u, sequence);
        if (status != BC_OK) session_note_error(session, status);
        return;
    }
    if (!session->assembler.active || length < 7) return;
    uint32_t real_length = payload[5];
    if (!real_length || real_length > BC_HUAWEI_FRAGMENT) return;
    uint8_t chunk[BC_HUAWEI_FRAGMENT + 16];
    uint32_t chunk_length = 0;
    if ((session->keys.flags & BC_HUAWEI_KEY_CONTENT) != 0) {
        uint32_t cipher_length = length - 6;
        if (cipher_length % 16 || cipher_length > sizeof(chunk)) return;
        if (huawei_aes_cbc(session->keys.key, session->keys.iv, payload + 6, cipher_length, chunk, 0) != BC_OK)
            return;
        if (real_length > cipher_length) return;
        chunk_length = real_length;
    } else {
        if (length - 5 > BC_HUAWEI_FRAGMENT) return;
        memcpy(chunk, payload + 5, length - 5);
        chunk_length = length - 5;
    }
    if (huawei_assembler_fragment(&session->assembler, sequence, offset, chunk, chunk_length) != BC_OK) return;
    if (!huawei_assembler_complete(&session->assembler)) return;
    if (session->video_sink) {
        bc_status status = session->video_sink(session->video_user, session->assembler.blocks,
            session->assembler.byte_length, session->assembler.width, session->assembler.height,
            session->assembler.quantization, session->assembler.sequence,
            session->assembler.key_frame ? BC_HUAWEI_FRAME_KEY : 0);
        session->assembler.active = 0;
        if (status != BC_OK) {
            session_error(session, status, BC_CONSOLE_PHASE_TRANSPORT, "video consumer failed");
            return;
        }
        session->stats.image_packets++;
        session->frame_width = session->assembler.width;
        session->frame_height = session->assembler.height;
        return;
    }
    bc_status status = huawei_renderer_draw(&session->renderer, session->assembler.blocks,
                                            session->assembler.byte_length, session->assembler.width,
                                            session->assembler.height, session->assembler.quantization);
    if (status != BC_OK) { session_note_error(session, status); return; }
    if (session->frame_ready) ++session->stats.dropped_frames;
    session->stats.image_packets++;
    session->stats.decoded_frames++;
    session->frame.width = session->assembler.width;
    session->frame.height = session->assembler.height;
    session->frame.stride = session->assembler.width * 4;
    session->frame.pixels = session->options.frame_buffer;
    session->frame.pixel_bytes = session->assembler.width * session->assembler.height * 4;
    session->frame.sequence = session->assembler.sequence;
    session->frame.quantization = session->assembler.quantization;
    session->frame.flags = BC_HUAWEI_FRAME_READY | (session->assembler.key_frame ? BC_HUAWEI_FRAME_KEY : 0);
    session->frame_width = session->assembler.width;
    session->frame_height = session->assembler.height;
    session->frame_ready = 1;
    session->assembler.active = 0;
}

static bc_status session_vmm_decrypt(bc_huawei_kvm_session *session, const uint8_t *payload, uint32_t length,
                                     uint8_t *plain, uint32_t *plain_length) {
    if (length < 2 || (length - 2) % 16 || length - 2 > 96) return BC_PROTOCOL_ERROR;
    if ((session->keys.flags & BC_HUAWEI_KEY_CONTENT) == 0) return BC_PROTOCOL_ERROR;
    uint32_t cipher = length - 2;
    if (huawei_aes_cbc(session->keys.key, session->keys.iv, payload + 2, cipher, plain, 0) != BC_OK)
        return BC_PROTOCOL_ERROR;
    *plain_length = cipher;
    return BC_OK;
}

static void session_process_vmm(bc_huawei_kvm_session *session, const uint8_t *payload, uint32_t length) {
    uint8_t plain[96];
    uint32_t plain_length = 0;
    if (session_vmm_decrypt(session, payload, length, plain, &plain_length) != BC_OK) {
        session->vmm.state = BC_HUAWEI_VMM_STATE_DISABLED;
        return;
    }
    if (payload[0] == HCMD_VMM_CODEKEY) {
        if (plain_length < 36) { session->vmm.state = BC_HUAWEI_VMM_STATE_DISABLED; return; }
        uint8_t utf8[64], derived[56];
        uint32_t utf8_length = huawei_latin1_to_utf8(plain, 20, utf8, sizeof(utf8));
        if (!utf8_length ||
            huawei_pbkdf2(utf8, utf8_length, plain + 20, 16, session->keys.iterations, session->keys.hmac == 3,
                          derived, sizeof(derived)) != BC_OK) {
            session->vmm.state = BC_HUAWEI_VMM_STATE_DISABLED;
            return;
        }
        memcpy(session->vmm.auth, derived, BC_HUAWEI_AUTH_MAX);
        memcpy(session->vmm.key, derived + 24, 16);
        memcpy(session->vmm.iv, derived + 40, 16);
        session->vmm.state = BC_HUAWEI_VMM_STATE_CONNECTING;
        session->vmm_stage = 2;
        session->vmm_next_ms = session_clock(session) + 1000u;
    } else if (payload[0] == HCMD_VMM_STATE) {
        session->vmm.state = read_u16_le(plain) == 1 ? BC_HUAWEI_VMM_STATE_ENABLED : BC_HUAWEI_VMM_STATE_DISABLED;
        if (session->vmm.state == BC_HUAWEI_VMM_STATE_DISABLED) { session->vmm_stage = 7; return; }
        session->vmm_stage = 4;
        session->vmm_next_ms = session_clock(session) + 1000u;
    } else if (payload[0] == HCMD_VMM_PORT) {
        session->vmm.port = read_u16_le(plain);
        session->vmm_stage = 6;
    }
}

static bc_status session_handle_payload(bc_huawei_kvm_session *session, const uint8_t *payload, uint32_t length) {
    if (!length) return BC_OK;
    switch (payload[0]) {
    case CMD_RSP_SUITE: {
        uint32_t hmac = 0, iterations = 0;
        bc_status status = session->state == BC_HUAWEI_KVM_STATE_CONNECTING && !session->auth_sent ?
            session_select_suite(payload, length, &hmac, &iterations) : BC_PROTOCOL_ERROR;
        if (status != BC_OK) {
            session_error(session, status, BC_CONSOLE_PHASE_VALIDATION, "unsupported or invalid KVM suite response");
            return status;
        }
        session->keys.hmac = hmac; session->keys.iterations = iterations;
        uint8_t packet[32]; uint32_t written = 0;
        status = bc_huawei_kvm_set_suite_packet(&session->params, hmac, iterations, packet, sizeof(packet), &written);
        if (status == BC_OK) status = session_send(session, packet, written);
        if (status != BC_OK) {
            session_error(session, status, BC_CONSOLE_PHASE_TRANSPORT, "suite selection send failed");
            return status;
        }
        status = session_send_auth_and_connect(session);
        if (status != BC_OK) session_error(session, status, BC_CONSOLE_PHASE_VALIDATION, "auth handshake failed");
        return status;
    }
    case HCMD_REPORT_KVMKEY:
        if (length == 50) {
            if (!session->auth_sent) {
                session_error(session, BC_PROTOCOL_ERROR, BC_CONSOLE_PHASE_VALIDATION, "unsolicited content keys");
                return BC_PROTOCOL_ERROR;
            }
            bc_status status = bc_huawei_kvm_content_keys(payload + 2, 48, &session->params, session->keys.hmac,
                                                         session->keys.iterations, &session->keys);
            if (status != BC_OK) { session_error(session, status, BC_CONSOLE_PHASE_VALIDATION, "content key negotiation failed"); return status; }
            session->profile.evidence |= BC_SERVICE_EVIDENCE_HANDSHAKE;
            session->state = BC_HUAWEI_KVM_STATE_STREAMING;
            session->last_heartbeat = session_clock(session);
        } else if (length == 130) {
            uint8_t key[16], iv[16];
            if (params_negotiation(&session->params, key, iv)) {
                (void)huawei_aes_cbc(key, iv, payload + 2, 128, session->keys.reconnect, 0);
                session->keys.flags |= BC_HUAWEI_KEY_RECONNECT;
            }
        }
        return BC_OK;
    case HCMD_CONNECT_STATE:
        if (length > 2 && payload[2] != 0) {
            session_error(session, BC_PROTOCOL_ERROR, BC_CONSOLE_PHASE_VALIDATION, "KVM session rejected by the device");
            session->failure.cause = BC_CONSOLE_CAUSE_SESSION_REJECTED;
            session->failure.device_code = payload[2];
            return BC_PROTOCOL_ERROR;
        }
        return BC_OK;
    case HCMD_IMAGE:
        session_process_image(session, payload, length);
        return BC_OK;
    case HCMD_VMM_CODEKEY:
    case HCMD_VMM_PORT:
    case HCMD_VMM_STATE:
        session_process_vmm(session, payload, length);
        return BC_OK;
    default:
        return BC_OK;
    }
}

static int session_payload_callback(void *user, const uint8_t *payload, uint32_t length) {
    bc_huawei_kvm_session *session = (bc_huawei_kvm_session *)user;
    if (session->state == BC_HUAWEI_KVM_STATE_ERROR) return 0;
    (void)session_handle_payload(session, payload, length);
    return 1;
}

static bc_status session_receive(bc_huawei_kvm_session *session, uint32_t timeout_ms) {
    uint8_t buffer[4096];
    uint32_t received = 0;
    if (!session->io.recv) return BC_INVALID_ARGUMENT;
    bc_status status = session->io.recv(session->io.user, buffer, sizeof(buffer), &received, timeout_ms);
    if (status != BC_OK) return status;
    if (!received) return BC_OK;
    session->stats.received_bytes += received;
    (void)huawei_reader_feed(&session->reader, buffer, received, session_payload_callback, session);
    return session->state == BC_HUAWEI_KVM_STATE_ERROR ? session->failure.status : BC_OK;
}

bc_status bc_huawei_kvm_session_create(const bc_huawei_kvm_params *params, const bc_huawei_io *io,
                                       const bc_huawei_kvm_options *options, bc_huawei_kvm_session **out) {
    if (!params || !io || !io->send || !io->recv || !out) return BC_INVALID_ARGUMENT;
    if (!options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    if (!options->frame_buffer || !options->frame_capacity) return BC_INVALID_ARGUMENT;
    bc_huawei_kvm_session *session = (bc_huawei_kvm_session *)calloc(1, sizeof(*session));
    if (!session) return BC_NO_MEMORY;
    session->params = *params;
    session->io = *io;
    session->options = *options;
    session->state = BC_HUAWEI_KVM_STATE_CREATED;
    session->profile = (bc_service_profile){sizeof(bc_service_profile), BC_SERVICE_KVM,
        BC_SERVICE_FAMILY_HUAWEI, BC_SERVICE_HUAWEI_KVM_NEGOTIATED, 0};
    session->keys.hmac = 2;
    session->keys.iterations = 5000;
    session->vmm.struct_size = sizeof(session->vmm);
    huawei_renderer_reset(&session->renderer, options->frame_buffer, options->frame_capacity);
    *out = session;
    return BC_OK;
}

bc_status bc_huawei_kvm_session_start(bc_huawei_kvm_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_HUAWEI_KVM_STATE_CREATED) return BC_BUSY;
    session->state = BC_HUAWEI_KVM_STATE_CONNECTING;
    session->error[0] = 0;
    bc_status status;
    if (session->params.verify_value_ext[0]) {
        uint8_t packet[16];
        uint32_t written = 0;
        status = bc_huawei_kvm_get_suite_packet(&session->params, packet, sizeof(packet), &written);
        if (status != BC_OK) { session_error(session, status, BC_CONSOLE_PHASE_VALIDATION, "cannot build GetSuite packet"); return status; }
        status = session_send(session, packet, written);
        if (status != BC_OK) { session_error(session, status, BC_CONSOLE_PHASE_TRANSPORT, "transport send failed"); return status; }
    } else {
        status = session_send_auth_and_connect(session);
        if (status != BC_OK) { session_error(session, status, BC_CONSOLE_PHASE_VALIDATION, "auth handshake failed"); return status; }
    }
    uint64_t started = session_clock(session);
    uint32_t timeout = (uint32_t)session_timeout(session, HUAWEI_DEFAULT_HANDSHAKE_MS);
    uint32_t iterations = timeout / HUAWEI_HANDSHAKE_STEP_MS + 1;
    while (session->state == BC_HUAWEI_KVM_STATE_CONNECTING) {
        if (session->options.clock && session->options.clock_user) {
            if (session_clock(session) - started > timeout) { session_error(session, BC_TIMEOUT, BC_CONSOLE_PHASE_VALIDATION, "KVM handshake timed out"); return BC_TIMEOUT; }
        } else if (!iterations--) {
            session_error(session, BC_TIMEOUT, BC_CONSOLE_PHASE_VALIDATION, "KVM handshake timed out");
            return BC_TIMEOUT;
        }
        status = session_receive(session, HUAWEI_HANDSHAKE_STEP_MS);
        if (status == BC_TIMEOUT) continue;
        if (status != BC_OK) { session_error(session, status, BC_CONSOLE_PHASE_TRANSPORT, "KVM handshake transport failed"); return status; }
    }
    if (session->state == BC_HUAWEI_KVM_STATE_ERROR) return BC_PROTOCOL_ERROR;
    return session->state == BC_HUAWEI_KVM_STATE_STREAMING ? BC_OK : BC_PROTOCOL_ERROR;
}

bc_status bc_huawei_kvm_session_set_video_sink(bc_huawei_kvm_session *session, bc_huawei_video_sink sink, void *user) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_HUAWEI_KVM_STATE_CREATED) return BC_BUSY;
    session->video_sink = sink; session->video_user = user;
    return BC_OK;
}

bc_status bc_huawei_kvm_session_poll(bc_huawei_kvm_session *session, uint32_t timeout_ms) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state == BC_HUAWEI_KVM_STATE_ERROR) return BC_PROTOCOL_ERROR;
    if (session->state != BC_HUAWEI_KVM_STATE_STREAMING) return BC_BUSY;
    bc_status status = session_receive(session, timeout_ms);
    if (status != BC_OK && status != BC_TIMEOUT) {
        session_error(session, status, BC_CONSOLE_PHASE_TRANSPORT, "KVM transport failed");
        return status;
    }
    if (session->state == BC_HUAWEI_KVM_STATE_ERROR) return BC_PROTOCOL_ERROR;
    if (session->vmm_stage == 2 || session->vmm_stage == 4) {
        uint64_t now = session_clock(session);
        int due = !session->options.clock || !session->options.clock_user || now >= session->vmm_next_ms;
        if (due) {
            if (session->vmm_stage == 2) {
                const uint8_t request[2] = {CMD_VMM_STATE, 0};
                (void)session_send_payload(session, request, sizeof(request));
                session->vmm_stage = 3;
            } else {
                const uint8_t request[2] = {CMD_VMM_PORT, 0};
                (void)session_send_payload(session, request, sizeof(request));
                session->vmm_stage = 5;
            }
        }
    }
    uint32_t interval = session->options.heartbeat_interval_ms;
    if (!interval) interval = HUAWEI_DEFAULT_HEARTBEAT_MS;
    if (session->options.clock && session->options.clock_user) {
        uint64_t now = session_clock(session);
        if (now - session->last_heartbeat >= interval) {
            session_send_heartbeat(session);
            session->last_heartbeat = now;
        }
    } else {
        if (++session->heartbeat_ticks >= 64) {
            session_send_heartbeat(session);
            session->heartbeat_ticks = 0;
        }
    }
    return BC_OK;
}

bc_status bc_huawei_kvm_session_frame(bc_huawei_kvm_session *session, bc_huawei_kvm_frame *frame) {
    if (!session || !frame) return BC_INVALID_ARGUMENT;
    if (!session->frame_ready) return BC_BUSY;
    *frame = session->frame;
    return BC_OK;
}

bc_status bc_huawei_kvm_session_ack_frame(bc_huawei_kvm_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    session->frame_ready = 0;
    return BC_OK;
}

static bc_status session_build_and_send_input(bc_huawei_kvm_session *session, uint32_t command,
                                              const uint8_t *payload, uint32_t length) {
    uint8_t packet[64];
    uint32_t written = 0;
    bc_status status = bc_huawei_kvm_input_packet(&session->params, &session->keys, command, payload, length,
                                                  packet, sizeof(packet), &written);
    if (status != BC_OK) return status;
    return session_send(session, packet, written);
}

static void session_build_key_report(const bc_huawei_kvm_session *session, uint8_t report[8]) {
    memset(report, 0, 8);
    for (uint32_t i = 0; i < session->pressed_count; ++i) {
        uint8_t usage = session->pressed[i];
        if (usage >= 0xE0 && usage <= 0xE7) report[0] |= (uint8_t)(1u << (usage - 0xE0));
        report[0] |= session->pressed_modifiers[i];
    }
    uint32_t at = 2;
    for (uint32_t i = 0; i < session->pressed_count && at < 8; ++i) {
        uint8_t usage = session->pressed[i];
        if (usage < 0xE0 || usage > 0xE7) report[at++] = usage;
    }
}

/* Firmware may interpret every keyboard packet as a new key event. Only submit an 8-byte HID
 * report when press/release actually changed the pressed keys or modifiers; repeating the same
 * report (macOS auto-repeat or a duplicate event) must not reach the wire. */
static bc_status session_send_key_report(bc_huawei_kvm_session *session) {
    uint8_t report[8];
    session_build_key_report(session, report);
    if (session->last_key_report_valid && memcmp(session->last_key_report, report, sizeof(report)) == 0)
        return BC_OK;
    bc_status status = session_build_and_send_input(session, CMD_KEYBOARD, report, sizeof(report));
    if (status == BC_OK) {
        memcpy(session->last_key_report, report, sizeof(report));
        session->last_key_report_valid = 1;
    }
    return status;
}

static void session_press(bc_huawei_kvm_session *session, uint8_t usage, uint8_t modifiers) {
    for (uint32_t i = 0; i < session->pressed_count; ++i) if (session->pressed[i] == usage) return;
    if (session->pressed_count >= sizeof(session->pressed)) return;
    session->pressed[session->pressed_count] = usage;
    session->pressed_modifiers[session->pressed_count] = modifiers;
    ++session->pressed_count;
}

static void session_release(bc_huawei_kvm_session *session, uint8_t usage) {
    for (uint32_t i = 0; i < session->pressed_count; ++i) {
        if (session->pressed[i] != usage) continue;
        uint32_t last = (uint32_t)session->pressed_count - 1;
        session->pressed[i] = session->pressed[last];
        session->pressed_modifiers[i] = session->pressed_modifiers[last];
        --session->pressed_count;
        return;
    }
}

static bc_status session_require_input(bc_huawei_kvm_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_HUAWEI_KVM_STATE_STREAMING) return BC_BUSY;
    if ((session->keys.flags & BC_HUAWEI_KEY_CONTENT) == 0) return BC_BUSY;
    return BC_OK;
}

bc_status bc_huawei_kvm_session_key_usage(bc_huawei_kvm_session *session, uint8_t usage, uint8_t modifiers,
                                          uint32_t down) {
    bc_status status = session_require_input(session);
    if (status != BC_OK) return status;
    if (down) session_press(session, usage, modifiers); else session_release(session, usage);
    return session_send_key_report(session);
}

bc_status bc_huawei_kvm_session_key(bc_huawei_kvm_session *session, uint32_t keysym, uint32_t down) {
    uint8_t modifiers = 0;
    uint32_t usage = bc_huawei_kvm_keysym_to_usage(keysym, &modifiers);
    if (!usage) return BC_UNSUPPORTED;
    return bc_huawei_kvm_session_key_usage(session, (uint8_t)usage, modifiers, down);
}

uint32_t bc_huawei_kvm_pointer_scale(uint32_t pixel, uint32_t extent) {
    if (!extent) return pixel > 3000 ? 3000 : pixel;
    uint64_t scaled = (uint64_t)pixel * 3000u / extent;
    return scaled > 3000 ? 3000 : (uint32_t)scaled;
}

static bc_status session_pointer_report(bc_huawei_kvm_session *session, uint16_t x, uint16_t y, uint8_t buttons) {
    bc_status status = session_require_input(session);
    if (status != BC_OK) return status;
    if (x > 3000) x = 3000;
    if (y > 3000) y = 3000;
    session->pointer_buttons = buttons;
    const uint8_t report[6] = {buttons, (uint8_t)(x >> 8), (uint8_t)x, (uint8_t)(y >> 8), (uint8_t)y, 0};
    return session_build_and_send_input(session, CMD_MOUSE, report, sizeof(report));
}

bc_status bc_huawei_kvm_session_pointer(bc_huawei_kvm_session *session, uint16_t x, uint16_t y, uint8_t buttons) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->frame_width && session->frame_height) {
        uint16_t scaled_x = (uint16_t)bc_huawei_kvm_pointer_scale(x, session->frame_width);
        uint16_t scaled_y = (uint16_t)bc_huawei_kvm_pointer_scale(y, session->frame_height);
        return session_pointer_report(session, scaled_x, scaled_y, buttons);
    }
    return session_pointer_report(session, x, y, buttons);
}

bc_status bc_huawei_kvm_session_pointer_device(bc_huawei_kvm_session *session, uint16_t x, uint16_t y,
                                               uint8_t buttons) {
    return session_pointer_report(session, x, y, buttons);
}

bc_status bc_huawei_kvm_session_pointer_delta(bc_huawei_kvm_session *session, int32_t dx, int32_t dy,
                                              uint8_t buttons) {
    bc_status status = session_require_input(session);
    if (status != BC_OK) return status;
    session->pointer_buttons = buttons;
    for (int step = 0; step < 8 && (dx || dy); ++step) {
        int32_t step_x = dx > 240 ? 240 : dx < -240 ? -240 : dx;
        int32_t step_y = dy > 240 ? 240 : dy < -240 ? -240 : dy;
        const uint8_t report[4] = {buttons, (uint8_t)(int8_t)step_x, (uint8_t)(int8_t)step_y, 0};
        status = session_build_and_send_input(session, CMD_MOUSE, report, sizeof(report));
        if (status != BC_OK) return status;
        dx -= step_x;
        dy -= step_y;
    }
    return BC_OK;
}

bc_status bc_huawei_kvm_session_mouse_mode(bc_huawei_kvm_session *session, uint32_t absolute) {
    if (!session) return BC_INVALID_ARGUMENT;
    uint8_t packet[16];
    uint32_t written = 0;
    bc_status status = bc_huawei_kvm_mouse_mode_packet(&session->params, absolute, packet, sizeof(packet), &written);
    if (status != BC_OK) return status;
    session->absolute_mode = absolute ? 1u : 0u;
    return session_send(session, packet, written);
}

bc_status bc_huawei_kvm_session_state(const bc_huawei_kvm_session *session, uint32_t *state) {
    if (!session || !state) return BC_INVALID_ARGUMENT;
    *state = session->state;
    return BC_OK;
}

bc_status bc_huawei_kvm_session_stats(const bc_huawei_kvm_session *session, bc_huawei_kvm_stats *stats) {
    if (!session || !stats || stats->struct_size != sizeof(*stats) || stats->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    *stats = session->stats;
    stats->struct_size = sizeof(*stats);
    stats->abi_version = BC_ABI_VERSION;
    return BC_OK;
}

bc_status bc_huawei_kvm_session_error(const bc_huawei_kvm_session *session, char *out, uint32_t capacity) {
    if (!session || !out || !capacity) return BC_INVALID_ARGUMENT;
    set_error(out, capacity, session->error);
    return BC_OK;
}

bc_status bc_huawei_kvm_session_vmm_request(bc_huawei_kvm_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_HUAWEI_KVM_STATE_STREAMING) return BC_BUSY;
    if ((session->keys.flags & BC_HUAWEI_KEY_CONTENT) == 0) return BC_BUSY;
    const uint8_t request[2] = {CMD_VMM_CODEKEY, 0};
    session->vmm.state = BC_HUAWEI_VMM_STATE_CONNECTING;
    session->vmm_stage = 1;
    return session_send_payload(session, request, sizeof(request));
}

bc_status bc_huawei_kvm_session_vmm_info(const bc_huawei_kvm_session *session, bc_huawei_vmm_info *info) {
    if (!session || !info) return BC_INVALID_ARGUMENT;
    if (session->vmm_stage != 6 && session->vmm_stage != 7) return BC_BUSY;
    *info = session->vmm;
    info->struct_size = sizeof(*info);
    return BC_OK;
}

void bc_huawei_kvm_session_destroy(bc_huawei_kvm_session *session) {
    if (!session) return;
    if (session->state == BC_HUAWEI_KVM_STATE_STREAMING &&
        (session->keys.flags & BC_HUAWEI_KEY_CONTENT) != 0) {
        const uint8_t zero_report[8] = {0};
        (void)session_build_and_send_input(session, CMD_KEYBOARD, zero_report, sizeof(zero_report));
        if (session->pointer_buttons) {
            const uint8_t zero_mouse[6] = {0};
            (void)session_build_and_send_input(session, CMD_MOUSE, zero_mouse, sizeof(zero_mouse));
        }
    }
    huawei_assembler_reset(&session->assembler);
    session->state = BC_HUAWEI_KVM_STATE_CLOSED;
    free(session);
}

const bc_service_profile *bc_huawei_kvm_session_profile_get(const bc_huawei_kvm_session *session) {
    return session ? &session->profile : NULL;
}

const bc_console_failure *bc_huawei_kvm_session_failure_get(const bc_huawei_kvm_session *session) {
    return session && session->failure.status != BC_OK ? &session->failure : NULL;
}

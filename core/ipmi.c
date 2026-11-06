#include "bcontrol/ipmi.h"
#include "bcontrol/wire.h"
#include <string.h>

#define BC_IPMI_PACKET_PREFIX (BC_IPMI_RMCP_HEADER_SIZE + BC_IPMI_SESSION_HEADER_SIZE)

static int bytes_valid(bc_bytes bytes) { return bytes.length == 0 || bytes.data; }
static uint8_t request_target(const bc_ipmi_request *r) { return r->target_address ? r->target_address : BC_IPMI_ADDRESS_BMC; }
static uint8_t request_source(const bc_ipmi_request *r) { return r->source_address ? r->source_address : BC_IPMI_ADDRESS_REMOTE_CONSOLE; }

bc_status bc_ipmi_message_encode(const bc_ipmi_request *r, uint8_t *out, uint64_t capacity, uint64_t *written) {
    if (!r || !out || !written || !bytes_valid(r->data)) return BC_INVALID_ARGUMENT;
    if (r->netfn > 0x3f || r->lun > 3 || r->sequence > 0x3f) return BC_INVALID_ARGUMENT;
    if (r->data.length > UINT64_MAX - 7) return BC_LIMIT_EXCEEDED;
    uint64_t need = r->data.length + 7;
    if (capacity < need) return BC_LIMIT_EXCEEDED;
    uint64_t len = 0;
    out[len++] = request_target(r);
    out[len++] = (uint8_t)((r->netfn << 2) | r->lun);
    out[len] = bc_wire_checksum(out, len);
    ++len;
    out[len++] = request_source(r);
    out[len++] = (uint8_t)(r->sequence << 2);
    out[len++] = r->command;
    if (r->data.length) { memcpy(out + len, r->data.data, (size_t)r->data.length); len += r->data.length; }
    out[len] = bc_wire_checksum(out + 3, len - 3);
    ++len;
    *written = len;
    return BC_OK;
}

bc_status bc_ipmi_message_decode(const uint8_t *data, uint64_t size, bc_ipmi_response *out) {
    if (!data || !out || size < 8) return BC_INVALID_ARGUMENT;
    if (data[2] != bc_wire_checksum(data, 2)) return BC_PROTOCOL_ERROR;
    if (data[size - 1] != bc_wire_checksum(data + 3, size - 4)) return BC_PROTOCOL_ERROR;
    bc_ipmi_response response = {0};
    response.target_address = data[0];
    response.netfn = (uint8_t)(data[1] >> 2);
    response.lun = (uint8_t)(data[1] & 3);
    response.source_address = data[3];
    response.sequence = (uint8_t)(data[4] >> 2);
    response.command = data[5];
    response.completion_code = data[6];
    response.data = (bc_bytes){data + 7, size - 8};
    *out = response;
    return BC_OK;
}

bc_status bc_ipmi_packet_encode(const bc_ipmi_packet *packet, uint8_t *out, uint64_t capacity, uint32_t *written) {
    if (!packet || !out || !written || !bytes_valid(packet->payload)) return BC_INVALID_ARGUMENT;
    if (packet->payload_type > BC_IPMI_PAYLOAD_TYPE_MASK) return BC_INVALID_ARGUMENT;
    if (packet->flags & (uint8_t)~(BC_IPMI_PAYLOAD_FLAG_ENCRYPTED | BC_IPMI_PAYLOAD_FLAG_AUTHENTICATED)) return BC_INVALID_ARGUMENT;
    if (packet->auth_type != BC_IPMI_AUTH_TYPE_NONE && packet->auth_type != BC_IPMI_AUTH_TYPE_RMCP_PLUS) return BC_INVALID_ARGUMENT;
    if (packet->payload.length > UINT16_MAX || packet->payload_length != packet->payload.length) return BC_LIMIT_EXCEEDED;
    uint64_t need = BC_IPMI_PACKET_PREFIX + packet->payload.length;
    if (capacity < need) return BC_LIMIT_EXCEEDED;
    out[0] = BC_IPMI_RMCP_VERSION;
    out[1] = 0;
    out[2] = BC_IPMI_RMCP_SEQUENCE_NO_ACK;
    out[3] = BC_IPMI_RMCP_CLASS_IPMI;
    out[4] = packet->auth_type;
    out[5] = (uint8_t)(packet->payload_type | packet->flags);
    bc_wire_write_le(out + 6, packet->session_id, 4);
    bc_wire_write_le(out + 10, packet->sequence, 4);
    bc_wire_write_le(out + 14, packet->payload.length, 2);
    if (packet->payload.length) memmove(out + BC_IPMI_PACKET_PREFIX, packet->payload.data, (size_t)packet->payload.length);
    *written = (uint32_t)need;
    return BC_OK;
}

bc_status bc_ipmi_packet_decode(const uint8_t *data, uint64_t size, bc_ipmi_packet *out) {
    if (!data || !out || size < BC_IPMI_PACKET_PREFIX) return BC_INVALID_ARGUMENT;
    if (data[0] != BC_IPMI_RMCP_VERSION || (data[3] & 0x1f) != BC_IPMI_RMCP_CLASS_IPMI) return BC_PROTOCOL_ERROR;
    uint16_t length = (uint16_t)bc_wire_read_le(data + 14, 2);
    if (size < BC_IPMI_PACKET_PREFIX + (uint64_t)length) return BC_PROTOCOL_ERROR;
    bc_ipmi_packet packet = {0};
    packet.auth_type = data[4];
    packet.flags = (uint8_t)(data[5] & (uint8_t)~BC_IPMI_PAYLOAD_TYPE_MASK);
    packet.payload_type = (uint8_t)(data[5] & BC_IPMI_PAYLOAD_TYPE_MASK);
    packet.session_id = (uint32_t)bc_wire_read_le(data + 6, 4);
    packet.sequence = (uint32_t)bc_wire_read_le(data + 10, 4);
    packet.payload_length = length;
    packet.payload = (bc_bytes){data + BC_IPMI_PACKET_PREFIX, length};
    *out = packet;
    return BC_OK;
}

bc_status bc_ipmi_sessionless_encode(const bc_ipmi_request *r, uint8_t *out, uint64_t capacity, uint32_t *written) {
    if (!r || !out || !written || !bytes_valid(r->data)) return BC_INVALID_ARGUMENT;
    if (r->data.length > UINT16_MAX - 7 || capacity < BC_IPMI_PACKET_PREFIX + r->data.length + 7) return BC_LIMIT_EXCEEDED;
    uint64_t message_length = 0;
    bc_status status = bc_ipmi_message_encode(r, out + BC_IPMI_PACKET_PREFIX, capacity - BC_IPMI_PACKET_PREFIX, &message_length);
    if (status != BC_OK) return status;
    bc_ipmi_packet packet = {0};
    packet.auth_type = BC_IPMI_AUTH_TYPE_RMCP_PLUS;
    packet.payload_type = BC_IPMI_PAYLOAD_IPMI;
    packet.payload_length = (uint16_t)message_length;
    packet.payload = (bc_bytes){out + BC_IPMI_PACKET_PREFIX, message_length};
    return bc_ipmi_packet_encode(&packet, out, capacity, written);
}

bc_status bc_ipmi_sessionless_decode(const uint8_t *data, uint64_t size, bc_ipmi_response *out) {
    if (!data || !out) return BC_INVALID_ARGUMENT;
    bc_ipmi_packet packet;
    bc_status status = bc_ipmi_packet_decode(data, size, &packet);
    if (status != BC_OK) return status;
    if (packet.auth_type != BC_IPMI_AUTH_TYPE_RMCP_PLUS || packet.payload_type != BC_IPMI_PAYLOAD_IPMI ||
        packet.session_id || packet.sequence || packet.flags || size != BC_IPMI_PACKET_PREFIX + (uint64_t)packet.payload_length)
        return BC_PROTOCOL_ERROR;
    return bc_ipmi_message_decode(packet.payload.data, packet.payload.length, out);
}

bc_status bc_ipmi_cipher_suites_request(uint8_t channel, uint8_t list_index, uint8_t sequence, uint8_t *out, uint64_t capacity, uint32_t *written) {
    if (!out || !written || list_index > 0x3f) return BC_INVALID_ARGUMENT;
    uint8_t data[3] = {channel, BC_IPMI_PAYLOAD_IPMI, (uint8_t)(BC_IPMI_CIPHER_LIST_ALL | list_index)};
    bc_ipmi_request request = {0};
    request.netfn = BC_IPMI_NETFN_APP;
    request.sequence = sequence;
    request.command = BC_IPMI_CMD_GET_CHANNEL_CIPHER_SUITES;
    request.data = (bc_bytes){data, sizeof(data)};
    return bc_ipmi_sessionless_encode(&request, out, capacity, written);
}

bc_status bc_ipmi_cipher_suites_parse(const bc_ipmi_response *response, bc_ipmi_cipher_suites *out) {
    if (!response || !out || !bytes_valid(response->data)) return BC_INVALID_ARGUMENT;
    if (response->completion_code != BC_IPMI_COMPLETION_OK) return BC_PROTOCOL_ERROR;
    if (response->data.length < 1) return BC_PROTOCOL_ERROR;
    memset(out, 0, sizeof(*out));
    out->channel = response->data.data[0];
    const uint8_t *record = response->data.data + 1;
    uint64_t left = response->data.length - 1;
    while (left) {
        if (out->count >= BC_IPMI_MAX_CIPHER_SUITES) return BC_LIMIT_EXCEEDED;
        bc_ipmi_cipher_suite suite = {0};
        uint64_t length;
        if (record[0] == 0xC0) {
            length = 5;
            if (left < length) return BC_PROTOCOL_ERROR;
            suite.cipher_suite_id = record[1];
            suite.auth_algorithm = (uint8_t)(record[2] & 0x3f);
            suite.integrity_algorithm = (uint8_t)(record[3] & 0x3f);
            suite.confidentiality_algorithm = (uint8_t)(record[4] & 0x3f);
        } else if (record[0] == 0xC1) {
            length = 8;
            if (left < length) return BC_PROTOCOL_ERROR;
            suite.flags = BC_IPMI_CIPHER_SUITE_OEM;
            suite.cipher_suite_id = record[1];
            suite.iana = (uint32_t)bc_wire_read_le(record + 2, 3);
            suite.auth_algorithm = (uint8_t)(record[5] & 0x3f);
            suite.integrity_algorithm = (uint8_t)(record[6] & 0x3f);
            suite.confidentiality_algorithm = (uint8_t)(record[7] & 0x3f);
        } else {
            return BC_PROTOCOL_ERROR;
        }
        out->suites[out->count++] = suite;
        record += length;
        left -= length;
    }
    return BC_OK;
}

static const bc_ipmi_cipher_suite_definition standard_suites[] = {
    {0, BC_IPMI_AUTH_ALG_NONE, BC_IPMI_INTEGRITY_ALG_NONE, BC_IPMI_CONFIDENTIALITY_ALG_NONE},
    {1, BC_IPMI_AUTH_ALG_HMAC_SHA1, BC_IPMI_INTEGRITY_ALG_NONE, BC_IPMI_CONFIDENTIALITY_ALG_NONE},
    {2, BC_IPMI_AUTH_ALG_HMAC_SHA1, BC_IPMI_INTEGRITY_ALG_HMAC_SHA1_96, BC_IPMI_CONFIDENTIALITY_ALG_NONE},
    {3, BC_IPMI_AUTH_ALG_HMAC_SHA1, BC_IPMI_INTEGRITY_ALG_HMAC_SHA1_96, BC_IPMI_CONFIDENTIALITY_ALG_AES_CBC_128},
    {4, BC_IPMI_AUTH_ALG_HMAC_SHA1, BC_IPMI_INTEGRITY_ALG_HMAC_SHA1_96, BC_IPMI_CONFIDENTIALITY_ALG_XRC4_128},
    {5, BC_IPMI_AUTH_ALG_HMAC_SHA1, BC_IPMI_INTEGRITY_ALG_HMAC_SHA1_96, BC_IPMI_CONFIDENTIALITY_ALG_XRC4_40},
    {6, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_NONE, BC_IPMI_CONFIDENTIALITY_ALG_NONE},
    {7, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_HMAC_MD5_128, BC_IPMI_CONFIDENTIALITY_ALG_NONE},
    {8, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_HMAC_MD5_128, BC_IPMI_CONFIDENTIALITY_ALG_AES_CBC_128},
    {9, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_HMAC_MD5_128, BC_IPMI_CONFIDENTIALITY_ALG_XRC4_128},
    {10, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_HMAC_MD5_128, BC_IPMI_CONFIDENTIALITY_ALG_XRC4_40},
    {11, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_MD5_128, BC_IPMI_CONFIDENTIALITY_ALG_NONE},
    {12, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_MD5_128, BC_IPMI_CONFIDENTIALITY_ALG_AES_CBC_128},
    {13, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_MD5_128, BC_IPMI_CONFIDENTIALITY_ALG_XRC4_128},
    {14, BC_IPMI_AUTH_ALG_HMAC_MD5, BC_IPMI_INTEGRITY_ALG_MD5_128, BC_IPMI_CONFIDENTIALITY_ALG_XRC4_40},
    {15, BC_IPMI_AUTH_ALG_HMAC_SHA256, BC_IPMI_INTEGRITY_ALG_NONE, BC_IPMI_CONFIDENTIALITY_ALG_NONE},
    {16, BC_IPMI_AUTH_ALG_HMAC_SHA256, BC_IPMI_INTEGRITY_ALG_HMAC_SHA256_128, BC_IPMI_CONFIDENTIALITY_ALG_NONE},
    {17, BC_IPMI_AUTH_ALG_HMAC_SHA256, BC_IPMI_INTEGRITY_ALG_HMAC_SHA256_128, BC_IPMI_CONFIDENTIALITY_ALG_AES_CBC_128},
};

const bc_ipmi_cipher_suite_definition *bc_ipmi_standard_cipher_suite(uint32_t id) {
    for (unsigned i = 0; i < sizeof(standard_suites) / sizeof(standard_suites[0]); ++i)
        if (standard_suites[i].cipher_suite_id == id) return &standard_suites[i];
    return NULL;
}

static const bc_ipmi_cipher_suite *find_suite(const bc_ipmi_cipher_suites *available, uint32_t id, int *inconsistent) {
    for (uint32_t i = 0; i < available->count && i < BC_IPMI_MAX_CIPHER_SUITES; ++i) {
        const bc_ipmi_cipher_suite *suite = &available->suites[i];
        if ((suite->flags & BC_IPMI_CIPHER_SUITE_OEM) || suite->cipher_suite_id != id) continue;
        const bc_ipmi_cipher_suite_definition *definition = bc_ipmi_standard_cipher_suite(id);
        if (!definition) return NULL;
        if (suite->auth_algorithm != definition->auth_algorithm ||
            suite->integrity_algorithm != definition->integrity_algorithm ||
            suite->confidentiality_algorithm != definition->confidentiality_algorithm) {
            *inconsistent = 1;
            return NULL;
        }
        return suite;
    }
    return NULL;
}

bc_status bc_ipmi_select_cipher_suite(const bc_ipmi_cipher_suites *available, uint32_t suite3_policy, bc_ipmi_suite_selection *out) {
    if (!available || !out || available->count > BC_IPMI_MAX_CIPHER_SUITES) return BC_INVALID_ARGUMENT;
    if (suite3_policy > BC_IPMI_SUITE3_CONFIRMED) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    int inconsistent = 0;
    const bc_ipmi_cipher_suite *preferred = find_suite(available, 17, &inconsistent);
    if (preferred) {
        out->cipher_suite_id = 17;
        out->auth_algorithm = preferred->auth_algorithm;
        out->integrity_algorithm = preferred->integrity_algorithm;
        out->confidentiality_algorithm = preferred->confidentiality_algorithm;
        return BC_OK;
    }
    const bc_ipmi_cipher_suite *fallback = find_suite(available, 3, &inconsistent);
    if (inconsistent) return BC_PROTOCOL_ERROR;
    if (!fallback || suite3_policy == BC_IPMI_SUITE3_DISALLOWED) return BC_UNSUPPORTED;
    out->cipher_suite_id = 3;
    out->auth_algorithm = fallback->auth_algorithm;
    out->integrity_algorithm = fallback->integrity_algorithm;
    out->confidentiality_algorithm = fallback->confidentiality_algorithm;
    out->flags = suite3_policy == BC_IPMI_SUITE3_ALLOWED ? BC_IPMI_SUITE_CONFIRMATION_REQUIRED : 0;
    return BC_OK;
}

static bc_status known_auth_code_size(uint8_t algorithm, uint32_t *size) {
    switch (algorithm) {
    case BC_IPMI_AUTH_ALG_NONE: *size = 0; return BC_OK;
    case BC_IPMI_AUTH_ALG_HMAC_SHA1: *size = 20; return BC_OK;
    case BC_IPMI_AUTH_ALG_HMAC_MD5: *size = 16; return BC_OK;
    case BC_IPMI_AUTH_ALG_HMAC_SHA256: *size = 32; return BC_OK;
    default: return BC_UNSUPPORTED;
    }
}

static bc_status known_integrity_code_size(uint8_t algorithm, uint32_t *size) {
    switch (algorithm) {
    case BC_IPMI_INTEGRITY_ALG_NONE: *size = 0; return BC_OK;
    case BC_IPMI_INTEGRITY_ALG_HMAC_SHA1_96: *size = 12; return BC_OK;
    case BC_IPMI_INTEGRITY_ALG_HMAC_MD5_128: *size = 16; return BC_OK;
    case BC_IPMI_INTEGRITY_ALG_MD5_128: *size = 16; return BC_OK;
    case BC_IPMI_INTEGRITY_ALG_HMAC_SHA256_128: *size = 16; return BC_OK;
    default: return BC_UNSUPPORTED;
    }
}

uint32_t bc_ipmi_auth_code_size(uint8_t algorithm) {
    uint32_t size = 0;
    return known_auth_code_size(algorithm, &size) == BC_OK ? size : 0;
}

uint32_t bc_ipmi_integrity_code_size(uint8_t algorithm) {
    uint32_t size = 0;
    return known_integrity_code_size(algorithm, &size) == BC_OK ? size : 0;
}

bc_status bc_ipmi_open_session_request_encode(const bc_ipmi_open_session_request *request, uint8_t *out, uint64_t capacity) {
    if (!request || !out) return BC_INVALID_ARGUMENT;
    if (capacity < BC_IPMI_OPEN_SESSION_REQUEST_SIZE) return BC_LIMIT_EXCEEDED;
    if (request->maximum_privilege > 0x1f) return BC_INVALID_ARGUMENT;
    memset(out, 0, BC_IPMI_OPEN_SESSION_REQUEST_SIZE);
    out[0] = request->message_tag;
    out[1] = request->maximum_privilege;
    bc_wire_write_le(out + 4, request->console_session_id, 4);
    const uint8_t algorithms[3] = {request->auth_algorithm, request->integrity_algorithm, request->confidentiality_algorithm};
    for (unsigned i = 0; i < 3; ++i) {
        uint8_t *payload = out + 8 + i * 8;
        payload[0] = (uint8_t)i;
        payload[3] = 8;
        payload[4] = algorithms[i];
    }
    return BC_OK;
}

bc_status bc_ipmi_open_session_response_decode(const uint8_t *data, uint64_t size, bc_ipmi_open_session_response *out) {
    if (!data || !out || size < 8) return BC_INVALID_ARGUMENT;
    bc_ipmi_open_session_response response = {0};
    response.message_tag = data[0];
    response.status = data[1];
    response.maximum_privilege = (uint8_t)(data[2] & 0x0f);
    response.console_session_id = (uint32_t)bc_wire_read_le(data + 4, 4);
    if (response.status != BC_IPMI_COMPLETION_OK) { *out = response; return BC_OK; }
    if (size < BC_IPMI_OPEN_SESSION_RESPONSE_SIZE) return BC_PROTOCOL_ERROR;
    response.bmc_session_id = (uint32_t)bc_wire_read_le(data + 8, 4);
    uint8_t algorithms[3] = {0};
    for (unsigned i = 0; i < 3; ++i) {
        const uint8_t *payload = data + 12 + i * 8;
        if (payload[0] != i || payload[3] != 8) return BC_PROTOCOL_ERROR;
        algorithms[i] = (uint8_t)(payload[4] & 0x3f);
    }
    response.auth_algorithm = algorithms[0];
    response.integrity_algorithm = algorithms[1];
    response.confidentiality_algorithm = algorithms[2];
    *out = response;
    return BC_OK;
}

bc_status bc_ipmi_rakp1_encode(const bc_ipmi_rakp1 *message, uint8_t *out, uint64_t capacity, uint64_t *written) {
    if (!message || !out || !written || !message->console_random) return BC_INVALID_ARGUMENT;
    if (message->user_name.length > BC_IPMI_MAX_USER_NAME || (message->user_name.length && !message->user_name.data)) return BC_INVALID_ARGUMENT;
    if (message->requested_privilege > 0x1f) return BC_INVALID_ARGUMENT;
    uint64_t need = BC_IPMI_RAKP1_FIXED_SIZE + message->user_name.length;
    if (capacity < need) return BC_LIMIT_EXCEEDED;
    memset(out, 0, BC_IPMI_RAKP1_FIXED_SIZE);
    out[0] = message->message_tag;
    bc_wire_write_le(out + 4, message->bmc_session_id, 4);
    memcpy(out + 8, message->console_random, BC_IPMI_RANDOM_SIZE);
    out[24] = message->requested_privilege;
    out[27] = (uint8_t)message->user_name.length;
    memcpy(out + BC_IPMI_RAKP1_FIXED_SIZE, message->user_name.data, (size_t)message->user_name.length);
    *written = need;
    return BC_OK;
}

bc_status bc_ipmi_rakp2_decode(const uint8_t *data, uint64_t size, uint8_t auth_algorithm, bc_ipmi_rakp2 *out) {
    if (!data || !out || size < BC_IPMI_RAKP2_FIXED_SIZE) return BC_INVALID_ARGUMENT;
    uint32_t auth_code_size = 0;
    bc_status status = known_auth_code_size(auth_algorithm, &auth_code_size);
    if (status != BC_OK) return status;
    bc_ipmi_rakp2 message = {0};
    message.message_tag = data[0];
    message.status = data[1];
    message.console_session_id = (uint32_t)bc_wire_read_le(data + 4, 4);
    message.bmc_random = (bc_bytes){data + 8, BC_IPMI_RANDOM_SIZE};
    message.bmc_guid = (bc_bytes){data + 24, BC_IPMI_GUID_SIZE};
    if (message.status == BC_IPMI_COMPLETION_OK) {
        if (size != BC_IPMI_RAKP2_FIXED_SIZE + auth_code_size) return BC_PROTOCOL_ERROR;
        message.auth_code = (bc_bytes){data + BC_IPMI_RAKP2_FIXED_SIZE, auth_code_size};
    }
    *out = message;
    return BC_OK;
}

bc_status bc_ipmi_rakp3_encode(const bc_ipmi_rakp3 *message, uint8_t *out, uint64_t capacity, uint64_t *written) {
    if (!message || !out || !written || !bytes_valid(message->auth_code)) return BC_INVALID_ARGUMENT;
    uint32_t auth_code_size = 0;
    bc_status status = known_auth_code_size(message->auth_algorithm, &auth_code_size);
    if (status != BC_OK) return status;
    if (message->status == BC_IPMI_COMPLETION_OK ? message->auth_code.length != auth_code_size : message->auth_code.length != 0)
        return BC_INVALID_ARGUMENT;
    uint64_t need = BC_IPMI_RAKP3_FIXED_SIZE + message->auth_code.length;
    if (capacity < need) return BC_LIMIT_EXCEEDED;
    memset(out, 0, BC_IPMI_RAKP3_FIXED_SIZE);
    out[0] = message->message_tag;
    out[1] = message->status;
    bc_wire_write_le(out + 4, message->bmc_session_id, 4);
    if (message->auth_code.length) memcpy(out + BC_IPMI_RAKP3_FIXED_SIZE, message->auth_code.data, (size_t)message->auth_code.length);
    *written = need;
    return BC_OK;
}

bc_status bc_ipmi_rakp4_decode(const uint8_t *data, uint64_t size, uint8_t integrity_algorithm, bc_ipmi_rakp4 *out) {
    if (!data || !out || size < BC_IPMI_RAKP4_FIXED_SIZE) return BC_INVALID_ARGUMENT;
    uint32_t integrity_code_size = 0;
    bc_status status = known_integrity_code_size(integrity_algorithm, &integrity_code_size);
    if (status != BC_OK) return status;
    bc_ipmi_rakp4 message = {0};
    message.message_tag = data[0];
    message.status = data[1];
    message.console_session_id = (uint32_t)bc_wire_read_le(data + 4, 4);
    if (message.status == BC_IPMI_COMPLETION_OK) {
        if (size != BC_IPMI_RAKP4_FIXED_SIZE + integrity_code_size) return BC_PROTOCOL_ERROR;
        message.integrity_check_value = (bc_bytes){data + BC_IPMI_RAKP4_FIXED_SIZE, integrity_code_size};
    }
    *out = message;
    return BC_OK;
}

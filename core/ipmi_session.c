#include "ipmi_session_internal.h"
#include "../adapters/ilom/profile.h"
#include "bcontrol/wire.h"
#include "log_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BC_IPMI_MAX_DATAGRAM 4096u
#define BC_IPMI_MAX_MESSAGE 1024u
#define BC_IPMI_MAX_RECORDS (64u * 16u)
#define BC_IPMI_CMD_GET_CHANNEL_AUTH_CAPABILITIES 0x38u

struct bc_ipmi_session {
    const bc_ipmi_io *io;
    const bc_ipmi_crypto *crypto;
    uint32_t timeout_ms;
    uint32_t retries;
    uint32_t channel;
    uint32_t suite3_policy;
    uint8_t username[BC_IPMI_MAX_USER_NAME];
    uint8_t username_length;
    uint8_t password[BC_IPMI_MAX_PASSWORD];
    bc_ipmi_cipher_suites discovered;
    bc_ipmi_suite_selection selection;
    bc_ipmi_session_info info;
    uint8_t console_random[BC_IPMI_RANDOM_SIZE];
    uint8_t bmc_random[BC_IPMI_RANDOM_SIZE];
    uint8_t bmc_guid[BC_IPMI_GUID_SIZE];
    uint8_t sik[32], k1[32], k2[32];
    uint32_t sik_length, k1_length, k2_length;
    uint32_t send_sequence;
    uint8_t message_sequence;
    uint8_t message_tag;
    uint8_t discovered_done;
    uint8_t fallback_suite3;
    uint8_t opened;
    uint8_t command_busy;
    uint8_t open_session_done;
    uint8_t padded_handshake;
    uint32_t receive_high;
    uint64_t receive_window;
    void *payload_owner;
    bc_ipmi_payload_handler payload_handler;
};

static void secure_clear(void *data, size_t length) {
    volatile uint8_t *bytes = data;
    while (length--) *bytes++ = 0;
}

static int constant_time_equal(const uint8_t *left, const uint8_t *right, uint32_t length) {
    uint8_t difference = 0;
    while (length--) difference |= (uint8_t)(*left++ ^ *right++);
    return difference == 0;
}

static int bytes_valid(bc_bytes bytes) { return bytes.length == 0 || bytes.data; }

#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_VERBOSE
static int sensitive_command(uint8_t netfn, uint8_t command, uint64_t length, int mutating) {
    if(mutating)return 1;
    switch(netfn){
    case BC_IPMI_NETFN_CHASSIS:
        return length!=0||(command!=BC_IPMI_CMD_GET_CHASSIS_CAPABILITIES&&command!=BC_IPMI_CMD_GET_CHASSIS_STATUS&&
            command!=BC_IPMI_CMD_GET_SYSTEM_RESTART_CAUSE);
    case BC_IPMI_NETFN_SENSOR:
        return command!=BC_IPMI_CMD_GET_SENSOR_READING||length!=1;
    case BC_IPMI_NETFN_APP:
        return !((command==BC_IPMI_CMD_GET_DEVICE_ID&&length==0)||(command==BC_IPMI_CMD_GET_CHANNEL_CIPHER_SUITES&&length==3));
    case BC_IPMI_NETFN_STORAGE:
        switch(command){
        case BC_IPMI_CMD_GET_SDR_REPOSITORY_INFO:case BC_IPMI_CMD_RESERVE_SDR_REPOSITORY:
        case BC_IPMI_CMD_GET_SEL_INFO:case BC_IPMI_CMD_RESERVE_SEL:return length!=0;
        case BC_IPMI_CMD_GET_SDR:case BC_IPMI_CMD_GET_SEL_ENTRY:return length!=6;
        case BC_IPMI_CMD_GET_FRU_INVENTORY_AREA_INFO:return length!=1;
        case BC_IPMI_CMD_READ_FRU_DATA:return length!=4;
        default:return 1;
        }
    default:return 1;
    }
}
#endif
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_INFO
static void suite_list(char *out, size_t capacity, const bc_ipmi_cipher_suites *suites) {
    size_t used = 0;
    if (!capacity) return;
    out[0] = 0;
    for (uint32_t i = 0; i < suites->count && used + 8 < capacity; ++i) {
        int written = snprintf(out + used, capacity - used, i ? ",%u" : "%u", suites->suites[i].cipher_suite_id);
        if (written < 0) break;
        used += (size_t)written;
    }
}
#endif

static int io_valid(const bc_ipmi_io *io) {
    return io && io->struct_size == sizeof(*io) && io->abi_version == BC_ABI_VERSION && io->send && io->receive;
}

static int crypto_valid(const bc_ipmi_crypto *crypto) {
    return crypto && crypto->struct_size == sizeof(*crypto) && crypto->abi_version == BC_ABI_VERSION &&
        crypto->hmac && crypto->encrypt && crypto->decrypt && crypto->random;
}

static bc_status compute_hmac(bc_ipmi_session *session, uint8_t algorithm, const uint8_t *key, uint32_t key_length,
    const uint8_t *data, uint32_t data_length, uint8_t *out, uint32_t *out_length) {
    return session->crypto->hmac(session->crypto->userdata, algorithm, key, key_length, data, data_length, out, out_length);
}

static bc_status next_random(bc_ipmi_session *session, uint8_t *out, uint32_t length) {
    return session->crypto->random(session->crypto->userdata, out, length);
}

static uint8_t next_tag(bc_ipmi_session *session) {
    uint8_t tag = session->message_tag;
    session->message_tag = (uint8_t)(tag + 1);
    return tag;
}

static uint8_t next_message_sequence(bc_ipmi_session *session) {
    session->message_sequence = (uint8_t)((session->message_sequence + 1) & 0x3f);
    return session->message_sequence;
}

static bc_status handshake_attempts(bc_ipmi_session *session, uint8_t payload_type, uint8_t response_type,
    const uint8_t *payload, uint16_t payload_length, uint8_t *response, uint32_t capacity, uint16_t *response_length,
    uint32_t attempts) {
    uint8_t datagram[BC_IPMI_MAX_DATAGRAM];
    for (uint32_t attempt = 0; attempt < attempts; ++attempt) {
        BC_LOG_TRACE(BC_LOG_CATEGORY_IPMI, "ipmi.handshake.send",
            "payload=%u response=%u attempt=%u len=%u", payload_type, response_type, attempt + 1, payload_length);
        bc_ipmi_packet packet = {0};
        packet.auth_type = BC_IPMI_AUTH_TYPE_RMCP_PLUS;
        packet.payload_type = payload_type;
        packet.payload_length = payload_length;
        packet.payload = (bc_bytes){payload, payload_length};
        uint32_t datagram_length = 0;
        bc_status status = bc_ipmi_packet_encode(&packet, datagram, sizeof(datagram), &datagram_length);
        if (status != BC_OK) return status;
        status = session->io->send(session->io->userdata, datagram, datagram_length);
        if (status != BC_OK) return status;
        for (;;) {
            uint8_t incoming[BC_IPMI_MAX_DATAGRAM];
            uint32_t received = 0;
            status = session->io->receive(session->io->userdata, incoming, sizeof(incoming), &received, session->timeout_ms);
            if (status == BC_TIMEOUT) break;
            if (status != BC_OK) return status;
            bc_ipmi_packet decoded;
            if (bc_ipmi_packet_decode(incoming, received, &decoded) != BC_OK) continue;
            if (decoded.auth_type != BC_IPMI_AUTH_TYPE_RMCP_PLUS || decoded.payload_type != response_type || decoded.session_id) continue;
            if (decoded.payload_length > capacity) return BC_LIMIT_EXCEEDED;
            memcpy(response, decoded.payload.data, decoded.payload_length);
            *response_length = decoded.payload_length;
            BC_LOG_TRACE(BC_LOG_CATEGORY_IPMI, "ipmi.handshake.receive",
                "payload=%u attempt=%u len=%u", response_type, attempt + 1, decoded.payload_length);
            return BC_OK;
        }
    }
    BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.handshake_timeout",
        "payload=%u response=%u attempts=%u timeout_ms=%u", payload_type, response_type, attempts, session->timeout_ms);
    return BC_TIMEOUT;
}

static bc_status handshake(bc_ipmi_session *session, uint8_t payload_type, uint8_t response_type,
    const uint8_t *payload, uint16_t payload_length, uint8_t *response, uint32_t capacity, uint16_t *response_length) {
    return handshake_attempts(session, payload_type, response_type, payload, payload_length, response, capacity,
        response_length, session->retries ? session->retries : 1);
}

/* Get Channel Authentication Capabilities is defined for RMCP 1.5 framing and
 * works before an RMCP+ session exists.  Bit 7 of the channel byte requests the
 * IPMI 2.0 extended capability data; a response alone does not mean the
 * endpoint is IPMI 1.5-only, because IPMI 2.0 endpoints normally keep the 1.5
 * listener enabled.  Only the v2.0 capability bits decide that question. */
static bc_status auth_capabilities_exchange(bc_ipmi_session *session, uint8_t channel_byte,
    uint8_t *data, uint32_t capacity, uint32_t *data_length) {
    uint8_t message[32], datagram[BC_IPMI_MAX_DATAGRAM];
    bc_ipmi_request request = {0};
    uint8_t request_data[2] = {channel_byte, BC_IPMI_PRIVILEGE_ADMINISTRATOR};
    request.netfn = BC_IPMI_NETFN_APP;
    request.command = BC_IPMI_CMD_GET_CHANNEL_AUTH_CAPABILITIES;
    request.data = (bc_bytes){request_data, sizeof(request_data)};
    uint64_t message_length = 0;
    bc_status status = bc_ipmi_message_encode(&request, message, sizeof(message), &message_length);
    if (status != BC_OK) return status;
    uint32_t length = 0;
    datagram[length++] = BC_IPMI_RMCP_VERSION; datagram[length++] = 0;
    datagram[length++] = BC_IPMI_RMCP_SEQUENCE_NO_ACK; datagram[length++] = BC_IPMI_RMCP_CLASS_IPMI;
    datagram[length++] = BC_IPMI_AUTH_TYPE_NONE;
    memset(datagram + length, 0, 8); length += 8;
    datagram[length++] = (uint8_t)message_length;
    if (length + message_length > sizeof(datagram)) return BC_LIMIT_EXCEEDED;
    memcpy(datagram + length, message, (size_t)message_length); length += (uint32_t)message_length;
    status = session->io->send(session->io->userdata, datagram, length);
    if (status != BC_OK) return status;
    for (;;) {
        uint8_t incoming[BC_IPMI_MAX_DATAGRAM];
        uint32_t received = 0;
        status = session->io->receive(session->io->userdata, incoming, sizeof(incoming), &received, session->timeout_ms);
        if (status != BC_OK) return status;
        if (received < 14 || incoming[0] != BC_IPMI_RMCP_VERSION || incoming[3] != BC_IPMI_RMCP_CLASS_IPMI ||
            incoming[4] != BC_IPMI_AUTH_TYPE_NONE) continue;
        uint8_t payload_length = incoming[13];
        if ((uint64_t)received < 14u + payload_length) continue;
        bc_ipmi_response response;
        if (bc_ipmi_message_decode(incoming + 14, payload_length, &response) != BC_OK) continue;
        if (response.command != BC_IPMI_CMD_GET_CHANNEL_AUTH_CAPABILITIES) continue;
        if (response.completion_code != BC_IPMI_COMPLETION_OK) return BC_UNSUPPORTED;
        if (response.data.length > capacity) return BC_LIMIT_EXCEEDED;
        if (response.data.length) memcpy(data, response.data.data, (size_t)response.data.length);
        *data_length = (uint32_t)response.data.length;
        return BC_OK;
    }
}

/* Reports whether the endpoint advertises IPMI 2.0 on this channel.  The probe
 * itself is best-effort: a failure only means the question cannot be answered,
 * not that the endpoint is IPMI 1.5-only. */
static bc_status probe_auth_capabilities(bc_ipmi_session *session, int *ipmi_v2_supported) {
    uint8_t data[16];
    uint32_t length = 0;
    *ipmi_v2_supported = 0;
    int requested_v2 = 1;
    bc_status status = auth_capabilities_exchange(session, (uint8_t)(session->channel | 0x80), data, sizeof(data), &length);
    if (status != BC_OK) {
        requested_v2 = 0;
        status = auth_capabilities_exchange(session, (uint8_t)session->channel, data, sizeof(data), &length);
    }
    if (status != BC_OK) {
        BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.auth_capabilities", "channel=%u status=%s",
            session->channel, bc_status_string(status));
        return status;
    }
    if (length < 2) return BC_PROTOCOL_ERROR;
    int v2_data_available = (data[1] & 0x80) != 0;
    int v2_connection_support = length < 4 || (data[3] & 0x02) != 0;
    *ipmi_v2_supported = requested_v2 && v2_data_available && v2_connection_support ? 1 :
        length >= 4 && (data[3] & 0x01) && !(data[3] & 0x02) ? 0 : -1;
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.auth_capabilities",
        "channel=%u v2_data=%u v15_support=%u v20_support=%u requested_v2=%u result=%s",
        data[0] & 0x0f, v2_data_available, length < 4 ? 0 : (data[3] & 0x01) != 0,
        length < 4 ? 0 : (data[3] & 0x02) != 0, requested_v2,
        *ipmi_v2_supported > 0 ? "ipmi_v2" : *ipmi_v2_supported == 0 ? "ipmi_v1_5" : "unknown");
    return BC_OK;
}

static bc_status discover_cipher_suites(bc_ipmi_session *session) {
    if (session->discovered_done) return BC_OK;
    uint8_t combined[1 + BC_IPMI_MAX_RECORDS] = {0};
    uint64_t combined_length = 1;
    uint8_t channel = 0;
    for (uint32_t index = 0; index < 0x40; ++index) {
        uint8_t request_data[3] = {session->channel, BC_IPMI_PAYLOAD_IPMI,
            (uint8_t)(BC_IPMI_CIPHER_LIST_ALL | (index & 0x3f))};
        bc_ipmi_request request = {0};
        request.netfn = BC_IPMI_NETFN_APP;
        request.sequence = next_message_sequence(session);
        request.command = BC_IPMI_CMD_GET_CHANNEL_CIPHER_SUITES;
        request.data = (bc_bytes){request_data, sizeof(request_data)};
        uint8_t message[32];
        uint64_t message_length = 0;
        bc_status status = bc_ipmi_message_encode(&request, message, sizeof(message), &message_length);
        if (status != BC_OK) return status;
        uint8_t payload[BC_IPMI_MAX_DATAGRAM];
        uint16_t payload_length = 0;
        /* Cipher suite discovery is optional metadata: many BMCs answer RMCP+
         * Open Session but not this pre-session query.  A single attempt keeps
         * the unavoidable timeout off the connection path; the session
         * handshake itself still retries. */
        status = handshake_attempts(session, BC_IPMI_PAYLOAD_IPMI, BC_IPMI_PAYLOAD_IPMI, message,
            (uint16_t)message_length, payload, sizeof(payload), &payload_length, 1);
        if (status != BC_OK) return status;
        bc_ipmi_response response;
        status = bc_ipmi_message_decode(payload, payload_length, &response);
        if (status != BC_OK) return status;
        if (response.command != BC_IPMI_CMD_GET_CHANNEL_CIPHER_SUITES) return BC_PROTOCOL_ERROR;
        if (response.completion_code != BC_IPMI_COMPLETION_OK) return BC_UNSUPPORTED;
        if (response.data.length < 1) return BC_PROTOCOL_ERROR;
        channel = response.data.data[0];
        uint64_t records = response.data.length - 1;
        if (combined_length + records > sizeof(combined)) return BC_LIMIT_EXCEEDED;
        memcpy(combined + combined_length, response.data.data + 1, (size_t)records);
        combined_length += records;
        if (response.data.length != 1 + 16) break;
    }
    combined[0] = channel;
    bc_ipmi_response combined_response = {0};
    combined_response.data = (bc_bytes){combined, combined_length};
    bc_status status = bc_ipmi_cipher_suites_parse(&combined_response, &session->discovered);
    if (status != BC_OK) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.suites_failed", "status=%s channel=%u", bc_status_string(status), channel);
        return status;
    }
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_INFO
    char suites[128];
    suite_list(suites, sizeof(suites), &session->discovered);
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.suites", "channel=%u count=%u suites=%s",
        session->discovered.channel, session->discovered.count, suites);
#endif
    session->discovered_done = 1;
    return BC_OK;
}

static bc_status derive_keys(bc_ipmi_session *session) {
    uint8_t input[BC_IPMI_RANDOM_SIZE * 2 + 1 + 1 + BC_IPMI_MAX_USER_NAME];
    memcpy(input, session->console_random, BC_IPMI_RANDOM_SIZE);
    memcpy(input + BC_IPMI_RANDOM_SIZE, session->bmc_random, BC_IPMI_RANDOM_SIZE);
    input[BC_IPMI_RANDOM_SIZE * 2] = (uint8_t)session->info.maximum_privilege;
    input[BC_IPMI_RANDOM_SIZE * 2 + 1] = session->username_length;
    memcpy(input + BC_IPMI_RANDOM_SIZE * 2 + 2, session->username, session->username_length);
    uint32_t input_length = BC_IPMI_RANDOM_SIZE * 2 + 2 + session->username_length;
    uint32_t mac_length = 0;
    bc_status status = compute_hmac(session, session->info.auth_algorithm, session->password, BC_IPMI_MAX_PASSWORD,
        input, input_length, session->sik, &mac_length);
    if (status != BC_OK) return status;
    session->sik_length = mac_length;
    uint8_t constant[20];
    memset(constant, 0x01, sizeof(constant));
    status = compute_hmac(session, session->info.auth_algorithm, session->sik, session->sik_length,
        constant, sizeof(constant), session->k1, &session->k1_length);
    if (status != BC_OK) return status;
    memset(constant, 0x02, sizeof(constant));
    return compute_hmac(session, session->info.auth_algorithm, session->sik, session->sik_length,
        constant, sizeof(constant), session->k2, &session->k2_length);
}

static bc_status verify_rakp2(bc_ipmi_session *session, const bc_ipmi_rakp2 *message) {
    uint8_t input[4 + 4 + BC_IPMI_RANDOM_SIZE * 3 + 1 + 1 + BC_IPMI_MAX_USER_NAME];
    uint64_t offset = 0;
    bc_wire_write_le(input + offset, session->info.console_session_id, 4); offset += 4;
    bc_wire_write_le(input + offset, session->info.bmc_session_id, 4); offset += 4;
    memcpy(input + offset, session->console_random, BC_IPMI_RANDOM_SIZE); offset += BC_IPMI_RANDOM_SIZE;
    memcpy(input + offset, message->bmc_random.data, BC_IPMI_RANDOM_SIZE); offset += BC_IPMI_RANDOM_SIZE;
    memcpy(input + offset, message->bmc_guid.data, BC_IPMI_GUID_SIZE); offset += BC_IPMI_GUID_SIZE;
    input[offset++] = (uint8_t)session->info.maximum_privilege;
    input[offset++] = session->username_length;
    memcpy(input + offset, session->username, session->username_length); offset += session->username_length;
    uint8_t mac[32];
    uint32_t mac_length = 0;
    bc_status status = compute_hmac(session, session->info.auth_algorithm, session->password, BC_IPMI_MAX_PASSWORD,
        input, (uint32_t)offset, mac, &mac_length);
    if (status != BC_OK) return status;
    if (mac_length != message->auth_code.length || !constant_time_equal(mac, message->auth_code.data, mac_length))
        return BC_AUTHENTICATION_FAILED;
    return BC_OK;
}

static bc_status verify_rakp4(bc_ipmi_session *session, const bc_ipmi_rakp4 *message) {
    uint8_t input[BC_IPMI_RANDOM_SIZE + 4 + BC_IPMI_GUID_SIZE];
    memcpy(input, session->console_random, BC_IPMI_RANDOM_SIZE);
    bc_wire_write_le(input + BC_IPMI_RANDOM_SIZE, session->info.bmc_session_id, 4);
    memcpy(input + BC_IPMI_RANDOM_SIZE + 4, session->bmc_guid, BC_IPMI_GUID_SIZE);
    uint8_t mac[32];
    uint32_t mac_length = 0;
    bc_status status = compute_hmac(session, session->info.auth_algorithm, session->sik, session->sik_length,
        input, sizeof(input), mac, &mac_length);
    if (status != BC_OK) return status;
    uint32_t expected = bc_ipmi_integrity_code_size(session->info.integrity_algorithm);
    if (mac_length < expected || expected != message->integrity_check_value.length ||
        !constant_time_equal(mac, message->integrity_check_value.data, expected))
        return BC_AUTHENTICATION_FAILED;
    return BC_OK;
}

static bc_status open_selected_suite(bc_ipmi_session *session) {
    uint32_t attempts = session->retries ? session->retries : 1;
    uint32_t privilege = BC_IPMI_PRIVILEGE_ADMINISTRATOR;
    session->open_session_done = 0;
    for (uint32_t attempt = 0; attempt < attempts; ++attempt) {
        uint8_t identifier[4] = {0};
        bc_status status = next_random(session, identifier, sizeof(identifier));
        if (status != BC_OK) return status;
        session->info.console_session_id = (uint32_t)bc_wire_read_le(identifier, 4);
        if (!session->info.console_session_id) session->info.console_session_id = 0x0b0c0d0e;
        uint8_t tag = next_tag(session);
        bc_ipmi_open_session_request open = {0};
        open.message_tag = tag;
        open.maximum_privilege = (uint8_t)privilege;
        open.console_session_id = session->info.console_session_id;
        open.auth_algorithm = session->selection.auth_algorithm;
        open.integrity_algorithm = session->selection.integrity_algorithm;
        open.confidentiality_algorithm = session->selection.confidentiality_algorithm;
        uint8_t payload[BC_IPMI_MAX_DATAGRAM];
        uint16_t payload_length = 0;
        status = bc_ipmi_open_session_request_encode(&open, payload, sizeof(payload));
        if (status != BC_OK) return status;
        status = handshake(session, BC_IPMI_PAYLOAD_OPEN_SESSION_REQUEST, BC_IPMI_PAYLOAD_OPEN_SESSION_RESPONSE,
            payload, BC_IPMI_OPEN_SESSION_REQUEST_SIZE, payload, sizeof(payload), &payload_length);
        if (status != BC_OK) return status;
        session->padded_handshake = (uint8_t)bc_ilom_padded_handshake(payload, payload_length,
            session->selection.cipher_suite_id);
        bc_ipmi_open_session_response response;
        status = bc_ipmi_open_session_response_decode(payload, payload_length, &response);
        if (status != BC_OK) return status;
        if (response.message_tag != tag || response.console_session_id != session->info.console_session_id) return BC_PROTOCOL_ERROR;
        if (response.status != BC_IPMI_COMPLETION_OK) {
            BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.open_session",
                "attempt=%u status=0x%02x result=%s", attempt + 1, response.status,
                response.status == 0x04 || response.status == 0x05 || response.status == 0x06 ||
                response.status == 0x07 || response.status == 0x08 || response.status == 0x11 ?
                "unsupported" : "protocol_error");
            return response.status == 0x04 || response.status == 0x05 || response.status == 0x06 ||
                response.status == 0x07 || response.status == 0x08 || response.status == 0x11 ?
                BC_UNSUPPORTED : BC_PROTOCOL_ERROR;
        }
        if (!response.bmc_session_id) return BC_PROTOCOL_ERROR;
        if (response.auth_algorithm != open.auth_algorithm || response.integrity_algorithm != open.integrity_algorithm ||
            response.confidentiality_algorithm != open.confidentiality_algorithm) {
            BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.open_session",
                "requested_auth=%u requested_integrity=%u requested_crypto=%u"
                " reported_auth=%u reported_integrity=%u reported_crypto=%u result=algorithm_mismatch",
                open.auth_algorithm, open.integrity_algorithm, open.confidentiality_algorithm,
                response.auth_algorithm, response.integrity_algorithm, response.confidentiality_algorithm);
            return BC_UNSUPPORTED;
        }
        session->open_session_done = 1;
        session->info.bmc_session_id = response.bmc_session_id;
        if (response.maximum_privilege && response.maximum_privilege < privilege) privilege = response.maximum_privilege;
        session->info.maximum_privilege = privilege;
        status = next_random(session, session->console_random, BC_IPMI_RANDOM_SIZE);
        if (status != BC_OK) return status;
        bc_ipmi_rakp1 rakp1 = {0};
        rakp1.message_tag = next_tag(session);
        rakp1.bmc_session_id = session->info.bmc_session_id;
        rakp1.requested_privilege = (uint8_t)privilege;
        rakp1.console_random = session->console_random;
        rakp1.user_name = (bc_string){(const char *)session->username, session->username_length};
        uint64_t message_length = 0;
        status = bc_ipmi_rakp1_encode(&rakp1, payload, sizeof(payload), &message_length);
        if (status != BC_OK) return status;
        tag = rakp1.message_tag;
        status = handshake(session, BC_IPMI_PAYLOAD_RAKP_1, BC_IPMI_PAYLOAD_RAKP_2,
            payload, (uint16_t)message_length, payload, sizeof(payload), &payload_length);
        if (status != BC_OK) return status;
        /* Old ILOM adds a byte to handshake payloads. Authentication still covers
         * every required byte; limit compatibility to its observed framing. */
        if (session->padded_handshake && payload_length == 61) --payload_length;
        bc_ipmi_rakp2 rakp2;
        status = bc_ipmi_rakp2_decode(payload, payload_length, session->info.auth_algorithm, &rakp2);
        if (status != BC_OK) return status;
        if (rakp2.message_tag != tag || rakp2.console_session_id != session->info.console_session_id) return BC_PROTOCOL_ERROR;
        if (rakp2.status != BC_IPMI_COMPLETION_OK) {
            BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.rakp2", "status=0x%02x user_len=%u", rakp2.status, session->username_length);
            return BC_AUTHENTICATION_FAILED;
        }
        status = verify_rakp2(session, &rakp2);
        if (status != BC_OK) return status;
        memcpy(session->bmc_random, rakp2.bmc_random.data, BC_IPMI_RANDOM_SIZE);
        memcpy(session->bmc_guid, rakp2.bmc_guid.data, BC_IPMI_GUID_SIZE);
        status = derive_keys(session);
        if (status != BC_OK) return status;
        uint8_t rakp3_input[BC_IPMI_RANDOM_SIZE + 4 + 1 + 1 + BC_IPMI_MAX_USER_NAME];
        uint64_t offset = 0;
        memcpy(rakp3_input + offset, session->bmc_random, BC_IPMI_RANDOM_SIZE); offset += BC_IPMI_RANDOM_SIZE;
        bc_wire_write_le(rakp3_input + offset, session->info.console_session_id, 4); offset += 4;
        rakp3_input[offset++] = (uint8_t)privilege;
        rakp3_input[offset++] = session->username_length;
        memcpy(rakp3_input + offset, session->username, session->username_length); offset += session->username_length;
        uint8_t auth_code[32];
        uint32_t auth_length = 0;
        status = compute_hmac(session, session->info.auth_algorithm, session->password, BC_IPMI_MAX_PASSWORD,
            rakp3_input, (uint32_t)offset, auth_code, &auth_length);
        if (status != BC_OK) return status;
        bc_ipmi_rakp3 rakp3 = {0};
        rakp3.message_tag = next_tag(session);
        rakp3.bmc_session_id = session->info.bmc_session_id;
        rakp3.auth_algorithm = session->info.auth_algorithm;
        rakp3.auth_code = (bc_bytes){auth_code, auth_length};
        status = bc_ipmi_rakp3_encode(&rakp3, payload, sizeof(payload), &message_length);
        if (status != BC_OK) return status;
        tag = rakp3.message_tag;
        status = handshake(session, BC_IPMI_PAYLOAD_RAKP_3, BC_IPMI_PAYLOAD_RAKP_4,
            payload, (uint16_t)message_length, payload, sizeof(payload), &payload_length);
        if (status != BC_OK) return status;
        if (session->padded_handshake && payload_length == 21) --payload_length;
        bc_ipmi_rakp4 rakp4;
        status = bc_ipmi_rakp4_decode(payload, payload_length, session->info.integrity_algorithm, &rakp4);
        if (status != BC_OK) return status;
        if (rakp4.message_tag != tag || rakp4.console_session_id != session->info.console_session_id) return BC_PROTOCOL_ERROR;
        if (rakp4.status != BC_IPMI_COMPLETION_OK) {
            BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.rakp4", "status=0x%02x", rakp4.status);
            return BC_AUTHENTICATION_FAILED;
        }
        status = verify_rakp4(session, &rakp4);
        if (status != BC_OK) return status;
        session->send_sequence = 1;
        session->receive_high = 0; session->receive_window = 0;
        session->opened = 1;
        uint8_t requested = (uint8_t)session->info.maximum_privilege, completion = 0, granted = 0;
        uint32_t granted_length = 0;
        status = bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, BC_IPMI_CMD_SET_SESSION_PRIVILEGE,
            (bc_bytes){&requested, 1}, &completion, &granted, 1, &granted_length);
        if (status == BC_OK && completion != BC_IPMI_COMPLETION_OK) status = BC_AUTHENTICATION_FAILED;
        if (status == BC_OK && (granted_length != 1 || granted != requested)) status = BC_PROTOCOL_ERROR;
        if (status != BC_OK) {
            bc_ipmi_session_close(session);
            return status;
        }
        BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.session_open",
            "suite=%u auth=%u integrity=%u crypto=%u privilege=%u",
            session->info.cipher_suite_id, session->info.auth_algorithm, session->info.integrity_algorithm,
            session->info.confidentiality_algorithm, session->info.maximum_privilege);
        return BC_OK;
    }
    return BC_TIMEOUT;
}

bc_status bc_ipmi_session_create(const bc_ipmi_session_options *options, bc_ipmi_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        !io_valid(options->io) || !crypto_valid(options->crypto)) return BC_INVALID_ARGUMENT;
    if (options->suite3_policy > BC_IPMI_SUITE3_CONFIRMED) return BC_INVALID_ARGUMENT;
    if (options->username.length > BC_IPMI_MAX_USER_NAME || (options->username.length && !options->username.data) ||
        options->password.length > BC_IPMI_MAX_PASSWORD || (options->password.length && !options->password.data))
        return BC_INVALID_ARGUMENT;
    bc_ipmi_session *session = calloc(1, sizeof(*session));
    if (!session) return BC_NO_MEMORY;
    session->io = options->io;
    session->crypto = options->crypto;
    session->timeout_ms = options->timeout_ms ? options->timeout_ms : BC_IPMI_DEFAULT_TIMEOUT_MS;
    session->retries = options->retries ? options->retries : BC_IPMI_DEFAULT_RETRIES;
    session->channel = options->channel ? options->channel : BC_IPMI_DEFAULT_CHANNEL;
    session->suite3_policy = options->suite3_policy;
    session->username_length = (uint8_t)options->username.length;
    if (options->username.length) memcpy(session->username, options->username.data, (size_t)options->username.length);
    if (options->password.length) memcpy(session->password, options->password.data, (size_t)options->password.length);
    *out = session;
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.session_create",
        "channel=%u timeout_ms=%u retries=%u suite3=%u user_len=%" PRIu64 " password=%u",
        session->channel, session->timeout_ms, session->retries, session->suite3_policy,
        options->username.length, options->password.length != 0);
    return BC_OK;
}

static void apply_selection(bc_ipmi_session *session) {
    session->info.cipher_suite_id = session->selection.cipher_suite_id;
    session->info.auth_algorithm = session->selection.auth_algorithm;
    session->info.integrity_algorithm = session->selection.integrity_algorithm;
    session->info.confidentiality_algorithm = session->selection.confidentiality_algorithm;
}

static bc_status open_with_selection(bc_ipmi_session *session) {
    apply_selection(session);
    return open_selected_suite(session);
}

/* Open with a statically known standard suite when the channel did not provide
 * a usable cipher-suite list.  The Open Session response is then the
 * authoritative statement about which algorithms the endpoint accepts. */
static bc_status open_standard_suite(bc_ipmi_session *session, uint32_t cipher_suite_id) {
    const bc_ipmi_cipher_suite_definition *definition = bc_ipmi_standard_cipher_suite(cipher_suite_id);
    if (!definition) return BC_UNSUPPORTED;
    memset(&session->selection, 0, sizeof(session->selection));
    session->selection.cipher_suite_id = cipher_suite_id;
    session->selection.auth_algorithm = definition->auth_algorithm;
    session->selection.integrity_algorithm = definition->integrity_algorithm;
    session->selection.confidentiality_algorithm = definition->confidentiality_algorithm;
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.suite_selected",
        "suite=%u auth=%u integrity=%u crypto=%u flags=0 source=direct",
        cipher_suite_id, definition->auth_algorithm, definition->integrity_algorithm,
        definition->confidentiality_algorithm);
    return open_with_selection(session);
}

static int discovery_unavailable(bc_status status) {
    return status == BC_TIMEOUT || status == BC_UNSUPPORTED || status == BC_PROTOCOL_ERROR;
}

/* Get Channel Cipher Suites is not answered by every IPMI 2.0 endpoint, so a
 * failed pre-session query cannot decide that RMCP+ is absent.  Ask Get Channel
 * Authentication Capabilities for the IPMI 2.0 capability bits, then let Open
 * Session decide whether the preferred standard suite is accepted.  A timeout
 * during Open Session is not evidence that suite 17 is unsupported, so it never
 * triggers a suite 3 fallback. */
static bc_status open_without_cipher_suites(bc_ipmi_session *session) {
    int ipmi_v2_supported = 0;
    bc_status probe = probe_auth_capabilities(session, &ipmi_v2_supported);
    if (probe == BC_OK && ipmi_v2_supported == 0) {
        session->info.flags |= BC_IPMI_SESSION_LEGACY_1_5;
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.legacy_1_5", "channel=%u auth=none status=detected", session->channel);
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.legacy_unsupported", "result=unsupported");
        return BC_UNSUPPORTED;
    }
    bc_status status = open_standard_suite(session, 17);
    if (status == BC_OK) return BC_OK;
    if (session->open_session_done) return status;
    if (status != BC_UNSUPPORTED) return status;
    BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.suite_unavailable", "suite=17 channel=%u", session->channel);
    if (session->suite3_policy == BC_IPMI_SUITE3_DISALLOWED) return BC_UNSUPPORTED;
    if (session->suite3_policy == BC_IPMI_SUITE3_ALLOWED) {
        session->fallback_suite3 = 1;
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.suite_confirmation_required", "suite=3 source=direct");
        return BC_CONFIRMATION_REQUIRED;
    }
    return open_standard_suite(session, 3);
}

bc_status bc_ipmi_session_open(bc_ipmi_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->opened) return BC_BUSY;
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.session_open_start",
        "channel=%u suite3=%u timeout_ms=%u retries=%u", session->channel, session->suite3_policy,
        session->timeout_ms, session->retries);
    bc_status status = discover_cipher_suites(session);
    if (status != BC_OK) {
        if (!discovery_unavailable(status)) {
            BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.suites_failed", "status=%s", bc_status_string(status));
            return status;
        }
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.suites_unavailable",
            "status=%s channel=%u result=direct_suite_probe", bc_status_string(status), session->channel);
        return open_without_cipher_suites(session);
    }
    status = bc_ipmi_select_cipher_suite(&session->discovered, session->suite3_policy, &session->selection);
    if (status != BC_OK) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.select_failed", "status=%s count=%u", bc_status_string(status),
            session->discovered.count);
        return status;
    }
    if (session->selection.flags & BC_IPMI_SUITE_CONFIRMATION_REQUIRED) {
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.suite_confirmation_required", "suite=%u",
            session->selection.cipher_suite_id);
        return BC_CONFIRMATION_REQUIRED;
    }
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.suite_selected",
        "suite=%u auth=%u integrity=%u crypto=%u flags=%u", session->selection.cipher_suite_id,
        session->selection.auth_algorithm, session->selection.integrity_algorithm,
        session->selection.confidentiality_algorithm, session->selection.flags);
    return open_with_selection(session);
}

bc_status bc_ipmi_session_confirm_suite3(bc_ipmi_session *session) {
    if (!session || session->opened) return BC_INVALID_ARGUMENT;
    if (session->suite3_policy != BC_IPMI_SUITE3_ALLOWED) return BC_INVALID_ARGUMENT;
    if (!session->discovered_done && !session->fallback_suite3) return BC_INVALID_ARGUMENT;
    session->suite3_policy = BC_IPMI_SUITE3_CONFIRMED;
    BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.suite3_confirmed", "suite=3");
    if (!session->discovered_done) {
        session->fallback_suite3 = 0;
        return open_standard_suite(session, 3);
    }
    bc_status status = bc_ipmi_select_cipher_suite(&session->discovered, session->suite3_policy, &session->selection);
    if (status != BC_OK) return status;
    if (session->selection.cipher_suite_id != 3) return BC_UNSUPPORTED;
    return open_with_selection(session);
}

const bc_ipmi_session_info *bc_ipmi_session_info_get(const bc_ipmi_session *session) {
    return session ? &session->info : NULL;
}

bc_status bc_ipmi_session_probe(bc_ipmi_session *session, bc_ipmi_capabilities *out) {
    if (!session || !out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->cipher_suite_id = session->info.cipher_suite_id;
    if (!session->opened) return BC_BUSY;
    bc_ipmi_chassis_status chassis = {0};
    chassis.struct_size = sizeof(chassis);
    if (bc_ipmi_chassis_status_get(session, &chassis) == BC_OK) {
        out->flags |= BC_IPMI_CAPABILITY_CHASSIS_STATUS;
        out->chassis_power_state = chassis.power_state;
    }
    uint8_t completion_code = 0, data[16];
    uint32_t length = 0;
    if (bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, BC_IPMI_CMD_GET_DEVICE_ID,
            (bc_bytes){NULL, 0}, &completion_code, data, sizeof(data), &length) == BC_OK && !completion_code)
        out->flags |= bc_ilom_ipmi_capabilities(data, length);
    if (bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_SDR_REPOSITORY_INFO,
            (bc_bytes){NULL, 0}, &completion_code, data, sizeof(data), &length) == BC_OK &&
        completion_code == BC_IPMI_COMPLETION_OK && length >= 3) {
        out->flags |= BC_IPMI_CAPABILITY_SDR;
        out->sdr_record_count = (uint32_t)bc_wire_read_le(data + 1, 2);
    }
    if (bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_SEL_INFO,
            (bc_bytes){NULL, 0}, &completion_code, data, sizeof(data), &length) == BC_OK &&
        completion_code == BC_IPMI_COMPLETION_OK && length >= 3) {
        out->flags |= BC_IPMI_CAPABILITY_SEL;
        out->sel_record_count = (uint32_t)bc_wire_read_le(data + 1, 2);
    }
    uint8_t fru_id = 0;
    if (bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_FRU_INVENTORY_AREA_INFO,
            (bc_bytes){&fru_id, 1}, &completion_code, data, sizeof(data), &length) == BC_OK &&
        completion_code == BC_IPMI_COMPLETION_OK && length == 3) {
        out->flags |= BC_IPMI_CAPABILITY_FRU;
    }
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.capabilities", "flags=%u sdr=%u sel=%u", out->flags,
        out->sdr_record_count, out->sel_record_count);
    return BC_OK;
}

const bc_ipmi_cipher_suites *bc_ipmi_session_cipher_suites_get(const bc_ipmi_session *session) {
    return session && session->discovered_done ? &session->discovered : NULL;
}

static bc_status encode_active_packet(bc_ipmi_session *session, uint8_t type, const uint8_t *plaintext, uint16_t plaintext_length,
    uint8_t *datagram, uint32_t *datagram_length) {
    uint8_t payload[BC_IPMI_MAX_DATAGRAM];
    uint32_t payload_length = plaintext_length;
    uint8_t flags = 0;
    if (session->info.confidentiality_algorithm != BC_IPMI_CONFIDENTIALITY_ALG_NONE) {
        if (session->k2_length < 16) return BC_PROTOCOL_ERROR;
        uint32_t pad = 16 - ((plaintext_length + 1) % 16);
        if (pad == 16) pad = 0;
        uint8_t padded[BC_IPMI_MAX_DATAGRAM];
        if ((uint32_t)plaintext_length + pad + 1 > sizeof(padded)) return BC_LIMIT_EXCEEDED;
        memcpy(padded, plaintext, plaintext_length);
        for (uint32_t i = 0; i < pad; ++i) padded[plaintext_length + i] = (uint8_t)(i + 1);
        padded[plaintext_length + pad] = (uint8_t)pad;
        uint32_t padded_length = plaintext_length + pad + 1;
        bc_status status = next_random(session, payload, 16);
        if (status != BC_OK) return status;
        status = session->crypto->encrypt(session->crypto->userdata, session->info.confidentiality_algorithm,
            session->k2, 16, payload, padded, padded_length, payload + 16);
        if (status != BC_OK) return status;
        payload_length = 16 + padded_length;
        flags |= BC_IPMI_PAYLOAD_FLAG_ENCRYPTED;
    } else if (plaintext_length) {
        memcpy(payload, plaintext, plaintext_length);
    }
    if (session->info.integrity_algorithm != BC_IPMI_INTEGRITY_ALG_NONE) flags |= BC_IPMI_PAYLOAD_FLAG_AUTHENTICATED;
    bc_ipmi_packet packet = {0};
    packet.auth_type = BC_IPMI_AUTH_TYPE_RMCP_PLUS;
    packet.payload_type = type;
    packet.flags = flags;
    packet.session_id = session->info.bmc_session_id;
    packet.sequence = session->send_sequence++;
    if (!session->send_sequence) session->send_sequence = 1;
    packet.payload_length = (uint16_t)payload_length;
    packet.payload = (bc_bytes){payload, payload_length};
    bc_status status = bc_ipmi_packet_encode(&packet, datagram, BC_IPMI_MAX_DATAGRAM, datagram_length);
    if (status != BC_OK) return status;
    if (session->info.integrity_algorithm != BC_IPMI_INTEGRITY_ALG_NONE) {
        uint32_t integrity_size = bc_ipmi_integrity_code_size(session->info.integrity_algorithm);
        if (!integrity_size || session->k1_length < integrity_size) return BC_PROTOCOL_ERROR;
        uint32_t pad = (4 - ((12 + payload_length + 2) % 4)) % 4;
        uint32_t base = *datagram_length;
        if (base + pad + 2 + integrity_size > BC_IPMI_MAX_DATAGRAM) return BC_LIMIT_EXCEEDED;
        memset(datagram + base, 0xff, pad);
        datagram[base + pad] = (uint8_t)pad;
        datagram[base + pad + 1] = 0x07;
        uint8_t mac[32];
        uint32_t mac_length = 0;
        status = compute_hmac(session, session->info.integrity_algorithm, session->k1, session->k1_length,
            datagram + 4, 12 + payload_length + pad + 2, mac, &mac_length);
        if (status != BC_OK) return status;
        if (mac_length < integrity_size) return BC_PROTOCOL_ERROR;
        memcpy(datagram + base + pad + 2, mac, integrity_size);
        *datagram_length = base + pad + 2 + integrity_size;
    }
    return BC_OK;
}

static bc_status verify_and_decrypt(bc_ipmi_session *session, const uint8_t *datagram, uint32_t size,
    const bc_ipmi_packet *packet, uint8_t *plaintext, uint32_t capacity, uint32_t *plaintext_length) {
    uint32_t integrity_size = bc_ipmi_integrity_code_size(session->info.integrity_algorithm);
    if (integrity_size) {
        if (!(packet->flags & BC_IPMI_PAYLOAD_FLAG_AUTHENTICATED)) return BC_PROTOCOL_ERROR;
        uint32_t pad = (4 - ((12 + packet->payload_length + 2) % 4)) % 4;
        uint64_t expected = 16 + (uint64_t)packet->payload_length + pad + 2 + integrity_size;
        if (size != expected) return BC_PROTOCOL_ERROR;
        const uint8_t *trailer = datagram + 16 + packet->payload_length;
        for (uint32_t i = 0; i < pad; ++i) if (trailer[i] != 0xff) return BC_PROTOCOL_ERROR;
        if (trailer[pad] != pad || trailer[pad + 1] != 0x07) return BC_PROTOCOL_ERROR;
        uint8_t mac[32];
        uint32_t mac_length = 0;
        bc_status status = compute_hmac(session, session->info.integrity_algorithm, session->k1, session->k1_length,
            datagram + 4, 12 + packet->payload_length + pad + 2, mac, &mac_length);
        if (status != BC_OK) return status;
        if (mac_length < integrity_size || !constant_time_equal(mac, trailer + pad + 2, integrity_size))
            return BC_PROTOCOL_ERROR;
    }
    if (session->info.confidentiality_algorithm != BC_IPMI_CONFIDENTIALITY_ALG_NONE &&
        !(packet->flags & BC_IPMI_PAYLOAD_FLAG_ENCRYPTED)) return BC_PROTOCOL_ERROR;
    if (packet->flags & BC_IPMI_PAYLOAD_FLAG_ENCRYPTED) {
        if (session->info.confidentiality_algorithm == BC_IPMI_CONFIDENTIALITY_ALG_NONE || packet->payload_length < 32 ||
            (packet->payload_length - 16) % 16) return BC_PROTOCOL_ERROR;
        uint32_t cipher_length = packet->payload_length - 16;
        if (cipher_length > capacity) return BC_LIMIT_EXCEEDED;
        bc_status status = session->crypto->decrypt(session->crypto->userdata, session->info.confidentiality_algorithm,
            session->k2, 16, packet->payload.data, packet->payload.data + 16, cipher_length, plaintext);
        if (status != BC_OK) return status;
        uint8_t pad = plaintext[cipher_length - 1];
        if ((uint32_t)pad + 1 > cipher_length) return BC_PROTOCOL_ERROR;
        for (uint32_t i = 0; i < pad; ++i) if (plaintext[cipher_length - pad - 1 + i] != (uint8_t)(i + 1)) return BC_PROTOCOL_ERROR;
        *plaintext_length = cipher_length - pad - 1;
        return BC_OK;
    }
    if (packet->payload_length > capacity) return BC_LIMIT_EXCEEDED;
    if (packet->payload_length) memcpy(plaintext, packet->payload.data, packet->payload_length);
    *plaintext_length = packet->payload_length;
    return BC_OK;
}

static int accept_sequence(bc_ipmi_session *session, uint32_t sequence) {
    if (!sequence && !(session->padded_handshake && !session->receive_window)) return 0;
    if (!session->receive_window) {
        session->receive_high = sequence; session->receive_window = 1; return 1;
    }
    uint32_t ahead = sequence - session->receive_high;
    if (ahead && ahead < UINT32_C(0x80000000)) {
        session->receive_window = ahead >= 64 ? 1 : (session->receive_window << ahead) | 1;
        session->receive_high = sequence; return 1;
    }
    uint32_t behind = session->receive_high - sequence;
    if (behind >= 64 || (session->receive_window & (UINT64_C(1) << behind))) return 0;
    session->receive_window |= UINT64_C(1) << behind;
    return 1;
}
static bc_status receive_payload(bc_ipmi_session *session, uint8_t *type, uint32_t *sequence,
    uint8_t *plaintext, uint32_t capacity, uint32_t *length, uint32_t timeout_ms) {
    uint8_t incoming[BC_IPMI_MAX_DATAGRAM]; uint32_t received = 0;
    bc_status status = session->io->receive(session->io->userdata, incoming, sizeof(incoming), &received, timeout_ms);
    if (status != BC_OK) return status;
    bc_ipmi_packet packet;
    if (bc_ipmi_packet_decode(incoming, received, &packet) != BC_OK ||
        packet.auth_type != BC_IPMI_AUTH_TYPE_RMCP_PLUS || packet.session_id != session->info.console_session_id)
        return BC_BUSY;
    if (packet.payload_type != BC_IPMI_PAYLOAD_IPMI && (packet.payload_type != 1 || !session->payload_handler)) return BC_BUSY;
    status = verify_and_decrypt(session, incoming, received, &packet, plaintext, capacity, length);
    if (status != BC_OK) return status;
    if (!accept_sequence(session, packet.sequence)) return BC_BUSY;
    *type = packet.payload_type; *sequence = packet.sequence;
    return BC_OK;
}
bc_status bc_ipmi_payload_attach(bc_ipmi_session *session, void *owner, bc_ipmi_payload_handler handler) {
    if (!session || !owner || !handler) return BC_INVALID_ARGUMENT;
    if (!session->opened || session->payload_owner || session->command_busy) return BC_BUSY;
    session->payload_owner = owner; session->payload_handler = handler;
    return BC_OK;
}
void bc_ipmi_payload_detach(bc_ipmi_session *session, void *owner) {
    if (session && session->payload_owner == owner) { session->payload_owner = NULL; session->payload_handler = NULL; }
}
bc_status bc_ipmi_payload_send(bc_ipmi_session *session, const uint8_t *data, uint32_t length) {
    if (!session || !data || length > BC_IPMI_MAX_MESSAGE) return BC_INVALID_ARGUMENT;
    if (!session->opened || !session->payload_owner) return BC_BUSY;
    uint8_t datagram[BC_IPMI_MAX_DATAGRAM]; uint32_t n = 0;
    bc_status status = encode_active_packet(session, 1, data, (uint16_t)length, datagram, &n);
    if (status == BC_OK) status = session->io->send(session->io->userdata, datagram, n);
    BC_LOG_TRACE(BC_LOG_CATEGORY_IPMI, "ipmi.payload_send", "len=%u status=%s", length, bc_status_string(status));
    return status;
}
bc_status bc_ipmi_payload_poll(bc_ipmi_session *session, uint32_t timeout_ms) {
    if (!session || !session->opened || session->command_busy) return BC_BUSY;
    uint8_t data[BC_IPMI_MAX_DATAGRAM], type = 0; uint32_t length = 0, sequence = 0;
    bc_status status = receive_payload(session, &type, &sequence, data, sizeof(data), &length, timeout_ms);
    if (status == BC_BUSY) return BC_OK;
    if (status != BC_OK) return status;
    BC_LOG_TRACE(BC_LOG_CATEGORY_IPMI, "ipmi.payload_receive", "type=%u len=%u sequence=%u", type, length, sequence);
    return type == 1 && session->payload_handler ? session->payload_handler(session->payload_owner, data, length, sequence) : BC_OK;
}
static bc_status session_command(bc_ipmi_session *session, uint8_t netfn, uint8_t command, bc_bytes request,
    uint8_t *completion_code, uint8_t *response, uint32_t capacity, uint32_t *response_length, int *submitted) {
    *submitted = 0;
    if (!session || !completion_code || !response_length || !bytes_valid(request) || (capacity && !response)) return BC_INVALID_ARGUMENT;
    if (!session->opened) return BC_BUSY;
    if (request.length > BC_IPMI_MAX_MESSAGE - 7) return BC_LIMIT_EXCEEDED;
    *response_length = 0;
    bc_ipmi_request message = {0};
    message.netfn = netfn;
    message.sequence = next_message_sequence(session);
    message.command = command;
    message.data = request;
    uint8_t plaintext[BC_IPMI_MAX_MESSAGE];
    uint64_t plaintext_length = 0;
    bc_status status = bc_ipmi_message_encode(&message, plaintext, sizeof(plaintext), &plaintext_length);
    if (status != BC_OK) return status;
    uint8_t datagram[BC_IPMI_MAX_DATAGRAM];
    uint32_t datagram_length = 0;
    status = encode_active_packet(session, BC_IPMI_PAYLOAD_IPMI, plaintext, (uint16_t)plaintext_length, datagram, &datagram_length);
    if (status != BC_OK) return status;
    status = session->io->send(session->io->userdata, datagram, datagram_length);
    if (status != BC_OK) return status;
    *submitted = 1;
    for (unsigned packets = 0; packets < 256; ++packets) {
        uint8_t incoming[BC_IPMI_MAX_DATAGRAM], type = 0;
        uint32_t plain_length = 0, sequence = 0;
        status = receive_payload(session, &type, &sequence, incoming, sizeof(incoming), &plain_length, session->timeout_ms);
        if (status == BC_BUSY) continue;
        if (status != BC_OK) return status;
        if (type == 1 && session->payload_handler) {
            status = session->payload_handler(session->payload_owner, incoming, plain_length, sequence);
            if (status != BC_OK) return status;
            continue;
        }
        if (type != BC_IPMI_PAYLOAD_IPMI) continue;
        bc_ipmi_response decoded;
        if (bc_ipmi_message_decode(incoming, plain_length, &decoded) != BC_OK) continue;
        if (decoded.sequence != message.sequence || decoded.command != command || decoded.netfn != (netfn | 1)) continue;
        if (decoded.data.length > capacity) return BC_LIMIT_EXCEEDED;
        if (decoded.data.length) memcpy(response, decoded.data.data, (size_t)decoded.data.length);
        *response_length = (uint32_t)decoded.data.length;
        *completion_code = decoded.completion_code;
        return BC_OK;
    }
    return BC_TIMEOUT;
}
static bc_status command_dispatch(bc_ipmi_session *session, uint8_t netfn, uint8_t command, bc_bytes request,
    uint8_t *completion_code, uint8_t *response, uint32_t capacity, uint32_t *response_length, int mutating) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->command_busy) return BC_BUSY;
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_VERBOSE
    if (bc_log_enabled(BC_LOG_LEVEL_VERBOSE, BC_LOG_CATEGORY_IPMI)) {
        if (sensitive_command(netfn, command, request.length, mutating)) {
            BC_LOG_VERBOSE(BC_LOG_CATEGORY_IPMI, "ipmi.command.request",
                "netfn=0x%02x cmd=0x%02x data_len=%" PRIu64 " data=<redacted> redacted=1",
                netfn, command, request.length);
        } else {
            char hex[513];
            uint32_t shown = bc_log_hex(hex, sizeof(hex), request.data, (uint32_t)request.length, 256);
            BC_LOG_VERBOSE(BC_LOG_CATEGORY_IPMI, "ipmi.command.request",
                "netfn=0x%02x cmd=0x%02x data_len=%" PRIu64 " data=%s data_shown=%u data_truncated=%u",
                netfn, command, request.length, request.length ? hex : "-", shown, shown < request.length);
        }
    }
#endif
    session->command_busy = 1;
    int submitted = 0;
    bc_status status = session_command(session, netfn, command, request, completion_code, response, capacity, response_length, &submitted);
    session->command_busy = 0;
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_DEBUG
    if (status == BC_OK) {
        char completion[8];
        snprintf(completion, sizeof(completion), "0x%02x", *completion_code);
        BC_LOG_DEBUG(BC_LOG_CATEGORY_IPMI, "ipmi.command", "netfn=0x%02x cmd=0x%02x request_len=%" PRIu64
            " completion=%s response_len=%u status=ok", netfn, command, request.length, completion, *response_length);
    } else
#endif
    if (status == BC_TIMEOUT)
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.command", "netfn=0x%02x cmd=0x%02x request_len=%" PRIu64
            " status=timeout timeout_ms=%u", netfn, command, request.length, session->timeout_ms);
    else if (status != BC_OK)
        BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.command", "netfn=0x%02x cmd=0x%02x request_len=%" PRIu64
            " status=%s", netfn, command, request.length, bc_status_string(status));
    return mutating && submitted && status != BC_OK ? BC_OUTCOME_UNKNOWN : status;
}

bc_status bc_ipmi_session_command(bc_ipmi_session *session, uint8_t netfn, uint8_t command, bc_bytes request,
    uint8_t *completion, uint8_t *response, uint32_t capacity, uint32_t *length) {
    return command_dispatch(session, netfn, command, request, completion, response, capacity, length, 0);
}
bc_status bc_ipmi_session_mutate(bc_ipmi_session *session, uint8_t netfn, uint8_t command, bc_bytes request,
    uint8_t *completion, uint8_t *response, uint32_t capacity, uint32_t *length) {
    return command_dispatch(session, netfn, command, request, completion, response, capacity, length, 1);
}

bc_status bc_ipmi_session_close(bc_ipmi_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->payload_owner) return BC_BUSY;
    if (!session->opened) return BC_OK;
    uint8_t identifier[4];
    bc_wire_write_le(identifier, session->info.bmc_session_id, 4);
    uint8_t completion_code = 0;
    uint32_t response_length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, BC_IPMI_CMD_CLOSE_SESSION,
        (bc_bytes){identifier, sizeof(identifier)}, &completion_code, NULL, 0, &response_length);
    if (status == BC_OK && completion_code != BC_IPMI_COMPLETION_OK) status = BC_OUTCOME_UNKNOWN;
    session->opened = 0;
    secure_clear(session->sik, sizeof(session->sik));
    secure_clear(session->k1, sizeof(session->k1));
    secure_clear(session->k2, sizeof(session->k2));
    secure_clear(session->console_random, sizeof(session->console_random));
    secure_clear(session->bmc_random, sizeof(session->bmc_random));
    session->sik_length = session->k1_length = session->k2_length = 0;
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.session_close", "status=%s", bc_status_string(status));
    return status;
}

void bc_ipmi_session_destroy(bc_ipmi_session *session) {
    if (!session) return;
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.session_destroy", "opened=%u", session->opened);
    secure_clear(session->password, sizeof(session->password));
    secure_clear(session->sik, sizeof(session->sik));
    secure_clear(session->k1, sizeof(session->k1));
    secure_clear(session->k2, sizeof(session->k2));
    secure_clear(session->console_random, sizeof(session->console_random));
    secure_clear(session->bmc_random, sizeof(session->bmc_random));
    secure_clear(session->username, sizeof(session->username));
    free(session);
}

bc_status bc_ipmi_chassis_control(bc_ipmi_session *session, uint8_t action, uint8_t *completion_code) {
    if (!session || !completion_code || action > BC_IPMI_CHASSIS_CONTROL_SOFT_SHUTDOWN) return BC_INVALID_ARGUMENT;
    uint32_t length = 0;
    return bc_ipmi_session_mutate(session, BC_IPMI_NETFN_CHASSIS, BC_IPMI_CMD_CHASSIS_CONTROL,
        (bc_bytes){&action, 1}, completion_code, NULL, 0, &length);
}

bc_status bc_ipmi_session_group_command(bc_ipmi_session *session, uint32_t iana, uint8_t command, bc_bytes request,
    uint8_t *completion_code, uint8_t *response, uint32_t capacity, uint32_t *response_length) {
    if (!session || !completion_code || !response_length || !bytes_valid(request) || (capacity && !response) ||
        iana > 0xffffff || request.length > 250) return BC_INVALID_ARGUMENT;
    uint8_t data[256];
    bc_wire_write_le(data, iana, 3);
    if (request.length) memcpy(data + 3, request.data, (size_t)request.length);
    return bc_ipmi_session_command(session, BC_IPMI_NETFN_GROUP, command,
        (bc_bytes){data, 3 + request.length}, completion_code, response, capacity, response_length);
}

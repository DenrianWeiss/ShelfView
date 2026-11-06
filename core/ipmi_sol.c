#include "bcontrol/ipmi_sol.h"
#include "bcontrol/serial_provider.h"
#include "ipmi_session_internal.h"
#include "log_internal.h"
#include "bcontrol/wire.h"
#include <stdlib.h>
#include <string.h>

struct bc_ipmi_sol {
    bc_ipmi_session *session;
    bc_ipmi_sol_info info;
    uint8_t *rx, *tx;
    uint32_t rx_capacity, tx_capacity, rx_length, tx_length;
    uint32_t interval, retries, keepalive, attempts;
    uint64_t now, last_send, last_keepalive;
    uint8_t last_rx[255], rx_seq, rx_count, tx_seq, tx_count;
    uint8_t waiting, control, sent_control, blocked_seq;
    uint32_t blocked_need, rx_packet_sequence, latest_packet, tx_ack_floor;
    uint8_t attempted, owned, attached, delayed, closing, advertised_oversize;
};
static uint8_t next_sequence(uint8_t n) { return (uint8_t)(n == 15 ? 1 : n + 1); }
static bc_status fail(bc_ipmi_sol *sol, bc_status status) {
    sol->info.state = BC_IPMI_SOL_FAILED; sol->info.status = status; return status;
}
static bc_status command(bc_ipmi_sol *sol, uint8_t cmd, const uint8_t *data, uint32_t length,
    uint8_t *response, uint32_t capacity, uint32_t *received) {
    sol->info.completion_code = 0;
    bc_status status = bc_ipmi_session_command(sol->session, BC_IPMI_NETFN_APP, cmd,
        (bc_bytes){data, length}, &sol->info.completion_code, response, capacity, received);
    if (status != BC_OK) return status;
    if (!sol->info.completion_code) return BC_OK;
    if (sol->info.completion_code == 0x80 || sol->info.completion_code == 0x82) return BC_BUSY;
    if (sol->info.completion_code == 0x81 || sol->info.completion_code == 0x83 || sol->info.completion_code == 0x84 ||
        sol->info.completion_code == 0xc1) return BC_UNSUPPORTED;
    return BC_PROTOCOL_ERROR;
}
static bc_status owner(bc_ipmi_sol *sol, uint32_t *id) {
    uint8_t request[2] = {1, sol->info.instance}, response[16]; uint32_t n = 0;
    bc_status status = command(sol, 0x4b, request, sizeof(request), response, sizeof(response), &n);
    if (status != BC_OK) return status;
    if (n != 12) return BC_PROTOCOL_ERROR;
    *id = (uint32_t)bc_wire_read_le(response, 4); return BC_OK;
}
static int owner_matches(uint32_t id, uint32_t session_id) {
    /* Payload Instance Info carries the BMC session id in the device's byte
     * order; accept either interpretation instead of failing a valid owner. */
    return id == session_id || bc_wire_read_be((const uint8_t *)&id, 4) == session_id;
}
static bc_status acknowledge(bc_ipmi_sol *sol, uint8_t sequence, uint8_t count, int nack) {
    uint8_t data[4] = {0, sequence, count, nack ? 0x40 : 0};
    return bc_ipmi_payload_send(sol->session, data, sizeof(data));
}
static bc_status feed(void *userdata, const uint8_t *data, uint32_t length, uint32_t packet_sequence) {
    bc_ipmi_sol *sol = userdata;
    if (sol->closing || sol->info.state == BC_IPMI_SOL_FAILED || sol->info.state == BC_IPMI_SOL_CLOSED) return BC_OK;
    if (length < 4 || length > 259 || (data[0] & 0xf0) || (data[1] & 0xf0) || (data[3] & 0x83)) {
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.sol_packet_rejected",
            "reason=shape len=%u seq=%u ack=%u count=%u flags=0x%02x", length,
            length > 0 ? data[0] : 0, length > 1 ? data[1] : 0, length > 2 ? data[2] : 0, length > 3 ? data[3] : 0);
        return fail(sol, BC_PROTOCOL_ERROR);
    }
    /* Use the advertised outbound payload size for sizing only. BMCs may send
     * packets larger than advertised (Huawei iBMC advertises 255 while sending
     * 256-byte SOL payloads on bulk output); the structural 259-byte limit above
     * is authoritative, so do not fail the session over this disagreement. */
    if (sol->info.outbound_payload_size && length > sol->info.outbound_payload_size &&
        !sol->advertised_oversize) {
        sol->advertised_oversize = 1;
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.sol_packet_larger_than_advertised",
            "len=%u outbound=%u action=accept", length, sol->info.outbound_payload_size);
    }
    if (!data[0] && length != 4) {
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.sol_packet_rejected", "reason=zero_sequence len=%u", length);
        return fail(sol, BC_PROTOCOL_ERROR);
    }
    BC_LOG_TRACE(BC_LOG_CATEGORY_IPMI, "ipmi.sol_packet",
        "len=%u seq=%u ack=%u count=%u flags=0x%02x", length, data[0], data[1], data[2], data[3]);
    uint32_t advance = packet_sequence - sol->latest_packet;
    if (!sol->latest_packet || (advance && advance < UINT32_C(0x80000000))) sol->latest_packet = packet_sequence;
    if (data[3] & 8) sol->info.flags |= BC_IPMI_SOL_OVERRUN;
    if (data[3] & 4) sol->info.flags |= BC_IPMI_SOL_BREAK_DETECTED;
    if (data[3] & 0x20) sol->info.flags |= BC_IPMI_SOL_TRANSFER_UNAVAILABLE;
    else sol->info.flags &= ~BC_IPMI_SOL_TRANSFER_UNAVAILABLE;
    if (data[3] & 0x10) {
        sol->owned = 0; sol->info.state = BC_IPMI_SOL_CLOSED;
        sol->info.status = sol->waiting ? BC_OUTCOME_UNKNOWN : BC_CANCELLED;
        return BC_OK;
    }
    uint32_t ack_advance = packet_sequence - sol->tx_ack_floor;
    if (sol->waiting && data[1] == sol->tx_seq && (!sol->tx_ack_floor || (ack_advance && ack_advance < UINT32_C(0x80000000)))) {
        uint8_t count = data[2];
        if (count > sol->tx_count) {
            BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.sol_packet_rejected",
                "reason=ack_count count=%u tx_count=%u flags=0x%02x", count, sol->tx_count, data[3]);
            return fail(sol, BC_PROTOCOL_ERROR);
        }
        /* A zero-character ACK does not confirm delivery. Keep the pending
         * packet and its retry budget; inbound data still needs processing. */
        if (count || !sol->tx_count) {
            if (sol->sent_control & 1) {
                sol->rx_length = 0; sol->rx_seq = sol->rx_count = sol->blocked_seq = 0;
            }
            if (count) { memmove(sol->tx, sol->tx + count, sol->tx_length - count); sol->tx_length -= count; }
            sol->waiting = sol->sent_control = sol->tx_count = 0;
            sol->attempts = 0; sol->delayed = !!(data[3] & 0x40); sol->last_send = sol->now;
        }
    }
    if (!data[0] || sol->info.state == BC_IPMI_SOL_FAILED || sol->info.state == BC_IPMI_SOL_CLOSED) return BC_OK;
    uint8_t sequence = data[0], count = (uint8_t)(length - 4), previous = 0;
    if (sequence == sol->rx_seq) {
        uint8_t common = count < sol->rx_count ? count : sol->rx_count;
        if (memcmp(data + 4, sol->last_rx, common)) {
            BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.sol_packet_rejected",
                "reason=retransmission_mismatch seq=%u count=%u previous=%u", sequence, count, sol->rx_count);
            return fail(sol, BC_PROTOCOL_ERROR);
        }
        if (count <= sol->rx_count) return acknowledge(sol, sequence, count, 0);
        previous = sol->rx_count;
    } else if (sol->rx_seq) {
        uint32_t ahead = packet_sequence - sol->rx_packet_sequence;
        if (!ahead || ahead >= UINT32_C(0x80000000)) return BC_OK;
        if (sequence != next_sequence(sol->rx_seq)) sol->info.flags |= BC_IPMI_SOL_DATA_LOSS;
    }
    uint32_t extra = count - previous;
    if (extra > sol->rx_capacity - sol->rx_length) {
        sol->blocked_seq = sequence; sol->blocked_need = extra;
        return acknowledge(sol, sequence, 0, 1);
    }
    if (extra) memcpy(sol->rx + sol->rx_length, data + 4 + previous, extra);
    sol->rx_length += extra;
    memcpy(sol->last_rx, data + 4, count);
    sol->rx_seq = sequence; sol->rx_count = count; sol->rx_packet_sequence = packet_sequence;
    sol->blocked_seq = 0;
    return acknowledge(sol, sequence, count, 0);
}
bc_status bc_ipmi_sol_config_get(bc_ipmi_session *session, bc_ipmi_sol_config *out, uint8_t *completion) {
    if (!session || !out || !completion) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out);
    uint8_t probe[2] = {BC_IPMI_DEFAULT_CHANNEL, 1}, capabilities[8]; uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, 0x4e, (bc_bytes){probe, 1},
        completion, capabilities, sizeof(capabilities), &length);
    if (status == BC_OK && *completion == 0xcc) {
        probe[0] = 1;
        status = bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, 0x4e, (bc_bytes){probe, 1},
            completion, capabilities, sizeof(capabilities), &length);
    }
    if (status != BC_OK) return status;
    if (*completion) return BC_UNSUPPORTED;
    if (length != 8) return BC_PROTOCOL_ERROR;
    if (!(capabilities[0] & 2)) return BC_UNSUPPORTED;
    status = bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, 0x4f, (bc_bytes){probe, 2},
        completion, capabilities, sizeof(capabilities), &length);
    if (status != BC_OK) return status;
    if (*completion) return BC_UNSUPPORTED;
    if (length != 1) return BC_PROTOCOL_ERROR;
    out->payload_version = capabilities[0];
    if ((out->payload_version >> 4) != 1 || (out->payload_version & 15) > 9) return BC_UNSUPPORTED;
    static const uint8_t parameters[] = {1, 2, 5, 6, 7, 8};
    /* Some BMCs (e.g. Dell iDRAC) do not answer SOL configuration requests for
     * the default/current channel selector but do answer on their LAN channel 1.
     * Probe with the first parameter before committing to a channel. */
    uint8_t channel = BC_IPMI_DEFAULT_CHANNEL, response[8]; uint32_t n = 0;
    uint8_t request[4] = {channel, parameters[0], 0, 0};
    bc_status probe_status = bc_ipmi_session_command(session, 0x0c, 0x22, (bc_bytes){request, sizeof(request)},
        completion, response, sizeof(response), &n);
    if (probe_status == BC_TIMEOUT || (probe_status == BC_OK && *completion)) {
        uint8_t fallback_completion = 0, fallback_response[8]; uint32_t fallback_length = 0;
        uint8_t fallback_request[4] = {1, parameters[0], 0, 0};
        bc_status fallback = bc_ipmi_session_command(session, 0x0c, 0x22,
            (bc_bytes){fallback_request, sizeof(fallback_request)}, &fallback_completion,
            fallback_response, sizeof(fallback_response), &fallback_length);
        if (fallback == BC_OK && !fallback_completion) {
            channel = 1; probe_status = BC_OK; *completion = 0; n = fallback_length;
            memcpy(response, fallback_response, sizeof(response));
        }
    }
    if (probe_status != BC_OK) return probe_status;
    /* Older ILOM advertises SOL payloads but has no SOL configuration command.
     * Keep configuration unknown; encrypted Activate Payload is authoritative. */
    if (*completion == 0xc1) {
        out->enabled = BC_IPMI_SOL_ENABLED_UNKNOWN;
        out->payload_channel = probe[0];
        *completion = 0;
        return BC_OK;
    }
    if (*completion) return *completion == 0x80 || *completion == 0xc1 ? BC_UNSUPPORTED : BC_PROTOCOL_ERROR;
    if (n != 2) return BC_PROTOCOL_ERROR;
    out->enabled = response[1] & 1;
    for (unsigned i = 1; i < sizeof(parameters); ++i) {
        uint8_t parameter_request[4] = {channel, parameters[i], 0, 0}, parameter_response[8]; uint32_t parameter_length = 0;
        bc_status parameter_status = bc_ipmi_session_command(session, 0x0c, 0x22,
            (bc_bytes){parameter_request, sizeof(parameter_request)}, completion,
            parameter_response, sizeof(parameter_response), &parameter_length);
        /* Rates, payload channel and port are optional for opening; the payload
         * activation response carries the authoritative port. Keep the values we
         * can read and continue when a BMC omits the rest. */
        if (parameters[i] >= 5) {
            if (parameter_status != BC_OK || *completion ||
                parameter_length != (parameters[i] == 8 ? 3u : 2u)) continue;
        } else {
            if (parameter_status != BC_OK) return parameter_status;
            if (*completion) return *completion == 0x80 || *completion == 0xc1 ? BC_UNSUPPORTED : BC_PROTOCOL_ERROR;
            if (parameter_length != 2) return BC_PROTOCOL_ERROR;
        }
        switch (parameters[i]) {
        case 2:
            out->force_encryption = !!(parameter_response[1] & 0x80); out->force_authentication = !!(parameter_response[1] & 0x40);
            out->privilege = parameter_response[1] & 15; break;
        case 6: out->volatile_bit_rate = parameter_response[1] & 15; break;
        case 5: out->nonvolatile_bit_rate = parameter_response[1] & 15; break;
        case 7: out->payload_channel = parameter_response[1]; break;
        case 8: out->payload_port = (uint16_t)bc_wire_read_le(parameter_response + 1, 2); break;
        }
    }
    return BC_OK;
}
bc_status bc_ipmi_sol_open(bc_ipmi_session *session, const bc_ipmi_sol_options *options, uint64_t now, bc_ipmi_sol **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!session || !options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        options->instance > 15 || options->retries > 100 || options->receive_capacity > 1024u * 1024u ||
        options->send_capacity > 1024u * 1024u || options->retry_interval_ms > 60000 || options->keepalive_ms > 600000)
        return BC_INVALID_ARGUMENT;
    const bc_ipmi_session_info *session_info = bc_ipmi_session_info_get(session);
    if (!session_info || session_info->integrity_algorithm == BC_IPMI_INTEGRITY_ALG_NONE ||
        session_info->confidentiality_algorithm == BC_IPMI_CONFIDENTIALITY_ALG_NONE) return BC_UNSUPPORTED;
    bc_ipmi_sol *sol = calloc(1, sizeof(*sol));
    if (!sol) return BC_NO_MEMORY;
    sol->rx_capacity = options->receive_capacity ? options->receive_capacity : 8192;
    sol->tx_capacity = options->send_capacity ? options->send_capacity : 8192;
    if (sol->rx_capacity < 255 || !sol->tx_capacity) { free(sol); return BC_INVALID_ARGUMENT; }
    sol->rx = malloc(sol->rx_capacity); sol->tx = malloc(sol->tx_capacity);
    if (!sol->rx || !sol->tx) { free(sol->rx); free(sol->tx); free(sol); return BC_NO_MEMORY; }
    sol->session = session; sol->interval = options->retry_interval_ms ? options->retry_interval_ms : 500;
    sol->retries = options->retries; sol->keepalive = options->keepalive_ms ? options->keepalive_ms : 15000;
    sol->now = sol->last_keepalive = now;
    sol->info.struct_size = sizeof(sol->info); sol->info.instance = options->instance ? options->instance : 1;
    sol->info.port = options->session_port ? options->session_port : 623;
    sol->info.cleanup_status = BC_OK;
    *out = sol;
    bc_status status = bc_ipmi_payload_attach(session, sol, feed);
    if (status != BC_OK) return fail(sol, status);
    sol->attached = 1;
    bc_ipmi_sol_config config;
    status = bc_ipmi_sol_config_get(session, &config, &sol->info.completion_code);
    if (status != BC_OK) return fail(sol, status);
    if (!config.enabled) return fail(sol, BC_UNSUPPORTED);
    uint8_t request[6] = {1, sol->info.instance, 0xc4, 0, 0, 0}, response[16]; uint32_t n = 0;
    status = command(sol, 0x4a, request, 1, response, sizeof(response), &n);
    BC_LOG_DEBUG(BC_LOG_CATEGORY_IPMI, "ipmi.sol.activation_status",
        "status=%s completion=%u length=%u values=%u,%u,%u", bc_status_string(status),
        sol->info.completion_code, n, n > 0 ? response[0] : 0, n > 1 ? response[1] : 0, n > 2 ? response[2] : 0);
    if (status == BC_TIMEOUT || (status == BC_OK && n < 3)) {
        /* Some BMCs (e.g. Dell iDRAC) do not answer Get Payload Activation
         * Status. Activate Payload itself reports an occupied instance, so skip
         * the advisory pre-check instead of failing the whole SOL session. */
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.sol.activation_status_skipped",
            "status=%s length=%u", bc_status_string(status), n);
        sol->info.completion_code = 0;
    } else {
        if (status != BC_OK) return fail(sol, status);
        if (bc_wire_read_le(response + 1, 2) & (UINT32_C(1) << (sol->info.instance - 1))) return fail(sol, BC_BUSY);
    }
    sol->attempted = 1;
    status = command(sol, 0x48, request, sizeof(request), response, sizeof(response), &n);
    BC_LOG_DEBUG(BC_LOG_CATEGORY_IPMI, "ipmi.sol.activate",
        "status=%s completion=%u length=%u", bc_status_string(status), sol->info.completion_code, n);
    if (status != BC_OK) {
        if (sol->info.completion_code) sol->attempted = 0;
        if (!sol->info.completion_code) { sol->info.state = BC_IPMI_SOL_OUTCOME_UNKNOWN; sol->info.status = BC_OUTCOME_UNKNOWN; return BC_OUTCOME_UNKNOWN; }
        return fail(sol, status);
    }
    if (n != 12) return fail(sol, BC_PROTOCOL_ERROR);
    sol->info.inbound_payload_size = (uint16_t)bc_wire_read_le(response + 4, 2);
    sol->info.outbound_payload_size = (uint16_t)bc_wire_read_le(response + 6, 2);
    uint16_t port = (uint16_t)bc_wire_read_le(response + 8, 2);
    if (sol->info.port != port) { sol->info.port = port; return fail(sol, BC_UNSUPPORTED); }
    if (sol->info.inbound_payload_size < 5 || sol->info.outbound_payload_size < 4) return fail(sol, BC_PROTOCOL_ERROR);
    uint32_t id = 0;
    status = owner(sol, &id);
    if (status != BC_OK) return fail(sol, status);
    if (!owner_matches(id, session_info->bmc_session_id)) return fail(sol, BC_OUTCOME_UNKNOWN);
    sol->owned = 1; sol->info.state = BC_IPMI_SOL_ACTIVE;
    return BC_OK;
}
static bc_status send_pending(bc_ipmi_sol *sol, int retry) {
    uint8_t data[259];
    if (!retry) {
        sol->tx_seq = next_sequence(sol->tx_seq); sol->tx_count = 0;
        sol->sent_control = sol->control; sol->control = 0;
        if (!sol->sent_control) {
            uint32_t count = sol->info.inbound_payload_size - 4;
            if (count > 255) count = 255;
            if (count > sol->tx_length) count = sol->tx_length;
            sol->tx_count = (uint8_t)count;
        }
        sol->attempts = 0;
        sol->tx_ack_floor = sol->latest_packet;
    }
    data[0] = sol->tx_seq; data[1] = data[2] = 0; data[3] = sol->sent_control;
    if (sol->tx_count) memcpy(data + 4, sol->tx, sol->tx_count);
    sol->waiting = 1; sol->last_send = sol->now;
    bc_status status = bc_ipmi_payload_send(sol->session, data, 4u + sol->tx_count);
    return status == BC_OK ? BC_OK : fail(sol, BC_OUTCOME_UNKNOWN);
}
bc_status bc_ipmi_sol_poll(bc_ipmi_sol *sol, uint64_t now, uint32_t timeout_ms) {
    if (!sol || now < sol->now || timeout_ms > 1000) return BC_INVALID_ARGUMENT;
    sol->now = now;
    if (sol->info.state != BC_IPMI_SOL_ACTIVE) return sol->info.status ? sol->info.status : BC_BUSY;
    bc_status status;
    if (now - sol->last_keepalive >= sol->keepalive) {
        uint32_t id = 0; status = owner(sol, &id); sol->last_keepalive = now;
        if (status != BC_OK) return fail(sol, status);
        if (!owner_matches(id, bc_ipmi_session_info_get(sol->session)->bmc_session_id)) {
            sol->owned = 0; sol->info.state = BC_IPMI_SOL_CLOSED;
            sol->info.status = sol->waiting ? BC_OUTCOME_UNKNOWN : BC_CANCELLED; return sol->info.status;
        }
    }
    if (sol->waiting && now - sol->last_send >= sol->interval) {
        if (sol->attempts >= sol->retries) return fail(sol, BC_OUTCOME_UNKNOWN);
        ++sol->attempts; status = send_pending(sol, 1); if (status != BC_OK) return status;
    } else if (!sol->waiting && (sol->tx_length || sol->control) && (!sol->delayed || now - sol->last_send >= sol->interval)) {
        sol->delayed = 0; status = send_pending(sol, 0); if (status != BC_OK) return status;
    }
    status = bc_ipmi_payload_poll(sol->session, timeout_ms);
    if (status == BC_TIMEOUT) return BC_OK;
    return status == BC_OK ? BC_OK : fail(sol, status);
}
bc_status bc_ipmi_sol_write(bc_ipmi_sol *sol, bc_bytes data, uint32_t *accepted) {
    if (!sol || !accepted || (data.length && !data.data)) return BC_INVALID_ARGUMENT;
    *accepted = 0;
    if (sol->info.state != BC_IPMI_SOL_ACTIVE) return sol->info.status ? sol->info.status : BC_BUSY;
    if (sol->control || sol->sent_control) return BC_BUSY;
    uint32_t n = sol->tx_capacity - sol->tx_length;
    if (data.length < n) n = (uint32_t)data.length;
    if (n) memcpy(sol->tx + sol->tx_length, data.data, n);
    sol->tx_length += n; *accepted = n;
    return !n && data.length ? BC_BUSY : BC_OK;
}
bc_status bc_ipmi_sol_read(bc_ipmi_sol *sol, uint8_t *out, uint32_t capacity, uint32_t *length) {
    if (!sol || !length || (capacity && !out)) return BC_INVALID_ARGUMENT;
    uint32_t n = sol->rx_length < capacity ? sol->rx_length : capacity;
    if (n) { memcpy(out, sol->rx, n); memmove(sol->rx, sol->rx + n, sol->rx_length - n); }
    sol->rx_length -= n; *length = n;
    if (sol->blocked_seq && sol->info.state == BC_IPMI_SOL_ACTIVE && sol->blocked_need <= sol->rx_capacity - sol->rx_length) {
        bc_status status = acknowledge(sol, sol->blocked_seq, 0, 0);
        if (status != BC_OK) return fail(sol, status);
        sol->blocked_seq = 0;
    }
    return BC_OK;
}
static bc_status control(bc_ipmi_sol *sol, uint8_t flags) {
    if (!sol) return BC_INVALID_ARGUMENT;
    if (sol->info.state != BC_IPMI_SOL_ACTIVE || sol->tx_length || sol->waiting || sol->control) return BC_BUSY;
    sol->control = flags; return BC_OK;
}
bc_status bc_ipmi_sol_break(bc_ipmi_sol *sol) { return control(sol, 0x10); }
bc_status bc_ipmi_sol_flush(bc_ipmi_sol *sol, uint32_t directions) {
    if (!directions || (directions & ~3u)) return BC_INVALID_ARGUMENT;
    return control(sol, (uint8_t)(((directions & 1) ? 2 : 0) | ((directions & 2) ? 1 : 0)));
}
bc_status bc_ipmi_sol_info_get(const bc_ipmi_sol *sol, bc_ipmi_sol_info *out) {
    if (!sol || !out || out->struct_size != sizeof(*out)) return BC_INVALID_ARGUMENT;
    *out = sol->info; out->receive_pending = sol->rx_length; out->send_pending = sol->tx_length;
    if (sol->tx_length || sol->waiting || sol->control) out->flags |= BC_IPMI_SOL_INPUT_PENDING;
    return BC_OK;
}
bc_status bc_ipmi_sol_close(bc_ipmi_sol *sol) {
    if (!sol) return BC_INVALID_ARGUMENT;
    if (!sol->attached) return sol->info.cleanup_status != BC_OK ? sol->info.cleanup_status : sol->info.status;
    sol->closing = 1;
    bc_status status = BC_OK;
    if (sol->attempted) {
        uint32_t id = 0; status = owner(sol, &id);
        if (status == BC_OK && owner_matches(id, bc_ipmi_session_info_get(sol->session)->bmc_session_id)) {
            uint8_t request[6] = {1, sol->info.instance, 0, 0, 0, 0}, response[8]; uint32_t n = 0;
            status = command(sol, 0x49, request, sizeof(request), response, sizeof(response), &n);
            if (sol->info.completion_code == 0x80) status = BC_OK;
        }
    }
    sol->info.cleanup_status = status;
    if (status != BC_OK) { sol->closing = 0; return status; }
    bc_ipmi_payload_detach(sol->session, sol); sol->attached = sol->owned = sol->attempted = 0;
    sol->info.state = BC_IPMI_SOL_CLOSED;
    if (sol->waiting) sol->info.status = BC_OUTCOME_UNKNOWN;
    else if (sol->tx_length || sol->control) sol->info.status = BC_CANCELLED;
    return sol->info.status;
}
void bc_ipmi_sol_destroy(bc_ipmi_sol *sol) {
    if (!sol) return;
    bc_ipmi_payload_detach(sol->session, sol);
    if (sol->tx) { volatile uint8_t *p = sol->tx; for (uint32_t i = 0; i < sol->tx_capacity; ++i) p[i] = 0; }
    if (sol->rx) { volatile uint8_t *p = sol->rx; for (uint32_t i = 0; i < sol->rx_capacity; ++i) p[i] = 0; }
    free(sol->tx); free(sol->rx); free(sol);
}

static bc_status stream_read(void *context, uint64_t now, uint32_t timeout,
    uint8_t *data, uint32_t capacity, uint32_t *length) {
    bc_ipmi_sol *sol = context;
    bc_status status = bc_ipmi_sol_read(sol, data, capacity, length);
    if (status != BC_OK || *length) return status;
    bc_status polled = bc_ipmi_sol_poll(sol, now, timeout);
    if (polled != BC_OK && polled != BC_TIMEOUT) return polled;
    status = bc_ipmi_sol_read(sol, data, capacity, length);
    return status == BC_OK && !*length ? polled : status;
}
static bc_status stream_write(void *context, bc_bytes bytes, uint32_t *accepted) {
    return bc_ipmi_sol_write(context, bytes, accepted);
}
static bc_status stream_control(void *context, uint32_t command) {
    return command == BC_SERIAL_CONTROL_BREAK ? bc_ipmi_sol_break(context) : BC_UNSUPPORTED;
}
static bc_status stream_info(const void *context, bc_serial_info *out) {
    bc_ipmi_sol_info info = {0}; info.struct_size = sizeof(info);
    bc_status status = bc_ipmi_sol_info_get(context, &info);
    if (status != BC_OK) return status;
    uint32_t state = info.state == BC_IPMI_SOL_ACTIVE ? BC_SERIAL_ACTIVE :
        info.state == BC_IPMI_SOL_CLOSED ? BC_SERIAL_CLOSED : BC_SERIAL_FAILED;
    *out = (bc_serial_info){sizeof(*out), state, BC_SERIAL_READ | BC_SERIAL_BREAK | BC_SERIAL_BUFFERED_INPUT |
        (state == BC_SERIAL_ACTIVE ? BC_SERIAL_WRITE : 0), info.status, info.cleanup_status,
        info.receive_pending, info.send_pending, info.flags, info.port};
    return BC_OK;
}
static bc_status stream_close(void *context) {
    (void)bc_ipmi_sol_close(context);
    bc_ipmi_sol_info info = {0}; info.struct_size = sizeof(info);
    bc_status status = bc_ipmi_sol_info_get(context, &info);
    return status == BC_OK ? info.cleanup_status : status;
}
bc_status bc_ipmi_sol_stream(bc_ipmi_sol *sol, bc_serial_stream **out) {
    static const bc_serial_provider provider = {sizeof(provider), stream_read, stream_write,
        stream_control, stream_info, stream_close, NULL};
    return bc_serial_wrap(&provider, sol, out);
}

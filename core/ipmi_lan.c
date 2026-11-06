#include "bcontrol/ipmi_lan.h"
#include <stdio.h>
#include <string.h>

static bc_status lan_completion(uint8_t code) {
    if (!code) return BC_OK;
    if (code == 0x80) return BC_UNSUPPORTED;
    if (code == 0xd4) return BC_AUTHENTICATION_FAILED;
    if (code == 0xc0 || code == 0x81) return BC_BUSY;
    if (code == 0xc3) return BC_TIMEOUT;
    if (code == 0xcc) return BC_INVALID_ARGUMENT;
    if (code == 0xc1 || code == 0xcb || code == 0xcd) return BC_UNSUPPORTED;
    return BC_PROTOCOL_ERROR;
}

const char *bc_ipmi_lan_ip_source_name(uint8_t source) {
    switch (source) {
    case 0: return "unknown";
    case 1: return "static";
    case 2: return "dhcp";
    case 3: return "bios";
    case 4: return "other";
    default: return "reserved";
    }
}

const char *bc_ipmi_lan_set_in_progress_name(uint8_t state) {
    switch (state) {
    case 0: return "not-in-progress";
    case 1: return "in-progress";
    case 2: return "commit";
    default: return "reserved";
    }
}

bc_status bc_ipmi_lan_ipv4_format(const bc_ipmi_lan_parameter *parameter, char *out, uint32_t capacity) {
    if (!parameter || !out || capacity < 16 || !(parameter->flags & BC_IPMI_LAN_PARAM_PRESENT) ||
        parameter->data_length < 4)
        return BC_UNSUPPORTED;
    int written = snprintf(out, capacity, "%u.%u.%u.%u",
        parameter->data[0], parameter->data[1], parameter->data[2], parameter->data[3]);
    return written > 0 && (uint32_t)written < capacity ? BC_OK : BC_NO_MEMORY;
}

bc_status bc_ipmi_lan_mac_format(const bc_ipmi_lan_parameter *parameter, char *out, uint32_t capacity) {
    if (!parameter || !out || capacity < 18 || !(parameter->flags & BC_IPMI_LAN_PARAM_PRESENT) ||
        parameter->data_length < 6)
        return BC_UNSUPPORTED;
    int written = snprintf(out, capacity, "%02x:%02x:%02x:%02x:%02x:%02x",
        parameter->data[0], parameter->data[1], parameter->data[2],
        parameter->data[3], parameter->data[4], parameter->data[5]);
    return written > 0 && (uint32_t)written < capacity ? BC_OK : BC_NO_MEMORY;
}

bc_status bc_ipmi_lan_vlan_parse(const bc_ipmi_lan_parameter *parameter, uint32_t *vlan_id, uint32_t *enabled) {
    if (!parameter || !(parameter->flags & BC_IPMI_LAN_PARAM_PRESENT) || parameter->data_length < 2)
        return BC_UNSUPPORTED;
    if (vlan_id) *vlan_id = (uint32_t)parameter->data[0] | (uint32_t)(parameter->data[1] & 0x0f) << 8;
    if (enabled) *enabled = (parameter->data[1] & 0x80) != 0;
    return BC_OK;
}

uint32_t bc_ipmi_lan_cipher_suites(const bc_ipmi_lan_channel *channel, uint8_t *out, uint32_t capacity) {
    if (!channel || !out) return 0;
    const bc_ipmi_lan_parameter *entries = &channel->parameters[BC_IPMI_LAN_PARAM_CIPHER_SUITE_ENTRIES];
    if (!(entries->flags & BC_IPMI_LAN_PARAM_PRESENT) || entries->data_length < 1) return 0;
    uint32_t available = entries->data[0];
    if (available > entries->data_length - 1) available = entries->data_length - 1;
    if (available > capacity) available = capacity;
    memcpy(out, entries->data + 1, available);
    return available;
}

static bc_status channel_info(bc_ipmi_session *session, uint8_t channel, bc_ipmi_lan_channel *out) {
    uint8_t code = 0, data[9];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, BC_IPMI_CMD_GET_CHANNEL_INFO,
        (bc_bytes){&channel, 1}, &code, data, sizeof(data), &length);
    if (status != BC_OK) { out->status = status; return status; }
    if (code) { out->status = lan_completion(code); out->completion_code = code; return out->status; }
    if (length < 2) { out->status = BC_PROTOCOL_ERROR; return out->status; }
    out->medium_type = data[1] & 0x7f;
    out->is_lan = out->medium_type == BC_IPMI_LAN_MEDIUM_LAN || out->medium_type == BC_IPMI_LAN_MEDIUM_OTHER_LAN;
    out->flags |= BC_IPMI_LAN_CHANNEL_PRESENT;
    out->status = BC_OK;
    return BC_OK;
}

static bc_status parameter_read(bc_ipmi_session *session, uint8_t channel, uint8_t selector,
    uint8_t block_selector, bc_ipmi_lan_parameter *out) {
    uint8_t request[4] = {channel, selector, 0, block_selector};
    uint8_t code = 0, data[BC_IPMI_LAN_MAX_PARAMETER_DATA];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_TRANSPORT, BC_IPMI_CMD_GET_LAN_CONFIG,
        (bc_bytes){request, sizeof(request)}, &code, data, sizeof(data), &length);
    out->selector = selector;
    out->block_selector = block_selector;
    if (status != BC_OK) { out->status = status; return status; }
    if (code) { out->status = lan_completion(code); out->completion_code = code; return out->status; }
    if (length < 1) { out->status = BC_PROTOCOL_ERROR; return out->status; }
    out->status = BC_OK;
    out->revision = data[0];
    out->flags |= BC_IPMI_LAN_PARAM_PRESENT;
    out->data_length = length - 1;
    if (out->data_length) memcpy(out->data, data + 1, out->data_length);
    return BC_OK;
}

/* Cipher suite entries arrive one block per read; the first data byte of each
 * block counts the IDs that follow. Blocks are appended (count byte dropped)
 * until the advertised count is met, a block comes back short, or the buffer
 * fills. */
static void cipher_chain(bc_ipmi_session *session, uint8_t channel, bc_ipmi_lan_channel *out) {
    bc_ipmi_lan_parameter *entries = &out->parameters[BC_IPMI_LAN_PARAM_CIPHER_SUITE_ENTRIES];
    uint32_t advertised = 0;
    const bc_ipmi_lan_parameter *support = &out->parameters[BC_IPMI_LAN_PARAM_CIPHER_SUITE_SUPPORT];
    if ((support->flags & BC_IPMI_LAN_PARAM_PRESENT) && support->data_length >= 1) advertised = support->data[0];
    uint8_t collected[BC_IPMI_LAN_MAX_CIPHER_SUITES];
    uint32_t total = 0;
    uint8_t revision = 0;
    for (uint8_t block = 0; block < 2 && total < sizeof(collected); ++block) {
        bc_ipmi_lan_parameter current = {0};
        bc_status status = parameter_read(session, channel, BC_IPMI_LAN_PARAM_CIPHER_SUITE_ENTRIES, block, &current);
        if (status != BC_OK || !(current.flags & BC_IPMI_LAN_PARAM_PRESENT) || current.data_length < 2) {
            if (block == 0) *entries = current;
            break;
        }
        revision = current.revision;
        uint32_t count = current.data[0];
        if (count > current.data_length - 1) count = current.data_length - 1;
        if (count > sizeof(collected) - total) count = (uint32_t)sizeof(collected) - total;
        memcpy(collected + total, current.data + 1, count);
        total += count;
        if (count < 16 || (advertised && total >= advertised)) break;
    }
    if (!total && !(entries->flags & BC_IPMI_LAN_PARAM_PRESENT)) return;
    entries->selector = BC_IPMI_LAN_PARAM_CIPHER_SUITE_ENTRIES;
    entries->status = BC_OK;
    entries->revision = revision;
    entries->flags |= BC_IPMI_LAN_PARAM_PRESENT;
    if (advertised && advertised < total) total = advertised;
    entries->data[0] = (uint8_t)total;
    memcpy(entries->data + 1, collected, total);
    entries->data_length = total + 1;
}

bc_status bc_ipmi_lan_channel_get(bc_ipmi_session *session, uint8_t channel, bc_ipmi_lan_channel *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION ||
        channel < 1 || channel > BC_IPMI_LAN_MAX_CHANNELS)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    out->channel = channel;
    if (channel_info(session, channel, out) != BC_OK || !out->is_lan) return BC_OK;
    for (uint8_t selector = 0; selector <= BC_IPMI_LAN_PARAM_LAST_STANDARD; ++selector) {
        if (selector == BC_IPMI_LAN_PARAM_COMMUNITY_STRING) continue;
        if (selector == BC_IPMI_LAN_PARAM_CIPHER_SUITE_ENTRIES) { cipher_chain(session, channel, out); continue; }
        bc_ipmi_lan_parameter *parameter = &out->parameters[selector];
        bc_status status = parameter_read(session, channel, selector, 0, parameter);
        if (status == BC_OK) { out->supported_count++; continue; }
        out->unsupported_count++;
        if (status == BC_TIMEOUT) { out->status = BC_TIMEOUT; break; }
        if (out->status == BC_OK && status != BC_UNSUPPORTED) out->status = status;
    }
    if (out->status == BC_OK && !out->supported_count) out->status = BC_UNSUPPORTED;
    return BC_OK;
}

bc_status bc_ipmi_lan_config_scan(bc_ipmi_session *session, bc_ipmi_lan_config *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    /* 0x0c/0x0d are reserved; 0x0e selects the current channel, not another interface. */
    for (uint8_t channel = 1; channel < 0x0c; ++channel) {
        bc_ipmi_lan_channel *entry = &out->channels[channel - 1];
        entry->struct_size = sizeof(*entry);
        entry->abi_version = BC_ABI_VERSION;
        bc_status status = bc_ipmi_lan_channel_get(session, channel, entry);
        if (status != BC_OK) { entry->status = status; continue; }
        if (entry->flags & BC_IPMI_LAN_CHANNEL_PRESENT) out->channel_count++;
        if (entry->is_lan) {
            out->lan_channel_count++;
            if (entry->status != BC_OK) return entry->status;
        }
    }
    return BC_OK;
}

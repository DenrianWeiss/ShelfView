#include "bcontrol/ipmi_sel.h"
#include "bcontrol/wire.h"
#include <string.h>

#define BC_IPMI_SEL_VERSION 0x51u
#define BC_IPMI_SEL_OPERATION_RESERVE 0x40u
#define BC_IPMI_SEL_OPERATION_OVERFLOW 0x02u
#define BC_IPMI_COMPLETION_RESERVATION_CANCELLED 0xC5u
#define BC_IPMI_COMPLETION_ERASE_IN_PROGRESS 0x81u
#define BC_IPMI_COMPLETION_PROCESSING_TIMEOUT 0xC3u
#define BC_IPMI_SEL_RESERVATION_RETRIES 3u

static bc_status sel_completion(uint8_t code) {
    if (!code) return BC_OK;
    if (code == 0xc1 || code == 0xcb || code == 0xcd) return BC_UNSUPPORTED;
    if (code == 0xd4) return BC_AUTHENTICATION_FAILED;
    if (code == 0xc0 || code == BC_IPMI_COMPLETION_ERASE_IN_PROGRESS) return BC_BUSY;
    if (code == BC_IPMI_COMPLETION_PROCESSING_TIMEOUT) return BC_TIMEOUT;
    return BC_PROTOCOL_ERROR;
}

bc_status bc_ipmi_sel_info_parse(bc_bytes response, bc_ipmi_sel_info *out) {
    if (!response.data || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    if (response.length < 14) return BC_PROTOCOL_ERROR;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    out->version = response.data[0];
    out->record_count = bc_wire_read_le(response.data + 1, 2);
    out->free_space = bc_wire_read_le(response.data + 3, 2);
    out->addition_timestamp = bc_wire_read_le(response.data + 5, 4);
    out->erase_timestamp = bc_wire_read_le(response.data + 9, 4);
    out->operation_support = response.data[13];
    out->reserve_supported = (uint8_t)((response.data[13] & BC_IPMI_SEL_OPERATION_RESERVE) != 0);
    out->overflow = (uint8_t)((response.data[13] & BC_IPMI_SEL_OPERATION_OVERFLOW) != 0);
    return response.data[0] == BC_IPMI_SEL_VERSION ? BC_OK : BC_PROTOCOL_ERROR;
}

bc_status bc_ipmi_sel_entry_parse(bc_bytes record, bc_ipmi_sel_entry *out) {
    if (!record.data || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    if (record.length > BC_IPMI_SEL_RECORD_MAX) return BC_LIMIT_EXCEEDED;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    out->raw_length = (uint8_t)record.length;
    memcpy(out->raw, record.data, record.length);
    if (record.length < 3) return out->status = BC_PROTOCOL_ERROR;
    out->record_id = (uint16_t)bc_wire_read_le(record.data, 2);
    out->record_type = record.data[2];
    if (record.data[2] == 0x02u || record.data[2] >= 0xe0u) {
        if (record.length < 6) return out->status = BC_PROTOCOL_ERROR;
        out->timestamp = bc_wire_read_le(record.data + 3, 3);
        out->flags |= BC_IPMI_SEL_ENTRY_TIMESTAMP_PRESENT;
    }
    out->status = record.length == BC_IPMI_SEL_RECORD_MAX ? BC_OK : BC_PROTOCOL_ERROR;
    return out->status;
}

bc_status bc_ipmi_sel_info_get(bc_ipmi_session *session, bc_ipmi_sel_info *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    uint8_t code = 0, data[16];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_SEL_INFO,
        (bc_bytes){NULL, 0}, &code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (code) return sel_completion(code);
    return bc_ipmi_sel_info_parse((bc_bytes){data, length}, out);
}

static bc_status sel_reserve(bc_ipmi_session *session, uint16_t *reservation) {
    uint8_t code = 0, data[2];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_RESERVE_SEL,
        (bc_bytes){NULL, 0}, &code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (code) return sel_completion(code);
    if (length != 2) return BC_PROTOCOL_ERROR;
    *reservation = (uint16_t)bc_wire_read_le(data, 2);
    return BC_OK;
}

static void log_record(bc_ipmi_sel_log *out, bc_ipmi_sel_entry *entry) {
    if (out->count == BC_IPMI_MAX_SEL_ENTRIES) {
        out->flags |= BC_IPMI_SEL_TRUNCATED;
        return;
    }
    out->entries[out->count++] = *entry;
    if (out->status == BC_OK && entry->status != BC_OK) out->status = entry->status;
}

static void log_error(bc_ipmi_sel_log *out, uint16_t record_id, bc_status status) {
    bc_ipmi_sel_entry entry = {0};
    entry.struct_size = sizeof(entry);
    entry.abi_version = BC_ABI_VERSION;
    entry.record_id = record_id;
    entry.status = status;
    log_record(out, &entry);
    if (!(out->flags & BC_IPMI_SEL_TRUNCATED)) out->status = status;
}

static bc_status log_status(bc_ipmi_sel_log *out) {
    if (out->flags & BC_IPMI_SEL_TRUNCATED) out->status = BC_LIMIT_EXCEEDED;
    return out->status;
}

bc_status bc_ipmi_sel_log_get(bc_ipmi_session *session, bc_ipmi_sel_log *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    bc_ipmi_sel_info info = {0};
    info.struct_size = sizeof(info);
    info.abi_version = BC_ABI_VERSION;
    bc_status status = bc_ipmi_sel_info_get(session, &info);
    if (status != BC_OK) return out->status = status;
    out->info = info;
    if (!info.record_count) return out->status = BC_OK;
    uint16_t reservation = 0;
    if (info.reserve_supported) {
        status = sel_reserve(session, &reservation);
        if (status != BC_OK) return out->status = status;
    }
    uint8_t code = 0, response[2 + BC_IPMI_SEL_RECORD_MAX];
    uint32_t length = 0;
    uint16_t id = 0, next = 0;
    unsigned reservation_retries = 0;
    for (;;) {
        if (out->flags & BC_IPMI_SEL_TRUNCATED) return out->status = BC_LIMIT_EXCEEDED;
        uint8_t request[6];
        bc_wire_write_le(request, reservation, 2);
        bc_wire_write_le(request + 2, id, 2);
        request[4] = 0;
        request[5] = 0xff;
        status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_SEL_ENTRY,
            (bc_bytes){request, sizeof(request)}, &code, response, sizeof(response), &length);
        if (status != BC_OK) return out->status = status;
        if (code == BC_IPMI_COMPLETION_RESERVATION_CANCELLED && info.reserve_supported &&
            reservation_retries < BC_IPMI_SEL_RESERVATION_RETRIES) {
            ++reservation_retries;
            status = sel_reserve(session, &reservation);
            if (status != BC_OK) return out->status = status;
            continue;
        }
        if (code) {
            log_error(out, id, sel_completion(code));
            return log_status(out);
        }
        if (length < 2) return out->status = BC_PROTOCOL_ERROR;
        next = (uint16_t)bc_wire_read_le(response, 2);
        bc_ipmi_sel_entry entry = {0};
        entry.struct_size = sizeof(entry);
        entry.abi_version = BC_ABI_VERSION;
        bc_ipmi_sel_entry_parse((bc_bytes){response + 2, length - 2}, &entry);
        log_record(out, &entry);
        if (next == 0xffff) return log_status(out);
        id = next;
    }
}

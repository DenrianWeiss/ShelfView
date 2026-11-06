#include "bcontrol/ipmi_io_guard.h"
#include <string.h>

static uint32_t target(uint8_t selector) {
    switch (selector) {
    case 0: return BC_BOOT_NONE;
    case 1: return BC_BOOT_PXE;
    case 2: return BC_BOOT_DISK;
    case 5: return BC_BOOT_CD;
    case 6: return BC_BOOT_SETUP;
    case 7: return BC_BOOT_REMOTE_FLOPPY;
    case 8: return BC_BOOT_REMOTE_CD;
    case 9: return BC_BOOT_REMOTE_PRIMARY;
    case 11: return BC_BOOT_REMOTE_DISK;
    case 15: return BC_BOOT_FLOPPY;
    default: return BC_BOOT_UNKNOWN;
    }
}
bc_status bc_ipmi_boot_flags_parse(const uint8_t *data, uint32_t length, bc_ipmi_boot_info *out) {
    if (!data || !out) return BC_INVALID_ARGUMENT;
    if (length != 7 || data[0] != 1 || (data[1] & 0x7f) != 5) return BC_PROTOCOL_ERROR;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out); out->boot.struct_size = sizeof(out->boot);
    out->boot.target = target((data[3] >> 2) & 0xf);
    out->boot.mode = data[2] & 0x20 ? BC_BOOT_MODE_UEFI : BC_BOOT_MODE_LEGACY;
    out->boot.flags = BC_BOOT_ONCE_SUPPORTED;
    if (data[2] & 0x80) out->boot.flags |= BC_BOOT_ENABLED;
    if (data[2] & 0x40) out->boot.flags |= BC_BOOT_PERSISTENT;
    if (data[1] & 0x80) out->boot.flags |= BC_BOOT_LOCKED;
    memcpy(out->raw, data + 2, 5);
    return BC_OK;
}
bc_status bc_ipmi_boot_flags_build(const bc_ipmi_boot_info *current, uint32_t selected, uint32_t mode, uint8_t out[6]) {
    if (!current || current->struct_size != sizeof(*current) || !out || mode > BC_BOOT_MODE_UEFI) return BC_INVALID_ARGUMENT;
    if (current->boot.flags & BC_BOOT_LOCKED) return BC_BUSY;
    uint8_t selector;
    switch (selected) {
    case BC_BOOT_NONE: selector = 0; break;
    case BC_BOOT_PXE: selector = 1; break;
    case BC_BOOT_DISK: selector = 2; break;
    case BC_BOOT_CD: selector = 5; break;
    case BC_BOOT_SETUP: selector = 6; break;
    case BC_BOOT_REMOTE_FLOPPY: selector = 7; break;
    case BC_BOOT_REMOTE_CD: selector = 8; break;
    case BC_BOOT_REMOTE_PRIMARY: selector = 9; break;
    case BC_BOOT_REMOTE_DISK: selector = 11; break;
    case BC_BOOT_FLOPPY: selector = 15; break;
    default: return BC_UNSUPPORTED;
    }
    if (selected != BC_BOOT_NONE && mode == BC_BOOT_MODE_PRESERVE && !(current->boot.flags & BC_BOOT_ENABLED))
        return BC_CONFIRMATION_REQUIRED;
    out[0] = 5; memcpy(out + 1, current->raw, 5);
    if (selected == BC_BOOT_NONE) { out[1] &= 0x7f; return BC_OK; }
    out[1] = (uint8_t)((out[1] | 0x80) & ~0x40u);
    if (mode == BC_BOOT_MODE_UEFI) out[1] |= 0x20;
    else if (mode == BC_BOOT_MODE_LEGACY) out[1] &= (uint8_t)~0x20u;
    out[2] = (uint8_t)((out[2] & ~0x3cu) | (selector << 2));
    return BC_OK;
}
bc_status bc_ipmi_boot_get(bc_ipmi_session *session, bc_ipmi_boot_info *out, uint8_t *completion) {
    if (!session || !out || !completion) return BC_INVALID_ARGUMENT;
    const uint8_t request[3] = {5, 0, 0};
    uint8_t response[16]; uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_CHASSIS, 9,
        (bc_bytes){request, sizeof(request)}, completion, response, sizeof(response), &length);
    if (status != BC_OK) return status;
    if (*completion == 0x80 || *completion == 0xc1) return BC_UNSUPPORTED;
    if (*completion) return BC_PROTOCOL_ERROR;
    return bc_ipmi_boot_flags_parse(response, length, out);
}

static bc_status set_parameter(bc_ipmi_session *session, const uint8_t *data, uint32_t size, uint8_t *completion) {
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_mutate(session, BC_IPMI_NETFN_CHASSIS, 8,
        (bc_bytes){data, size}, completion, NULL, 0, &length);
    if (status != BC_OK) return status;
    if (*completion == 0x80 || *completion == 0xc1) return BC_UNSUPPORTED;
    return *completion ? BC_PROTOCOL_ERROR : BC_OK;
}
static bc_status set_once(bc_ipmi_session *session, uint32_t selected, uint32_t mode,
    bc_ipmi_io_guard *guard, bc_ipmi_boot_result *out) {
    if (!session || !out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out);
    out->write_status = out->cleanup_status = out->verify_status = BC_CANCELLED;
    uint8_t payload[6], response[8], completion = 0;
    bc_status status = bc_ipmi_boot_get(session, &out->before, &out->completion);
    if (status != BC_OK) return status;
    status = bc_ipmi_boot_flags_build(&out->before, selected, mode, payload);
    if (status != BC_OK) return status;
    const uint8_t query[3] = {0, 0, 0}, acquire[2] = {0, 1}, release[2] = {0, 0};
    uint32_t length = 0;
    status = bc_ipmi_session_command(session, BC_IPMI_NETFN_CHASSIS, 9,
        (bc_bytes){query, sizeof(query)}, &out->completion, response, sizeof(response), &length);
    if (status != BC_OK) return status;
    if (out->completion == 0x80 || out->completion == 0xc1) return BC_UNSUPPORTED;
    if (out->completion || length != 3 || response[0] != 1 || (response[1] & 0x7f) != 0) return BC_PROTOCOL_ERROR;
    if ((response[1] & 0x80) || (response[2] & 3)) return BC_BUSY;
    status = set_parameter(session, acquire, sizeof(acquire), &out->completion);
    /* A lost acquire response cannot establish ownership; do not clear another writer's lock. */
    if (status != BC_OK) return status;
    status = bc_ipmi_boot_get(session, &out->before, &out->completion);
    if (status == BC_OK) status = bc_ipmi_boot_flags_build(&out->before, selected, mode, payload);
    if (status == BC_OK) {
        out->flags |= BC_IPMI_BOOT_WRITE_ATTEMPTED;
        out->write_status = set_parameter(session, payload, sizeof(payload), &out->completion);
        status = out->write_status;
    }
    out->flags |= BC_IPMI_BOOT_CLEANUP_ATTEMPTED;
    out->cleanup_status = guard ? bc_ipmi_io_guard_begin_cleanup(guard, 3000) : BC_OK;
    if (out->cleanup_status == BC_OK) {
        out->cleanup_status = set_parameter(session, release, sizeof(release), &out->cleanup_completion);
        if (guard) bc_ipmi_io_guard_end_cleanup(guard);
    }
    if (out->flags & BC_IPMI_BOOT_WRITE_ATTEMPTED) {
        out->verify_status = bc_ipmi_boot_get(session, &out->after, &completion);
        if (out->verify_status == BC_OK && memcmp(out->after.raw, payload + 1, 5)) out->verify_status = BC_PROTOCOL_ERROR;
        if (out->verify_status == BC_OK) out->flags |= BC_IPMI_BOOT_VERIFIED;
        if (status != BC_OK || out->verify_status != BC_OK || out->cleanup_status != BC_OK) return BC_OUTCOME_UNKNOWN;
    }
    if (out->cleanup_status != BC_OK) return BC_OUTCOME_UNKNOWN;
    return status;
}
bc_status bc_ipmi_boot_set_once(bc_ipmi_session *session, uint32_t selected, uint32_t mode, bc_ipmi_boot_result *out) {
    return set_once(session, selected, mode, NULL, out);
}
bc_status bc_ipmi_boot_set_once_guarded(bc_ipmi_session *session, uint32_t selected, uint32_t mode,
    bc_ipmi_io_guard *guard, bc_ipmi_boot_result *out) {
    if (!guard) return BC_INVALID_ARGUMENT;
    return set_once(session, selected, mode, guard, out);
}

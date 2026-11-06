#include "bcontrol/ipmi_session.h"
#include "log_internal.h"
#include <string.h>

static bc_status chassis_completion(uint8_t code) {
    if (!code) return BC_OK;
    if (code == 0xc1 || code == 0xcb || code == 0xcd) return BC_UNSUPPORTED;
    if (code == 0xd4) return BC_AUTHENTICATION_FAILED;
    if (code == 0xc0 || code == 0x81) return BC_BUSY;
    if (code == 0xc3) return BC_TIMEOUT;
    return BC_PROTOCOL_ERROR;
}

/* Bit fields follow IPMI 2.0 chapter 28 with the E374 addendum for the
 * misc chassis state byte; see the session header for the flag values. */
bc_status bc_ipmi_chassis_status_get(bc_ipmi_session *session, bc_ipmi_chassis_status *out) {
    if (!session || !out || out->struct_size != sizeof(*out)) return BC_INVALID_ARGUMENT;
    uint8_t code = 0, data[16];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_CHASSIS, BC_IPMI_CMD_GET_CHASSIS_STATUS,
        (bc_bytes){NULL, 0}, &code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (code) return chassis_completion(code);
    if (length < 3) return BC_PROTOCOL_ERROR;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->power_state = (data[0] & 1u) ? BC_POWER_ON : BC_POWER_OFF;
    out->raw_power_state = (uint8_t)(data[0] & 0x1f);
    out->power_restore_policy = (data[0] >> 5) & 3u;
    out->last_power_event = data[1];
    out->misc_state = data[2];
    if (data[2] & 0x01) out->flags |= BC_IPMI_CHASSIS_INTRUSION_ACTIVE;
    if (data[2] & 0x02) out->flags |= BC_IPMI_CHASSIS_FRONT_PANEL_LOCKOUT;
    if (data[2] & 0x04) out->flags |= BC_IPMI_CHASSIS_DRIVE_FAULT;
    if (data[2] & 0x08) out->flags |= BC_IPMI_CHASSIS_FAN_FAULT;
    if (data[2] & 0x40) {
        out->flags |= BC_IPMI_CHASSIS_IDENTIFY_SUPPORTED;
        switch ((data[2] >> 4) & 3u) {
        case 1: out->flags |= BC_IPMI_CHASSIS_IDENTIFY_ON | BC_IPMI_CHASSIS_IDENTIFY_TEMPORARY; break;
        case 2: out->flags |= BC_IPMI_CHASSIS_IDENTIFY_ON; break;
        case 3: out->flags |= BC_IPMI_CHASSIS_IDENTIFY_STATE_UNKNOWN; break;
        default: break;
        }
    }
    if (length >= 5) {
        out->flags |= BC_IPMI_CHASSIS_ACPI_PRESENT;
        out->acpi_power_state = data[4];
    }
    BC_LOG_DEBUG(BC_LOG_CATEGORY_IPMI, "ipmi.chassis_status", "power=%u raw=0x%02x flags=%u length=%u",
        out->power_state, out->raw_power_state, out->flags, length);
    return BC_OK;
}

bc_status bc_ipmi_chassis_capabilities_get(bc_ipmi_session *session, bc_ipmi_chassis_capabilities *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    uint8_t code = 0, data[8];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_CHASSIS, BC_IPMI_CMD_GET_CHASSIS_CAPABILITIES,
        (bc_bytes){NULL, 0}, &code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (code) return chassis_completion(code);
    if (length < 5) return BC_PROTOCOL_ERROR;
    if (data[0] & 0x01) out->flags |= BC_IPMI_CHASSIS_CAP_INTRUSION_SENSOR;
    if (data[0] & 0x02) out->flags |= BC_IPMI_CHASSIS_CAP_FRONT_PANEL_LOCKOUT;
    if (data[0] & 0x04) out->flags |= BC_IPMI_CHASSIS_CAP_DIAGNOSTIC_INTERRUPT;
    if (data[0] & 0x08) out->flags |= BC_IPMI_CHASSIS_CAP_POWER_INTERLOCK;
    out->fru_device_address = data[1];
    out->sdr_device_address = data[2];
    out->sel_device_address = data[3];
    out->sm_device_address = data[4];
    if (length >= 6) {
        out->bridge_device_address = data[5];
        out->bridge_present = 1;
    }
    return BC_OK;
}

bc_status bc_ipmi_system_restart_cause_get(bc_ipmi_session *session, bc_ipmi_restart_cause *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    uint8_t code = 0, data[2];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_CHASSIS, BC_IPMI_CMD_GET_SYSTEM_RESTART_CAUSE,
        (bc_bytes){NULL, 0}, &code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (code) return chassis_completion(code);
    if (length < 2) return BC_PROTOCOL_ERROR;
    out->cause = data[0] & 0x0f;
    out->channel = data[1];
    return BC_OK;
}

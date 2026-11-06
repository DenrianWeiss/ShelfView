#include "bcontrol/ipmi_platform.h"
#include "bcontrol/ipmi_sensor.h"
#include "bcontrol/ipmi_sel.h"
#include "bcontrol/ipmi_fru.h"
#include "bcontrol/ipmi_lan.h"
#include "yyjson.h"
#include "sol_cmd.h"
#include "ipmi_budget.h"
#include "server.h"
#include "sensor_json.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bc_string text(const char *value) { return (bc_string){value, value ? strlen(value) : 0}; }
static uint32_t parse_u32(const char *text_value, int *ok) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text_value, &end, 0);
    if (errno || !*text_value || *text_value == '-' || *end || value > UINT32_MAX) { *ok = 0; return 0; }
    *ok = 1;
    return (uint32_t)value;
}
static const char *auth_name(uint8_t algorithm) {
    switch (algorithm) {
    case BC_IPMI_AUTH_ALG_NONE: return "none";
    case BC_IPMI_AUTH_ALG_HMAC_SHA1: return "hmac-sha1";
    case BC_IPMI_AUTH_ALG_HMAC_MD5: return "hmac-md5";
    case BC_IPMI_AUTH_ALG_HMAC_SHA256: return "hmac-sha256";
    default: return "unknown";
    }
}
static const char *integrity_name(uint8_t algorithm) {
    switch (algorithm) {
    case BC_IPMI_INTEGRITY_ALG_NONE: return "none";
    case BC_IPMI_INTEGRITY_ALG_HMAC_SHA1_96: return "hmac-sha1-96";
    case BC_IPMI_INTEGRITY_ALG_HMAC_MD5_128: return "hmac-md5-128";
    case BC_IPMI_INTEGRITY_ALG_MD5_128: return "md5-128";
    case BC_IPMI_INTEGRITY_ALG_HMAC_SHA256_128: return "hmac-sha256-128";
    default: return "unknown";
    }
}
static const char *confidentiality_name(uint8_t algorithm) {
    switch (algorithm) {
    case BC_IPMI_CONFIDENTIALITY_ALG_NONE: return "none";
    case BC_IPMI_CONFIDENTIALITY_ALG_AES_CBC_128: return "aes-cbc-128";
    case BC_IPMI_CONFIDENTIALITY_ALG_XRC4_128: return "xrc4-128";
    case BC_IPMI_CONFIDENTIALITY_ALG_XRC4_40: return "xrc4-40";
    default: return "unknown";
    }
}
static void add_session(yyjson_mut_doc *doc, yyjson_mut_val *out, const bc_ipmi_session_info *info) {
    yyjson_mut_obj_add_uint(doc, out, "cipher_suite", info->cipher_suite_id);
    yyjson_mut_obj_add_strcpy(doc, out, "auth", auth_name(info->auth_algorithm));
    yyjson_mut_obj_add_strcpy(doc, out, "integrity", integrity_name(info->integrity_algorithm));
    yyjson_mut_obj_add_strcpy(doc, out, "confidentiality", confidentiality_name(info->confidentiality_algorithm));
    yyjson_mut_obj_add_uint(doc, out, "bmc_session_id", info->bmc_session_id);
}
static void add_device(yyjson_mut_doc *doc, yyjson_mut_val *out, const uint8_t *data, uint32_t length) {
    if (length < 11) {
        yyjson_mut_obj_add_uint(doc, out, "device_id_bytes", length);
        return;
    }
    yyjson_mut_obj_add_uint(doc, out, "device_id", data[0]);
    yyjson_mut_obj_add_uint(doc, out, "device_revision", data[1] & 0x0f);
    char firmware[16];
    snprintf(firmware, sizeof(firmware), "%u.%u", data[2], ((data[3] >> 4) & 0x0f) * 10 + (data[3] & 0x0f));
    yyjson_mut_obj_add_strcpy(doc, out, "firmware", firmware);
    yyjson_mut_obj_add_strcpy(doc, out, "ipmi_version", data[4] == 2 ? "2.0" : data[4] == 1 ? "1.5" : "unknown");
    yyjson_mut_obj_add_uint(doc, out, "manufacturer_id", (uint32_t)data[6] | (uint32_t)data[7] << 8 | (uint32_t)data[8] << 16);
    yyjson_mut_obj_add_uint(doc, out, "product_id", (uint32_t)data[9] | (uint32_t)data[10] << 8);
}
static const char *power_state_name(uint32_t state) {
    return state == BC_POWER_ON ? "on" : state == BC_POWER_OFF ? "off" : "unknown";
}
static const char *restore_policy_name(uint32_t policy) {
    switch (policy) {
    case BC_IPMI_POWER_RESTORE_ALWAYS_OFF: return "always-off";
    case BC_IPMI_POWER_RESTORE_PREVIOUS: return "previous";
    case BC_IPMI_POWER_RESTORE_ALWAYS_ON: return "always-on";
    default: return "unknown";
    }
}
static const char *restart_cause_name(uint32_t cause) {
    static const char *names[] = {"unknown", "chassis-power-command", "pushbutton-reset", "pushbutton-power-up",
        "watchdog-expired", "oem", "always-restore-policy", "previous-restore-policy", "pef-reset",
        "pef-power-cycle", "soft-reset", "rtc-wakeup"};
    return cause < 12 ? names[cause] : "reserved";
}
static void add_chassis_status_json(yyjson_mut_doc *doc, yyjson_mut_val *out, const bc_ipmi_chassis_status *chassis) {
    yyjson_mut_obj_add_strcpy(doc, out, "power_state", power_state_name(chassis->power_state));
    yyjson_mut_obj_add_uint(doc, out, "power_flags", chassis->flags);
    yyjson_mut_obj_add_uint(doc, out, "last_power_event", chassis->last_power_event);
    yyjson_mut_obj_add_uint(doc, out, "misc_state", chassis->misc_state);
    yyjson_mut_obj_add_strcpy(doc, out, "power_restore_policy", restore_policy_name(chassis->power_restore_policy));
    yyjson_mut_obj_add_bool(doc, out, "intrusion_active", (chassis->flags & BC_IPMI_CHASSIS_INTRUSION_ACTIVE) != 0);
    yyjson_mut_obj_add_bool(doc, out, "front_panel_lockout", (chassis->flags & BC_IPMI_CHASSIS_FRONT_PANEL_LOCKOUT) != 0);
    yyjson_mut_obj_add_bool(doc, out, "drive_fault", (chassis->flags & BC_IPMI_CHASSIS_DRIVE_FAULT) != 0);
    yyjson_mut_obj_add_bool(doc, out, "fan_fault", (chassis->flags & BC_IPMI_CHASSIS_FAN_FAULT) != 0);
    if ((chassis->flags & BC_IPMI_CHASSIS_IDENTIFY_SUPPORTED) &&
        !(chassis->flags & BC_IPMI_CHASSIS_IDENTIFY_STATE_UNKNOWN)) {
        const char *state = (chassis->flags & BC_IPMI_CHASSIS_IDENTIFY_ON) == 0 ? "off" :
            (chassis->flags & BC_IPMI_CHASSIS_IDENTIFY_TEMPORARY) ? "temporary" : "indefinite";
        yyjson_mut_obj_add_strcpy(doc, out, "identify_state", state);
    }
    if (chassis->flags & BC_IPMI_CHASSIS_ACPI_PRESENT)
        yyjson_mut_obj_add_uint(doc, out, "acpi_power_state", chassis->acpi_power_state);
}
static bc_status add_chassis_readonly(yyjson_mut_doc *doc, yyjson_mut_val *out, bc_ipmi_session *session) {
    bc_ipmi_chassis_status status = {0};
    status.struct_size = sizeof(status);
    bc_status result = bc_ipmi_chassis_status_get(session, &status);
    if (result != BC_OK) {
        yyjson_mut_obj_add_str(doc, out, "chassis_status", bc_status_string(result));
        return result;
    }
    add_chassis_status_json(doc, out, &status);
    bc_ipmi_chassis_capabilities caps = {0};
    caps.struct_size = sizeof(caps);
    caps.abi_version = BC_ABI_VERSION;
    bc_status current = bc_ipmi_chassis_capabilities_get(session, &caps);
    yyjson_mut_val *caps_obj = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, out, "capabilities", caps_obj);
    yyjson_mut_obj_add_str(doc, caps_obj, "status", bc_status_string(current));
    if (current == BC_OK) {
        yyjson_mut_obj_add_bool(doc, caps_obj, "intrusion_sensor", (caps.flags & BC_IPMI_CHASSIS_CAP_INTRUSION_SENSOR) != 0);
        yyjson_mut_obj_add_bool(doc, caps_obj, "front_panel_lockout", (caps.flags & BC_IPMI_CHASSIS_CAP_FRONT_PANEL_LOCKOUT) != 0);
        yyjson_mut_obj_add_bool(doc, caps_obj, "diagnostic_interrupt", (caps.flags & BC_IPMI_CHASSIS_CAP_DIAGNOSTIC_INTERRUPT) != 0);
        yyjson_mut_obj_add_bool(doc, caps_obj, "power_interlock", (caps.flags & BC_IPMI_CHASSIS_CAP_POWER_INTERLOCK) != 0);
        yyjson_mut_obj_add_uint(doc, caps_obj, "fru_device_address", caps.fru_device_address);
        yyjson_mut_obj_add_uint(doc, caps_obj, "sdr_device_address", caps.sdr_device_address);
        yyjson_mut_obj_add_uint(doc, caps_obj, "sel_device_address", caps.sel_device_address);
        yyjson_mut_obj_add_uint(doc, caps_obj, "sm_device_address", caps.sm_device_address);
        if (caps.bridge_present) yyjson_mut_obj_add_uint(doc, caps_obj, "bridge_device_address", caps.bridge_device_address);
    } else if (result == BC_OK && current != BC_UNSUPPORTED) {
        result = current;
    }
    bc_ipmi_restart_cause restart = {0};
    restart.struct_size = sizeof(restart);
    restart.abi_version = BC_ABI_VERSION;
    current = bc_ipmi_system_restart_cause_get(session, &restart);
    yyjson_mut_val *restart_obj = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, out, "restart_cause", restart_obj);
    yyjson_mut_obj_add_str(doc, restart_obj, "status", bc_status_string(current));
    if (current == BC_OK) {
        yyjson_mut_obj_add_uint(doc, restart_obj, "cause", restart.cause);
        yyjson_mut_obj_add_strcpy(doc, restart_obj, "cause_name", restart_cause_name(restart.cause));
        yyjson_mut_obj_add_uint(doc, restart_obj, "channel", restart.channel);
    } else if (result == BC_OK && current != BC_UNSUPPORTED) {
        result = current;
    }
    return result;
}
static int parse_power_action(const char *value) {
    if (!strcmp(value, "off")) return BC_IPMI_CHASSIS_CONTROL_OFF;
    if (!strcmp(value, "on")) return BC_IPMI_CHASSIS_CONTROL_ON;
    if (!strcmp(value, "cycle")) return BC_IPMI_CHASSIS_CONTROL_CYCLE;
    if (!strcmp(value, "hard-reset")) return BC_IPMI_CHASSIS_CONTROL_HARD_RESET;
    if (!strcmp(value, "diag-interrupt")) return BC_IPMI_CHASSIS_CONTROL_DIAGNOSTIC_INTERRUPT;
    if (!strcmp(value, "soft-off")) return BC_IPMI_CHASSIS_CONTROL_SOFT_SHUTDOWN;
    return -1;
}
static int boot_target(const char *value) {
    if (!strcmp(value, "remote-cd")) return BC_BOOT_REMOTE_CD;
    if (!strcmp(value, "remote-fd")) return BC_BOOT_REMOTE_FLOPPY;
    if (!strcmp(value, "remote-disk")) return BC_BOOT_REMOTE_DISK;
    if (!strcmp(value, "remote-primary")) return BC_BOOT_REMOTE_PRIMARY;
    if (!strcmp(value, "floppy")) return BC_BOOT_FLOPPY;
    const char *const names[] = {"none", "pxe", "disk", "cd", "setup"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) if (!strcmp(value, names[i])) return (int)i;
    return -1;
}
static void add_boot(yyjson_mut_doc *doc, yyjson_mut_val *out, const bc_ipmi_boot_info *value) {
    yyjson_mut_val *boot = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "boot", boot);
    yyjson_mut_obj_add_uint(doc, boot, "target", value->boot.target);
    yyjson_mut_obj_add_uint(doc, boot, "mode", value->boot.mode);
    yyjson_mut_obj_add_uint(doc, boot, "flags", value->boot.flags);
    yyjson_mut_obj_add_uint(doc, boot, "selector", (value->raw[1] >> 2) & 15);
    yyjson_mut_obj_add_uint(doc, boot, "supported_targets", value->boot.supported_targets);
}
static bc_status add_sensors(yyjson_mut_doc *doc, yyjson_mut_val *out, bc_ipmi_session *session) {
    bc_ipmi_sensor_list *list = malloc(sizeof(*list));
    if (!list) return BC_NO_MEMORY;
    bc_status status = bc_ipmi_sdr_scan(session, list);
    if (status != BC_OK) { free(list); return status; }
    yyjson_mut_obj_add_uint(doc, out, "sensor_count", list->count);
    yyjson_mut_obj_add_uint(doc, out, "sdr_record_count", list->record_count);
    yyjson_mut_obj_add_uint(doc, out, "sdr_flags", list->flags);
    yyjson_mut_val *sensors = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, out, "sensors", sensors);
    for (uint32_t i = 0; i < list->count; ++i) {
        const bc_ipmi_sensor_record *record = &list->sensors[i];
        yyjson_mut_val *row = yyjson_mut_obj(doc);
        yyjson_mut_arr_add_val(sensors, row);
        yyjson_mut_obj_add_uint(doc, row, "number", record->sensor_number);
        yyjson_mut_obj_add_uint(doc, row, "type", record->sensor_type);
        yyjson_mut_obj_add_uint(doc, row, "unit", record->unit_base);
        yyjson_mut_obj_add_strcpy(doc, row, "id", record->id);
        bc_ipmi_sensor_reading reading;
        if (bc_ipmi_sensor_read(session, record, &reading) == BC_OK) {
            if (reading.flags & BC_IPMI_SENSOR_READING_PRESENT) yyjson_mut_obj_add_real(doc, row, "reading", reading.reading);
            else yyjson_mut_obj_add_null(doc, row, "reading");
            yyjson_mut_obj_add_uint(doc, row, "flags", reading.flags);
        } else yyjson_mut_obj_add_strcpy(doc, row, "reading", "unavailable");
    }
    free(list);
    return BC_OK;
}
static bc_status add_sel(yyjson_mut_doc *doc, yyjson_mut_val *out, bc_ipmi_session *session) {
    bc_ipmi_sel_log *log = calloc(1, sizeof(*log));
    if (!log) return BC_NO_MEMORY;
    log->struct_size = sizeof(*log);
    log->abi_version = BC_ABI_VERSION;
    bc_status status = bc_ipmi_sel_log_get(session, log);
    yyjson_mut_obj_add_str(doc, out, "sel_status", bc_status_string(status));
    yyjson_mut_val *sel = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, out, "sel", sel);
    yyjson_mut_obj_add_uint(doc, sel, "entries_in_use", log->info.record_count);
    yyjson_mut_obj_add_uint(doc, sel, "free_space", log->info.free_space);
    yyjson_mut_obj_add_bool(doc, sel, "overflow", log->info.overflow != 0);
    if (log->flags & BC_IPMI_SEL_TRUNCATED) yyjson_mut_obj_add_bool(doc, sel, "truncated", 1);
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, sel, "entries", rows);
    for (uint32_t i = 0; i < log->count; ++i) {
        const bc_ipmi_sel_entry *entry = &log->entries[i];
        yyjson_mut_val *row = yyjson_mut_obj(doc);
        yyjson_mut_arr_add_val(rows, row);
        yyjson_mut_obj_add_uint(doc, row, "record_id", entry->record_id);
        yyjson_mut_obj_add_uint(doc, row, "record_type", entry->record_type);
        if (entry->flags & BC_IPMI_SEL_ENTRY_TIMESTAMP_PRESENT) yyjson_mut_obj_add_uint(doc, row, "timestamp", entry->timestamp);
        else yyjson_mut_obj_add_null(doc, row, "timestamp");
        yyjson_mut_val *raw = yyjson_mut_arr(doc);
        yyjson_mut_obj_add_val(doc, row, "raw", raw);
        for (uint32_t j = 0; j < entry->raw_length; ++j) yyjson_mut_arr_add_uint(doc, raw, entry->raw[j]);
        yyjson_mut_obj_add_str(doc, row, "status", bc_status_string(entry->status));
    }
    free(log);
    return status;
}
static void add_fru_field(yyjson_mut_doc *doc, yyjson_mut_val *parent, const char *name, const bc_ipmi_fru_field *field) {
    yyjson_mut_val *row = yyjson_mut_obj(doc);
    if (name) yyjson_mut_obj_add_val(doc, parent, name, row);
    else yyjson_mut_arr_add_val(parent, row);
    yyjson_mut_obj_add_str(doc, row, "status", bc_status_string(field->status));
    yyjson_mut_obj_add_uint(doc, row, "type", field->field_type);
    yyjson_mut_obj_add_strcpy(doc, row, "text", field->text);
    yyjson_mut_val *raw = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, row, "raw", raw);
    for (uint32_t i = 0; i < field->raw_length; ++i) yyjson_mut_arr_add_uint(doc, raw, field->raw[i]);
}
static void add_fru_custom(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *name,
    const bc_ipmi_fru_field *fields, uint32_t count) {
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, obj, name, rows);
    for (uint32_t i = 0; i < count; ++i) add_fru_field(doc, rows, NULL, &fields[i]);
}
static void add_fru_device_row(yyjson_mut_doc *doc, yyjson_mut_val *row, const bc_ipmi_fru_info *fru) {
    yyjson_mut_obj_add_uint(doc, row, "fru_id", fru->fru_id);
    yyjson_mut_obj_add_uint(doc, row, "area_size", fru->area.area_size);
    yyjson_mut_obj_add_bool(doc, row, "word_access", fru->area.word_access != 0);
    yyjson_mut_obj_add_str(doc, row, "status", bc_status_string(fru->status));
    if (fru->flags & BC_IPMI_FRU_TRUNCATED) yyjson_mut_obj_add_bool(doc, row, "truncated", 1);
    if (fru->internal_status) yyjson_mut_obj_add_str(doc, row, "internal_area", bc_status_string(fru->internal_status));
    const bc_ipmi_fru_chassis *chassis = &fru->chassis;
    yyjson_mut_val *chassis_obj = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, row, "chassis", chassis_obj);
    yyjson_mut_obj_add_bool(doc, chassis_obj, "present", chassis->present != 0);
    yyjson_mut_obj_add_str(doc, chassis_obj, "status", bc_status_string(chassis->status));
    yyjson_mut_obj_add_uint(doc, chassis_obj, "type", chassis->chassis_type);
    add_fru_field(doc, chassis_obj, "part_number", &chassis->part_number);
    add_fru_field(doc, chassis_obj, "serial_number", &chassis->serial_number);
    add_fru_custom(doc, chassis_obj, "custom", chassis->custom, chassis->custom_count);
    const bc_ipmi_fru_board *board = &fru->board;
    yyjson_mut_val *board_obj = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, row, "board", board_obj);
    yyjson_mut_obj_add_bool(doc, board_obj, "present", board->present != 0);
    yyjson_mut_obj_add_str(doc, board_obj, "status", bc_status_string(board->status));
    yyjson_mut_obj_add_uint(doc, board_obj, "language", board->language);
    yyjson_mut_obj_add_uint(doc, board_obj, "mfg_date", board->mfg_date);
    add_fru_field(doc, board_obj, "manufacturer", &board->manufacturer);
    add_fru_field(doc, board_obj, "product", &board->product);
    add_fru_field(doc, board_obj, "serial", &board->serial);
    add_fru_field(doc, board_obj, "part_number", &board->part_number);
    add_fru_field(doc, board_obj, "file_id", &board->file_id);
    add_fru_custom(doc, board_obj, "custom", board->custom, board->custom_count);
    const bc_ipmi_fru_product *product = &fru->product;
    yyjson_mut_val *product_obj = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, row, "product", product_obj);
    yyjson_mut_obj_add_bool(doc, product_obj, "present", product->present != 0);
    yyjson_mut_obj_add_str(doc, product_obj, "status", bc_status_string(product->status));
    yyjson_mut_obj_add_uint(doc, product_obj, "language", product->language);
    add_fru_field(doc, product_obj, "manufacturer", &product->manufacturer);
    add_fru_field(doc, product_obj, "name", &product->name);
    add_fru_field(doc, product_obj, "part_number", &product->part_number);
    add_fru_field(doc, product_obj, "version", &product->version);
    add_fru_field(doc, product_obj, "serial", &product->serial);
    add_fru_field(doc, product_obj, "asset_tag", &product->asset_tag);
    add_fru_field(doc, product_obj, "file_id", &product->file_id);
    add_fru_custom(doc, product_obj, "custom", product->custom, product->custom_count);
    yyjson_mut_val *multi = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_val(doc, row, "multi_record", multi);
    yyjson_mut_obj_add_str(doc, multi, "status", bc_status_string(fru->multi_status));
    yyjson_mut_obj_add_uint(doc, multi, "length", fru->multi_length);
    yyjson_mut_val *raw = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, multi, "raw", raw);
    for (uint32_t i = 0; i < fru->multi_length; ++i) yyjson_mut_arr_add_uint(doc, raw, fru->multi_raw[i]);
}
static bc_status add_fru_device(yyjson_mut_doc *doc, yyjson_mut_val *devices, bc_ipmi_session *session, uint8_t fru_id) {
    bc_ipmi_fru_info *fru = calloc(1, sizeof(*fru));
    if (!fru) return BC_NO_MEMORY;
    fru->struct_size = sizeof(*fru);
    fru->abi_version = BC_ABI_VERSION;
    bc_status status = bc_ipmi_fru_info_get(session, fru_id, fru);
    yyjson_mut_val *row = yyjson_mut_obj(doc);
    yyjson_mut_arr_add_val(devices, row);
    add_fru_device_row(doc, row, fru);
    free(fru);
    return status;
}
static bc_status add_fru(yyjson_mut_doc *doc, yyjson_mut_val *out, bc_ipmi_session *session, int single, uint8_t fru_id) {
    yyjson_mut_val *devices = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, out, "fru_devices", devices);
    bc_status status = BC_OK;
    if (single) {
        status = add_fru_device(doc, devices, session, fru_id);
    } else {
        bc_ipmi_fru_inventory *inventory = calloc(1, sizeof(*inventory));
        if (!inventory) return BC_NO_MEMORY;
        inventory->struct_size = sizeof(*inventory);
        inventory->abi_version = BC_ABI_VERSION;
        bc_status scan = bc_ipmi_fru_inventory_get(session, inventory);
        for (uint32_t i = 0; i < inventory->count; ++i) {
            bc_status current = add_fru_device(doc, devices, session, (uint8_t)i);
            if (status == BC_OK && current != BC_OK) status = current;
        }
        if (status == BC_OK && scan != BC_OK) status = scan;
        free(inventory);
    }
    yyjson_mut_obj_add_str(doc, out, "fru_status", bc_status_string(status));
    return status;
}
static bc_status add_lan(yyjson_mut_doc *doc, yyjson_mut_val *out, bc_ipmi_session *session) {
    static const char *const parameter_names[] = {
        "set-in-progress", "auth-type-support", "auth-type-enables", "ip-address", "ip-address-source",
        "mac-address", "subnet-mask", "ipv4-header", "primary-rmcp-port", "secondary-rmcp-port",
        "bmc-arp-control", "gratuitous-arp-interval", "default-gateway", "default-gateway-mac",
        "backup-gateway", "backup-gateway-mac", "community-string", "number-of-destinations",
        "destination-type", "destination-addresses", "vlan-id", "vlan-priority",
        "cipher-suite-support", "cipher-suite-entries", "cipher-suite-privileges",
        "destination-vlan-tags", "bad-password-threshold"
    };
    bc_ipmi_lan_config *config = calloc(1, sizeof(*config));
    if (!config) return BC_NO_MEMORY;
    config->struct_size = sizeof(*config);
    config->abi_version = BC_ABI_VERSION;
    bc_status status = bc_ipmi_lan_config_scan(session, config);
    yyjson_mut_obj_add_uint(doc, out, "channel_count", config->channel_count);
    yyjson_mut_obj_add_uint(doc, out, "lan_channel_count", config->lan_channel_count);
    yyjson_mut_val *channels = yyjson_mut_arr(doc);
    yyjson_mut_obj_add_val(doc, out, "lan_channels", channels);
    for (uint32_t i = 0; i < BC_IPMI_LAN_MAX_CHANNELS; ++i) {
        const bc_ipmi_lan_channel *channel = &config->channels[i];
        if (!(channel->flags & BC_IPMI_LAN_CHANNEL_PRESENT)) continue;
        yyjson_mut_val *row = yyjson_mut_obj(doc);
        yyjson_mut_arr_add_val(channels, row);
        yyjson_mut_obj_add_uint(doc, row, "channel", channel->channel);
        yyjson_mut_obj_add_uint(doc, row, "medium_type", channel->medium_type);
        yyjson_mut_obj_add_bool(doc, row, "is_lan", channel->is_lan != 0);
        yyjson_mut_obj_add_str(doc, row, "status", bc_status_string(channel->status));
        if (!channel->is_lan) continue;
        yyjson_mut_val *parameters = yyjson_mut_arr(doc);
        yyjson_mut_obj_add_val(doc, row, "parameters", parameters);
        for (uint32_t selector = 0; selector <= BC_IPMI_LAN_PARAM_LAST_STANDARD; ++selector) {
            if (selector == BC_IPMI_LAN_PARAM_COMMUNITY_STRING) continue;
            const bc_ipmi_lan_parameter *parameter = &channel->parameters[selector];
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_arr_add_val(parameters, item);
            yyjson_mut_obj_add_uint(doc, item, "selector", selector);
            yyjson_mut_obj_add_str(doc, item, "name", parameter_names[selector]);
            yyjson_mut_obj_add_str(doc, item, "status", bc_status_string(parameter->status));
            if (parameter->status != BC_OK) {
                if (parameter->completion_code) yyjson_mut_obj_add_uint(doc, item, "completion_code", parameter->completion_code);
                continue;
            }
            yyjson_mut_obj_add_uint(doc, item, "revision", parameter->revision);
            if (selector == BC_IPMI_LAN_PARAM_SET_IN_PROGRESS && parameter->data_length >= 1)
                yyjson_mut_obj_add_str(doc, item, "value", bc_ipmi_lan_set_in_progress_name(parameter->data[0]));
            else if (selector == BC_IPMI_LAN_PARAM_IP_ADDRESS_SOURCE && parameter->data_length >= 1)
                yyjson_mut_obj_add_str(doc, item, "value", bc_ipmi_lan_ip_source_name(parameter->data[0]));
            else if ((selector == BC_IPMI_LAN_PARAM_IP_ADDRESS || selector == BC_IPMI_LAN_PARAM_SUBNET_MASK ||
                selector == BC_IPMI_LAN_PARAM_DEFAULT_GATEWAY || selector == BC_IPMI_LAN_PARAM_BACKUP_GATEWAY)) {
                char text_value[16];
                if (bc_ipmi_lan_ipv4_format(parameter, text_value, sizeof(text_value)) == BC_OK)
                    yyjson_mut_obj_add_strcpy(doc, item, "value", text_value);
                else yyjson_mut_obj_add_bool(doc, item, "short_read", 1);
            } else if (selector == BC_IPMI_LAN_PARAM_MAC_ADDRESS || selector == BC_IPMI_LAN_PARAM_DEFAULT_GATEWAY_MAC ||
                selector == BC_IPMI_LAN_PARAM_BACKUP_GATEWAY_MAC) {
                char text_value[18];
                if (bc_ipmi_lan_mac_format(parameter, text_value, sizeof(text_value)) == BC_OK)
                    yyjson_mut_obj_add_strcpy(doc, item, "value", text_value);
                else yyjson_mut_obj_add_bool(doc, item, "short_read", 1);
            } else if (selector == BC_IPMI_LAN_PARAM_VLAN_ID) {
                uint32_t vlan_id = 0, enabled = 0;
                if (bc_ipmi_lan_vlan_parse(parameter, &vlan_id, &enabled) == BC_OK) {
                    yyjson_mut_obj_add_bool(doc, item, "enabled", enabled != 0);
                    yyjson_mut_obj_add_uint(doc, item, "vlan_id", vlan_id);
                }
            } else if (selector == BC_IPMI_LAN_PARAM_CIPHER_SUITE_SUPPORT && parameter->data_length >= 1)
                yyjson_mut_obj_add_uint(doc, item, "value", parameter->data[0]);
            else if (selector == BC_IPMI_LAN_PARAM_CIPHER_SUITE_ENTRIES) {
                uint8_t suites[BC_IPMI_LAN_MAX_CIPHER_SUITES];
                uint32_t count = bc_ipmi_lan_cipher_suites(channel, suites, sizeof(suites));
                yyjson_mut_val *values = yyjson_mut_arr(doc);
                yyjson_mut_obj_add_val(doc, item, "value", values);
                for (uint32_t n = 0; n < count; ++n) yyjson_mut_arr_add_uint(doc, values, suites[n]);
            } else if (selector == BC_IPMI_LAN_PARAM_CIPHER_SUITE_PRIVILEGES && parameter->data_length >= 9) {
                yyjson_mut_val *values = yyjson_mut_arr(doc);
                yyjson_mut_obj_add_val(doc, item, "value", values);
                for (uint32_t n = 0; n < 16; ++n)
                    yyjson_mut_arr_add_uint(doc, values, n % 2 ? parameter->data[1 + n / 2] >> 4 : parameter->data[1 + n / 2] & 0x0f);
            }
            if (selector != BC_IPMI_LAN_PARAM_CIPHER_SUITE_ENTRIES) {
                yyjson_mut_val *raw = yyjson_mut_arr(doc);
                yyjson_mut_obj_add_val(doc, item, "raw", raw);
                for (uint32_t n = 0; n < parameter->data_length; ++n)
                    yyjson_mut_arr_add_uint(doc, raw, parameter->data[n]);
            }
        }
    }
    free(config);
    return status;
}
static void usage(void) {
    fputs("bcontrol-agent ipmi --host HOST [--port 623] [--channel 0x0e] [--timeout-ms n] [--budget-ms n] [--retries n]\n"
          "  [--command device-id|cipher-suites|power-status|sensors|sensor-details|sel|fru|chassis|capabilities|boot-status|lan] [--action off|on|cycle|hard-reset|soft-off|diag-interrupt]\n"
          "  [--fru-id n] [--boot-once none|pxe|disk|cd|setup|remote-cd|remote-fd|remote-disk|remote-primary|floppy --boot-mode preserve|legacy|uefi]\n"
          "  [--netfn n --cmd n --data hex] [--allow-suite3] [--confirm-suite3]\n"
          "Credentials: BC_BMC_USERNAME and BC_BMC_PASSWORD environment variables.\n", stderr);
}
static bc_status add_sensor_details(yyjson_mut_doc *doc, yyjson_mut_val *out, bc_ipmi_session *session) {
    bc_ipmi_sensor_catalog *list = calloc(1, sizeof(*list));
    if (!list) return BC_NO_MEMORY;
    list->struct_size = sizeof(*list); list->abi_version = BC_ABI_VERSION;
    bc_status status = bc_ipmi_sensor_catalog_get(session, list);
    yyjson_mut_obj_add_str(doc, out, "catalog_status", bc_status_string(status));
    yyjson_mut_obj_add_uint(doc, out, "sensor_count", list->count);
    yyjson_mut_obj_add_uint(doc, out, "sdr_record_count", list->record_count);
    yyjson_mut_val *rows = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, out, "sensors", rows);
    if (status != BC_OK) { free(list); return status; }
    for (uint32_t i = 0; i < list->count; ++i) {
        const bc_ipmi_sensor_descriptor *record = &list->sensors[i];
        bc_sensor_details details = {0}; details.struct_size = sizeof(details); details.abi_version = BC_ABI_VERSION;
        bc_status current = bc_ipmi_sensor_details_get(session, record, &details);
        if (status == BC_OK && current != BC_OK) status = current;
        yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(rows, row);
        yyjson_mut_obj_add_uint(doc, row, "number", record->sensor.sensor_number);
        yyjson_mut_obj_add_uint(doc, row, "type", record->sensor.sensor_type);
        yyjson_mut_obj_add_uint(doc, row, "event_type", record->sensor.event_type);
        yyjson_mut_obj_add_uint(doc, row, "record_id", record->record_id);
        yyjson_mut_obj_add_uint(doc, row, "record_type", record->record_type);
        yyjson_mut_obj_add_uint(doc, row, "owner", record->sensor.owner_id);
        yyjson_mut_obj_add_uint(doc, row, "owner_channel", record->owner_channel);
        yyjson_mut_obj_add_uint(doc, row, "owner_lun", record->sensor.owner_lun);
        yyjson_mut_obj_add_uint(doc, row, "share_index", record->share_index);
        yyjson_mut_obj_add_uint(doc, row, "share_count", record->share_count);
        yyjson_mut_obj_add_strcpy(doc, row, "id", record->name);
        bc_agent_sensor_details_json(doc, row, &details);
    }
    free(list); return status;
}
static int emit(yyjson_mut_doc *doc, int exit_code, int sol_mode) {
    char *json = yyjson_mut_write(doc, 0, NULL);
    if (json) { fprintf(sol_mode ? stderr : stdout, "%s\n", json); free(json); }
    yyjson_mut_doc_free(doc);
    return exit_code;
}
int bc_agent_ipmi_inspect(int argc, char **argv) {
    int sol_mode = !strcmp(argv[0], "sol");
    int sensor_details = 0;
    bc_string host = {0}, username = text(getenv("BC_BMC_USERNAME")), password = text(getenv("BC_BMC_PASSWORD"));
    uint32_t port = 623, channel = 0, timeout_ms = 0, budget_ms = 15000, retries = 0;
    uint32_t raw_netfn = 0, raw_command = 0, boot_mode = BC_BOOT_MODE_PRESERVE;
    int boot_status = 0, boot_selection = -1, mode_given = 0;
    uint8_t raw_data[256];
    uint32_t raw_length = 0;
    int raw = 0, allow_suite3 = 0, confirm_suite3 = 0, cipher_suites = 0, power_status = 0, sensors = 0, capabilities = 0, sel = 0, fru = 0, chassis_read = 0, lan_read = 0, power_action = -1;
    int fru_id_given = 0;
    uint8_t fru_id = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--allow-suite3")) { allow_suite3 = 1; continue; }
        if (!strcmp(argv[i], "--confirm-suite3")) { confirm_suite3 = 1; continue; }
        if (i + 1 >= argc) { usage(); return 2; }
        const char *value = argv[++i];
        int ok = 0;
        if (!strcmp(argv[i - 1], "--host")) host = text(value);
        else if (!strcmp(argv[i - 1], "--port")) { port = parse_u32(value, &ok); if (!ok || port > 65535) return 2; }
        else if (!strcmp(argv[i - 1], "--channel")) { channel = parse_u32(value, &ok); if (!ok) return 2; }
        else if (!strcmp(argv[i - 1], "--timeout-ms")) { timeout_ms = parse_u32(value, &ok); if (!ok) return 2; }
        else if (!strcmp(argv[i - 1], "--budget-ms")) { budget_ms = parse_u32(value, &ok); if (!ok || !budget_ms) return 2; }
        else if (!strcmp(argv[i - 1], "--retries")) { retries = parse_u32(value, &ok); if (!ok) return 2; }
        else if (!strcmp(argv[i - 1], "--command")) {
            if (!strcmp(value, "cipher-suites")) cipher_suites = 1;
            else if (!strcmp(value, "power-status")) power_status = 1;
            else if (!strcmp(value, "sensors")) sensors = 1;
            else if (!strcmp(value, "sensor-details")) { sensors = 1; sensor_details = 1; }
            else if (!strcmp(value, "sel")) sel = 1;
            else if (!strcmp(value, "fru")) fru = 1;
            else if (!strcmp(value, "chassis")) chassis_read = 1;
            else if (!strcmp(value, "lan")) lan_read = 1;
            else if (!strcmp(value, "capabilities")) capabilities = 1;
            else if (!strcmp(value, "boot-status")) boot_status = 1;
            else if (strcmp(value, "device-id")) { usage(); return 2; }
        } else if (!strcmp(argv[i - 1], "--fru-id")) {
            uint32_t value32 = parse_u32(value, &ok);
            if (!ok || value32 > 255) return 2;
            fru_id = (uint8_t)value32;
            fru_id_given = 1;
        } else if (!strcmp(argv[i - 1], "--boot-once")) {
            boot_selection = boot_target(value); if (boot_selection < 0) return 2;
        } else if (!strcmp(argv[i - 1], "--boot-mode")) {
            mode_given = 1;
            if (!strcmp(value, "preserve")) boot_mode = BC_BOOT_MODE_PRESERVE;
            else if (!strcmp(value, "legacy")) boot_mode = BC_BOOT_MODE_LEGACY;
            else if (!strcmp(value, "uefi")) boot_mode = BC_BOOT_MODE_UEFI;
            else return 2;
        } else if (!strcmp(argv[i - 1], "--action")) {
            power_action = parse_power_action(value);
            if (power_action < 0) { usage(); return 2; }
        } else if (!strcmp(argv[i - 1], "--netfn")) { raw_netfn = parse_u32(value, &ok); if (!ok || raw_netfn > 0x3f) return 2; raw = 1; }
        else if (!strcmp(argv[i - 1], "--cmd")) { raw_command = parse_u32(value, &ok); if (!ok || raw_command > 0xff) return 2; raw = 1; }
        else if (!strcmp(argv[i - 1], "--data")) {
            size_t length = strlen(value);
            if (length % 2 || length / 2 > sizeof(raw_data)) { usage(); return 2; }
            for (size_t j = 0; j < length / 2; ++j) {
                unsigned byte = 0;
                if (sscanf(value + j * 2, "%2x", &byte) != 1) { usage(); return 2; }
                raw_data[j] = (uint8_t)byte;
            }
            raw_length = (uint32_t)(length / 2);
            raw = 1;
        } else { usage(); return 2; }
    }
    if (!host.length || (mode_given && boot_selection < 0) ||
        (sol_mode && (raw || boot_status || boot_selection >= 0 || power_action >= 0 || power_status || sensors || capabilities || sel || fru || chassis_read || lan_read || cipher_suites)) ||
        ((boot_status || boot_selection >= 0) && (raw || power_action >= 0 || power_status || sensors || capabilities || sel || fru || chassis_read || lan_read || cipher_suites)) ||
        (fru_id_given && !fru) ||
        (boot_status && boot_selection >= 0)) { usage(); return 2; }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return 2;
    yyjson_mut_val *out = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, out);
    bc_agent_ipmi_budget budget = {0};
    bc_ipmi_io *io = NULL;
    bc_ipmi_crypto *crypto = NULL;
    bc_ipmi_session *session = NULL;
    uint64_t preparation_started = bc_agent_now_ms();
    bc_status status = bc_ipmi_udp_create_timeout(host, (uint16_t)port, budget_ms, &io);
    uint64_t preparation_elapsed = bc_agent_now_ms() - preparation_started;
    if (status == BC_OK && preparation_elapsed >= budget_ms) status = BC_TIMEOUT;
    if (status == BC_OK) status = bc_agent_ipmi_budget_open(&budget, io, budget_ms - (uint32_t)preparation_elapsed);
    if (status == BC_OK) status = bc_ipmi_openssl_crypto_create(&crypto);
    bc_ipmi_session_options options = {0};
    options.struct_size = sizeof(options);
    options.abi_version = BC_ABI_VERSION;
    options.io = bc_ipmi_io_guard_get(budget.guard);
    options.crypto = crypto;
    options.timeout_ms = timeout_ms;
    options.retries = retries;
    options.channel = channel;
    options.suite3_policy = allow_suite3 || confirm_suite3 ? BC_IPMI_SUITE3_ALLOWED : BC_IPMI_SUITE3_DISALLOWED;
    options.username = username;
    options.password = password;
    if (status == BC_OK) status = bc_ipmi_session_create(&options, &session);
    if (status == BC_OK) status = bc_ipmi_session_open(session);
    const bc_ipmi_session_info *info = bc_ipmi_session_info_get(session);
    if (status == BC_CONFIRMATION_REQUIRED) {
        const bc_ipmi_cipher_suites *suites = bc_ipmi_session_cipher_suites_get(session);
        if (!confirm_suite3) {
            yyjson_mut_obj_add_strcpy(doc, out, "status", "confirmation_required");
            yyjson_mut_obj_add_uint(doc, out, "cipher_suite", 3);
            yyjson_mut_obj_add_uint(doc, out, "offered_suites", suites ? suites->count : 0);
            bc_agent_ipmi_budget_cleanup(&budget);
            bc_ipmi_session_destroy(session);
            bc_agent_ipmi_budget_destroy(&budget);
            bc_ipmi_openssl_crypto_destroy(crypto);
            bc_ipmi_udp_destroy(io);
            return emit(doc, 3, sol_mode);
        }
        status = bc_ipmi_session_confirm_suite3(session);
    }
    if (status == BC_OK) yyjson_mut_obj_add_strcpy(doc, out, "status", "ok");
    else {
        yyjson_mut_obj_add_strcpy(doc, out, "status", bc_status_string(status));
        if (info && (info->flags & BC_IPMI_SESSION_LEGACY_1_5)) yyjson_mut_obj_add_bool(doc, out, "legacy_ipmi_1_5", 1);
        bc_agent_ipmi_budget_cleanup(&budget);
        bc_ipmi_session_destroy(session);
        bc_agent_ipmi_budget_destroy(&budget);
        bc_ipmi_openssl_crypto_destroy(crypto);
        bc_ipmi_udp_destroy(io);
        return emit(doc, status == BC_INVALID_ARGUMENT ? 2 : 1, sol_mode);
    }
    if (sol_mode) {
        yyjson_mut_doc_free(doc);
        int result = bc_agent_sol_run(session, (uint16_t)port, &budget);
        bc_agent_ipmi_budget_cleanup(&budget);
        bc_status closed = bc_ipmi_session_close(session);
        fprintf(stderr, "IPMI close=%s\n", bc_status_string(closed));
        bc_ipmi_session_destroy(session); bc_agent_ipmi_budget_destroy(&budget); bc_ipmi_openssl_crypto_destroy(crypto); bc_ipmi_udp_destroy(io);
        return closed == BC_OK ? result : 1;
    }
    add_session(doc, out, info);
    uint8_t completion_code = 0, response_data[256];
    uint32_t response_length = 0;
    if (boot_selection >= 0) {
        bc_ipmi_boot_result result;
        status = bc_ipmi_boot_set_once_guarded(session, (uint32_t)boot_selection, boot_mode, budget.guard, &result);
        yyjson_mut_obj_add_uint(doc, out, "boot_result_flags", result.flags);
        yyjson_mut_obj_add_str(doc, out, "write_status", bc_status_string(result.write_status));
        yyjson_mut_obj_add_str(doc, out, "cleanup_status", bc_status_string(result.cleanup_status));
        yyjson_mut_obj_add_str(doc, out, "verify_status", bc_status_string(result.verify_status));
        if (result.flags & BC_IPMI_BOOT_VERIFIED) add_boot(doc, out, &result.after);
    } else if (boot_status) {
        bc_ipmi_boot_info boot;
        status = bc_ipmi_boot_get(session, &boot, &completion_code);
        if (status == BC_OK) add_boot(doc, out, &boot);
    } else if (power_action >= 0) {
        status = bc_ipmi_chassis_control(session, (uint8_t)power_action, &completion_code);
        if (status == BC_OK) yyjson_mut_obj_add_uint(doc, out, "completion_code", completion_code);
    } else if (power_status) {
        bc_ipmi_chassis_status chassis = {0};
        chassis.struct_size = sizeof(chassis);
        status = bc_ipmi_chassis_status_get(session, &chassis);
        if (status == BC_OK) add_chassis_status_json(doc, out, &chassis);
    } else if (chassis_read) {
        status = add_chassis_readonly(doc, out, session);
    } else if (lan_read) {
        status = add_lan(doc, out, session);
    } else if (capabilities) {
        bc_ipmi_capabilities caps;
        status = bc_ipmi_session_probe(session, &caps);
        if (status == BC_OK) {
            yyjson_mut_obj_add_bool(doc, out, "chassis_status", (caps.flags & BC_IPMI_CAPABILITY_CHASSIS_STATUS) != 0);
            yyjson_mut_obj_add_bool(doc, out, "sdr", (caps.flags & BC_IPMI_CAPABILITY_SDR) != 0);
            yyjson_mut_obj_add_bool(doc, out, "sel", (caps.flags & BC_IPMI_CAPABILITY_SEL) != 0);
            yyjson_mut_obj_add_bool(doc, out, "fru", (caps.flags & BC_IPMI_CAPABILITY_FRU) != 0);
            if (caps.flags & BC_IPMI_CAPABILITY_NO_GRAPHICAL_CONSOLE)
                yyjson_mut_obj_add_bool(doc, out, "graphical_console", false);
            if (caps.flags & BC_IPMI_CAPABILITY_ILOM_SERIAL_CANDIDATE)
                yyjson_mut_obj_add_bool(doc, out, "ilom_serial_candidate", true);
            yyjson_mut_obj_add_uint(doc, out, "sdr_record_count", caps.sdr_record_count);
            yyjson_mut_obj_add_uint(doc, out, "sel_record_count", caps.sel_record_count);
            yyjson_mut_obj_add_strcpy(doc, out, "power_state", power_state_name(caps.chassis_power_state));
        }
    } else if (sensors) {
        status = sensor_details ? add_sensor_details(doc, out, session) : add_sensors(doc, out, session);
    } else if (sel) {
        status = add_sel(doc, out, session);
    } else if (fru) {
        status = add_fru(doc, out, session, fru_id_given, fru_id);
    } else if (raw) {
        status = bc_ipmi_session_mutate(session, (uint8_t)raw_netfn, (uint8_t)raw_command,
            (bc_bytes){raw_data, raw_length}, &completion_code, response_data, sizeof(response_data), &response_length);
        if (status == BC_OK) {
            yyjson_mut_obj_add_uint(doc, out, "completion_code", completion_code);
            yyjson_mut_val *bytes = yyjson_mut_arr(doc);
            yyjson_mut_obj_add_val(doc, out, "data", bytes);
            for (uint32_t i = 0; i < response_length; ++i) yyjson_mut_arr_add_uint(doc, bytes, response_data[i]);
        }
    } else if (cipher_suites) {
        uint8_t request[3] = {(uint8_t)(channel ? channel : BC_IPMI_DEFAULT_CHANNEL), BC_IPMI_PAYLOAD_IPMI, BC_IPMI_CIPHER_LIST_ALL};
        status = bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, BC_IPMI_CMD_GET_CHANNEL_CIPHER_SUITES,
            (bc_bytes){request, sizeof(request)}, &completion_code, response_data, sizeof(response_data), &response_length);
        if (status == BC_OK) {
            yyjson_mut_obj_add_uint(doc, out, "completion_code", completion_code);
            bc_ipmi_response response = {0};
            response.completion_code = completion_code;
            response.data = (bc_bytes){response_data, response_length};
            bc_ipmi_cipher_suites found;
            if (completion_code == BC_IPMI_COMPLETION_OK && bc_ipmi_cipher_suites_parse(&response, &found) == BC_OK)
                yyjson_mut_obj_add_uint(doc, out, "session_suites", found.count);
        }
    } else {
        status = bc_ipmi_session_command(session, BC_IPMI_NETFN_APP, BC_IPMI_CMD_GET_DEVICE_ID,
            (bc_bytes){NULL, 0}, &completion_code, response_data, sizeof(response_data), &response_length);
        if (status == BC_OK) {
            yyjson_mut_obj_add_uint(doc, out, "completion_code", completion_code);
            if (completion_code == BC_IPMI_COMPLETION_OK) add_device(doc, out, response_data, response_length);
        }
    }
    bc_agent_ipmi_budget_cleanup(&budget);
    bc_status close_status = bc_ipmi_session_close(session);
    yyjson_mut_obj_add_strcpy(doc, out, "close", bc_status_string(close_status));
    bc_ipmi_session_destroy(session);
    bc_agent_ipmi_budget_destroy(&budget);
    bc_ipmi_openssl_crypto_destroy(crypto);
    bc_ipmi_udp_destroy(io);
    if (status != BC_OK) yyjson_mut_obj_add_strcpy(doc, out, "command_status", bc_status_string(status));
    return emit(doc, status == BC_OK && completion_code == BC_IPMI_COMPLETION_OK && close_status == BC_OK ? 0 : 1, sol_mode);
}

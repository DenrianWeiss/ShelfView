#include "bcontrol/ipmi_sensor.h"
#include "bcontrol/wire.h"
#include "sensor_internal.h"
#include <math.h>
#include <stdio.h>

static bc_status decode_name(bc_ipmi_sensor_descriptor *out) {
    uint32_t n = out->raw_id_length, used = 0;
    const uint8_t *data = out->raw_id;
    if (!n) return BC_OK;
    if (out->id_encoding == 1) {
        static const char digits[] = "0123456789 -.:,_";
        for (uint32_t i = 0; i < n; ++i) { out->name[used++] = digits[data[i] & 15]; out->name[used++] = digits[data[i] >> 4]; }
        out->name[used] = 0; return BC_OK;
    }
    if (out->id_encoding == 2) {
        uint32_t bits = 0, available = 0;
        for (uint32_t i = 0; i < n; ++i) {
            bits |= (uint32_t)data[i] << available; available += 8;
            while (available >= 6) { out->name[used++] = (char)(32 + (bits & 63)); bits >>= 6; available -= 6; }
        }
        out->name[used] = 0; return BC_OK;
    }
    if (out->id_encoding != 3) return BC_UNSUPPORTED;
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t c = data[i];
        if (!c) return BC_PROTOCOL_ERROR;
        if (c >= 128) out->name[used++] = (char)(0xc0 | (c >> 6));
        out->name[used++] = (char)(c < 128 ? c : 0x80 | (c & 63));
    }
    out->name[used] = 0; return BC_OK;
}
bc_status bc_ipmi_sdr_sensor_parse(bc_bytes record, uint32_t index, bc_ipmi_sensor_descriptor *out) {
    if (!record.data || record.length < 5 || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION) return BC_INVALID_ARGUMENT;
    uint8_t type = record.data[3];
    uint32_t id_offset = type == 1 ? 42 : type == 2 ? 26 : type == 3 ? 11 : 0;
    if (!id_offset) return BC_UNSUPPORTED;
    uint32_t n = record.data[4]; const uint8_t *data = record.data + 5;
    if (n < id_offset + 1 || record.length < n + 5) return BC_PROTOCOL_ERROR;
    uint32_t id_length = data[id_offset] & 31;
    if (id_length > 16 || id_offset + 1 + id_length > n) return BC_PROTOCOL_ERROR;
    uint8_t sharing = type == 2 ? data[18] : type == 3 ? data[7] : 0;
    uint8_t modifier = type == 2 ? data[19] : type == 3 ? data[8] : 0;
    uint32_t count = sharing & 15; if (!count) count = 1;
    if (index >= count || (uint32_t)data[2] + count > 255 || ((modifier & 0x80) && (data[4] & 127u) + count > 128)) return BC_PROTOCOL_ERROR;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->abi_version = BC_ABI_VERSION;
    out->record_type = type; out->record_id = (uint16_t)bc_wire_read_le(record.data, 2);
    out->owner_channel = data[1] >> 4; out->share_count = (uint8_t)count; out->share_index = (uint8_t)index;
    out->id_encoding = data[id_offset] >> 6; out->raw_id_length = (uint8_t)id_length;
    memcpy(out->raw_id, data + id_offset + 1, id_length);
    bc_ipmi_sensor_record *sensor = &out->sensor;
    if (type == 1) {
        bc_status status = bc_ipmi_sdr_parse_record(record.data, record.length, sensor);
        if (status != BC_OK) return status;
    } else {
        sensor->owner_id = data[0]; sensor->owner_lun = data[1] & 3;
        sensor->entity_id = data[3]; sensor->entity_instance = data[4];
        sensor->sensor_type = data[type == 2 ? 7 : 5]; sensor->event_type = data[type == 2 ? 8 : 6];
        sensor->analog_format = 3; sensor->flags |= BC_IPMI_SENSOR_DISCRETE;
        if (type == 2) {
            memcpy(sensor->units, data + 15, 3); sensor->unit_base = data[16];
            sensor->unit_rate = (data[15] >> 3) & 7; sensor->unit_modifier = (data[15] >> 1) & 3;
            sensor->unit_percentage = data[15] & 1; sensor->unit_modifier_type = data[17];
        }
    }
    sensor->sensor_number = (uint8_t)(data[2] + index);
    if (modifier & 0x80) sensor->entity_instance = (uint8_t)((data[4] & 128) | ((data[4] & 127) + index));
    if (type != 3) {
        out->capabilities = data[6]; out->readable_mask = (uint16_t)bc_wire_read_le(data + 13, 2);
        if (sensor->event_type == 1) out->comparison_mask = (uint8_t)(((data[10] >> 4) & 7) | ((data[12] >> 1) & 0x38));
    }
    out->name_status = decode_name(out);
    if (count > 1 && out->name_status == BC_OK) {
        char suffix[8]; unsigned value = (modifier & 127) + index, kind = (sharing >> 4) & 3;
        if (!kind) snprintf(suffix, sizeof(suffix), "%u", value);
        else if (kind == 1) {
            unsigned length = 0; char reversed[4]; ++value;
            do { reversed[length++] = (char)('A' + (value - 1) % 26); value = (value - 1) / 26; } while (value);
            for (unsigned i = 0; i < length; ++i) suffix[i] = reversed[length - 1 - i];
            suffix[length] = 0;
        } else { suffix[0] = 0; out->name_status = BC_UNSUPPORTED; }
        size_t used = strlen(out->name); snprintf(out->name + used, sizeof(out->name) - used, "%s", suffix);
    }
    return BC_OK;
}
static bc_status completion_status(uint8_t code) {
    if (!code) return BC_OK;
    if (code == 0xc1 || code == 0xcb || code == 0xcd) return BC_UNSUPPORTED;
    if (code == 0xd4) return BC_AUTHENTICATION_FAILED;
    if (code == 0xc0) return BC_BUSY;
    return BC_PROTOCOL_ERROR;
}
bc_status bc_ipmi_sensor_catalog_get(bc_ipmi_session *session, bc_ipmi_sensor_catalog *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->abi_version = BC_ABI_VERSION;
    uint8_t code = 0, response[300]; uint32_t n = 0;
    bc_status status = bc_ipmi_session_command(session, 0x0a, 0x20, (bc_bytes){NULL, 0}, &code, response, sizeof(response), &n);
    if (status != BC_OK) return status;
    if (code) return completion_status(code);
    if (n < 3) return BC_PROTOCOL_ERROR;
    out->record_count = (uint32_t)bc_wire_read_le(response + 1, 2);
    if (!out->record_count) return BC_OK;
    status = bc_ipmi_session_command(session, 0x0a, 0x22, (bc_bytes){NULL, 0}, &code, response, sizeof(response), &n);
    if (status != BC_OK) return status;
    if (code) return completion_status(code);
    if (n != 2) return BC_PROTOCOL_ERROR;
    uint16_t reservation = (uint16_t)bc_wire_read_le(response, 2), id = 0, visited[512];
    for (unsigned walked = 0; walked < 512; ++walked) {
        for (unsigned j = 0; j < walked; ++j) if (visited[j] == id) return BC_PROTOCOL_ERROR;
        visited[walked] = id;
        uint8_t request[6]; bc_wire_write_le(request, reservation, 2); bc_wire_write_le(request + 2, id, 2);
        request[4] = 0; request[5] = 255;
        status = bc_ipmi_session_command(session, 0x0a, 0x23, (bc_bytes){request, 6}, &code, response, sizeof(response), &n);
        if (status != BC_OK) return status;
        if (code) return completion_status(code);
        if (n < 7 || n != 7u + response[6]) return BC_PROTOCOL_ERROR;
        uint16_t next = (uint16_t)bc_wire_read_le(response, 2);
        bc_ipmi_sensor_descriptor parsed = {0}; parsed.struct_size = sizeof(parsed); parsed.abi_version = BC_ABI_VERSION;
        status = bc_ipmi_sdr_sensor_parse((bc_bytes){response + 2, n - 2}, 0, &parsed);
        if (status != BC_UNSUPPORTED && status != BC_OK) return status;
        if (status == BC_OK) for (uint32_t index = 0; index < parsed.share_count; ++index) {
            if (out->count == BC_IPMI_MAX_SENSORS) { out->flags |= BC_IPMI_SDR_TRUNCATED; return BC_LIMIT_EXCEEDED; }
            if (index) { status = bc_ipmi_sdr_sensor_parse((bc_bytes){response + 2, n - 2}, index, &parsed); if (status != BC_OK) return status; }
            out->sensors[out->count++] = parsed;
        }
        if (next == 0xffff) return BC_OK;
        id = next;
    }
    out->flags |= BC_IPMI_SDR_TRUNCATED; return BC_LIMIT_EXCEEDED;
}
static bc_status query(bc_ipmi_session *session, uint8_t cmd, uint8_t number, uint8_t *data, uint32_t *length) {
    uint8_t code = 0;
    bc_status status = bc_ipmi_session_command(session, 4, cmd, (bc_bytes){&number, 1}, &code, data, 8, length);
    return status == BC_OK ? completion_status(code) : status;
}
static void result_field(bc_sensor_details *out, unsigned field, bc_status status) {
    if (status == BC_UNSUPPORTED && out->fields[field].state == BC_SENSOR_FIELD_ERROR) return;
    bc_sensor_field_set(out, &out->fields[field], status == BC_OK ? BC_SENSOR_FIELD_READY : status == BC_UNSUPPORTED ? BC_SENSOR_FIELD_UNSUPPORTED : BC_SENSOR_FIELD_ERROR, status);
}
static bc_status convert(const bc_ipmi_sensor_record *sensor, uint8_t raw, double *value) {
    if (sensor->linearization > 0x0b) return BC_UNSUPPORTED;
    bc_status status = bc_ipmi_sensor_convert(sensor, raw, value);
    return status == BC_OK && !isfinite(*value) ? BC_PROTOCOL_ERROR : status;
}
bc_status bc_ipmi_sensor_details_get(bc_ipmi_session *session, const bc_ipmi_sensor_descriptor *record, bc_sensor_details *out) {
    if (!session || !record || record->struct_size != sizeof(*record) || record->abi_version != BC_ABI_VERSION || !bc_sensor_details_valid(out)) return BC_INVALID_ARGUMENT;
    bc_sensor_details_reset(out);
    result_field(out, BC_SENSOR_DETAIL_METADATA, record->name_status);
    const bc_ipmi_sensor_record *sensor = &record->sensor;
    const char *unit = NULL;
    if (!sensor->unit_rate && !sensor->unit_modifier) {
        if (sensor->unit_percentage && !sensor->unit_base) unit = "%";
        else if (!sensor->unit_percentage) switch (sensor->unit_base) {
        case 1: unit = "Cel"; break; case 2: unit = "[degF]"; break; case 3: unit = "K"; break;
        case 4: unit = "V"; break; case 5: unit = "A"; break; case 6: unit = "W"; break;
        case 7: unit = "J"; break; case 18: unit = "{rev}/min"; break; case 19: unit = "Hz"; break;
        }
    }
    if (unit) out->units = (bc_string){unit, strlen(unit)};
    for (unsigned i = 0; i < 4; ++i) result_field(out, i, BC_UNSUPPORTED);
    if (record->record_type == 3 || sensor->owner_id != BC_IPMI_ADDRESS_BMC || sensor->owner_lun || record->owner_channel) return out->status;
    int numeric = record->record_type == 1 && sensor->analog_format != 3;
    uint8_t data[8]; uint32_t n = 0;
    bc_status status = query(session, 0x2d, sensor->sensor_number, data, &n);
    if (status == BC_OK && n < 2) status = BC_PROTOCOL_ERROR;
    int discrete = sensor->event_type != 1;
    if (numeric) result_field(out, BC_SENSOR_DETAIL_READING, status);
    if (discrete) result_field(out, BC_SENSOR_DETAIL_STATES, status);
    if (status == BC_OK) {
        out->raw_status = data[1];
        if (!(data[1] & 0x40)) out->flags |= BC_SENSOR_DETAIL_SCANNING_DISABLED;
        if (!(data[1] & 0x80)) out->flags |= BC_SENSOR_DETAIL_EVENTS_DISABLED;
        if ((data[1] & 0x20) || !(data[1] & 0x40)) {
            if (numeric) out->fields[BC_SENSOR_DETAIL_READING].state = BC_SENSOR_FIELD_UNAVAILABLE;
            if (discrete) out->fields[BC_SENSOR_DETAIL_STATES].state = BC_SENSOR_FIELD_UNAVAILABLE;
        }
        else {
            if (numeric) {
                status = convert(sensor, data[0], &out->reading);
                result_field(out, BC_SENSOR_DETAIL_READING, status);
                if (status == BC_OK) out->flags |= BC_SENSOR_DETAIL_VALUE_PRESENT;
            }
            if (sensor->event_type == 1 && n >= 3 && record->comparison_mask) {
                out->active_threshold_valid_mask = record->comparison_mask;
                out->active_threshold_mask = data[2] & record->comparison_mask; out->flags |= BC_SENSOR_DETAIL_ALARMS_PRESENT;
                out->health = out->active_threshold_mask & 0x24 ? BC_SENSOR_HEALTH_FATAL : out->active_threshold_mask & 0x12 ? BC_SENSOR_HEALTH_CRITICAL : out->active_threshold_mask ? BC_SENSOR_HEALTH_WARNING : BC_SENSOR_HEALTH_OK;
                result_field(out, BC_SENSOR_DETAIL_HEALTH, BC_OK);
            } else if (discrete) {
                if (n < 3) result_field(out, BC_SENSOR_DETAIL_STATES, BC_PROTOCOL_ERROR);
                else {
                    out->discrete_valid_mask = record->readable_mask & (n >= 4 ? 0x7fff : 0xff);
                    out->discrete_states = (data[2] | (n >= 4 ? (uint32_t)(data[3] & 127) << 8 : 0)) & out->discrete_valid_mask;
                    if (!out->discrete_valid_mask) result_field(out, BC_SENSOR_DETAIL_STATES, BC_UNSUPPORTED);
                }
            }
        }
    }
    if (numeric && sensor->event_type == 1) {
        status = query(session, 0x27, sensor->sensor_number, data, &n);
        if (status == BC_OK && n != 7) status = BC_PROTOCOL_ERROR;
        result_field(out, BC_SENSOR_DETAIL_THRESHOLDS, status);
        if (status == BC_OK) for (unsigned i = 0; i < 6; ++i) {
            if (!(data[0] & (1u << i))) continue;
            status = convert(sensor, data[i + 1], &out->thresholds[i]);
            bc_sensor_field_set(out, &out->threshold_fields[i], status == BC_OK ? BC_SENSOR_FIELD_READY : status == BC_UNSUPPORTED ? BC_SENSOR_FIELD_UNSUPPORTED : BC_SENSOR_FIELD_ERROR, status);
            if (status == BC_OK) out->threshold_mask |= 1u << i;
            else result_field(out, BC_SENSOR_DETAIL_THRESHOLDS, status);
        }
    }
    return out->status;
}

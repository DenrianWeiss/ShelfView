#include "bcontrol/ipmi_sensor.h"
#include "bcontrol/wire.h"
#include "log_internal.h"
#include <math.h>
#include <string.h>

#define FULL_SENSOR_DATA_LENGTH 43u
#define SDR_SCAN_LIMIT 512u
#define SDR_GET_CHUNK 0xFFu

static int32_t sign_extend(uint32_t value, unsigned bits) {
    uint32_t sign = UINT32_C(1) << (bits - 1);
    return (int32_t)((value ^ sign) - sign);
}

static double linearize(double value, uint8_t linearization) {
    switch (linearization & 0x7f) {
    case 0x01: return log(value);
    case 0x02: return log10(value);
    case 0x03: return log(value) / log(2.0);
    case 0x04: return exp(value);
    case 0x05: return pow(10.0, value);
    case 0x06: return pow(2.0, value);
    case 0x07: return pow(value, -1.0);
    case 0x08: return pow(value, 2.0);
    case 0x09: return pow(value, 3.0);
    case 0x0a: return sqrt(value);
    case 0x0b: return cbrt(value);
    default: return value;
    }
}

bc_status bc_ipmi_sensor_convert(const bc_ipmi_sensor_record *record, uint8_t raw_reading, double *value) {
    if (!record || !value) return BC_INVALID_ARGUMENT;
    if (record->analog_format == 3 || (record->flags & BC_IPMI_SENSOR_NONLINEAR)) return BC_UNSUPPORTED;
    int32_t reading = raw_reading;
    if (record->analog_format == 2) reading = (int8_t)raw_reading;
    else if (record->analog_format == 1) {
        if (raw_reading & 0x80) ++reading;
        reading = (int8_t)reading;
    }
    double result = ((double)record->m * (double)reading + (double)record->b * pow(10.0, (double)record->k1)) *
        pow(10.0, (double)record->k2);
    *value = linearize(result, record->linearization);
    return BC_OK;
}

static void parse_thresholds(const uint8_t *data, bc_ipmi_sensor_record *out) {
    static const uint8_t order[BC_IPMI_THRESHOLD_COUNT] = {34, 35, 36, 33, 32, 31};
    for (unsigned i = 0; i < BC_IPMI_THRESHOLD_COUNT; ++i) {
        uint8_t raw = data[order[i]];
        out->raw_thresholds[i] = raw;
        if (raw == 0xFF) continue;
        double value = 0;
        if (bc_ipmi_sensor_convert(out, raw, &value) == BC_OK) {
            out->threshold_values[i] = value;
            out->threshold_mask |= UINT32_C(1) << i;
        }
    }
}

bc_status bc_ipmi_sdr_parse_record(const uint8_t *record, uint64_t length, bc_ipmi_sensor_record *out) {
    if (!record || !out || length < 5) return BC_INVALID_ARGUMENT;
    if (record[3] != BC_IPMI_SDR_RECORD_FULL_SENSOR) return BC_UNSUPPORTED;
    uint64_t data_length = record[4];
    if (data_length < FULL_SENSOR_DATA_LENGTH || 5 + data_length > length) return BC_PROTOCOL_ERROR;
    const uint8_t *data = record + 5;
    memset(out, 0, sizeof(*out));
    out->owner_id = data[0];
    out->owner_lun = (uint8_t)(data[1] & 3);
    out->sensor_number = data[2];
    out->entity_id = data[3];
    out->entity_instance = data[4];
    out->sensor_type = data[7];
    out->event_type = data[8];
    memcpy(out->units, data + 15, 3);
    out->analog_format = (uint8_t)(data[15] >> 6);
    out->unit_rate = (uint8_t)((data[15] >> 3) & 7);
    out->unit_modifier = (uint8_t)((data[15] >> 1) & 3);
    out->unit_percentage = (uint8_t)(data[15] & 1);
    out->unit_base = data[16];
    out->unit_modifier_type = data[17];
    out->linearization = data[18];
    out->m = sign_extend((uint32_t)data[19] | (uint32_t)(data[20] & 0xc0u) << 2, 10);
    out->b = sign_extend((uint32_t)data[21] | (uint32_t)(data[22] & 0xc0u) << 2, 10);
    out->accuracy = (data[22] & 0x3fu) | (uint32_t)(data[23] & 0xf0u) << 2;
    out->k1 = sign_extend(data[24] & 0x0fu, 4);
    out->k2 = sign_extend(data[24] >> 4, 4);
    out->nominal_read = data[26];
    out->normal_max = data[27];
    out->normal_min = data[28];
    out->sensor_max = data[29];
    out->sensor_min = data[30];
    if (out->linearization >= 0x70) out->flags |= BC_IPMI_SENSOR_NONLINEAR;
    parse_thresholds(data, out);
    uint8_t code = data[42];
    unsigned id_length = code & 0x3fu;
    if ((code >> 6) == 3 && id_length <= 16 && id_length <= data_length - 43) {
        memcpy(out->id, data + 43, id_length);
        out->id[id_length] = 0;
        out->id_length = (uint8_t)id_length;
    }
    return BC_OK;
}

bc_status bc_ipmi_sdr_scan(bc_ipmi_session *session, bc_ipmi_sensor_list *out) {
    if (!session || !out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    uint8_t completion_code = 0, data[64];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_SDR_REPOSITORY_INFO,
        (bc_bytes){NULL, 0}, &completion_code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (completion_code != BC_IPMI_COMPLETION_OK || length < 6) return BC_PROTOCOL_ERROR;
    out->version = data[0];
    out->record_count = (uint32_t)bc_wire_read_le(data + 1, 2);
    status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_RESERVE_SDR_REPOSITORY,
        (bc_bytes){NULL, 0}, &completion_code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (completion_code != BC_IPMI_COMPLETION_OK || length < 2) return BC_PROTOCOL_ERROR;
    uint16_t reservation = (uint16_t)bc_wire_read_le(data, 2);
    uint16_t record_id = 0;
    for (uint32_t walked = 0; walked < SDR_SCAN_LIMIT; ++walked) {
        uint8_t request[6];
        bc_wire_write_le(request, reservation, 2);
        bc_wire_write_le(request + 2, record_id, 2);
        request[4] = 0;
        request[5] = SDR_GET_CHUNK;
        uint8_t response[300];
        uint32_t response_length = 0;
        status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_SDR,
            (bc_bytes){request, sizeof(request)}, &completion_code, response, sizeof(response), &response_length);
        if (status != BC_OK) return status;
        if (completion_code != BC_IPMI_COMPLETION_OK || response_length < 2) return BC_PROTOCOL_ERROR;
        uint16_t next = (uint16_t)bc_wire_read_le(response, 2);
        if (response_length > 2 && out->count < BC_IPMI_MAX_SENSORS) {
            bc_ipmi_sensor_record parsed;
            if (bc_ipmi_sdr_parse_record(response + 2, response_length - 2, &parsed) == BC_OK) out->sensors[out->count++] = parsed;
        }
        if (next == 0xffff || next == record_id) break;
        if (out->count >= BC_IPMI_MAX_SENSORS) { out->flags |= BC_IPMI_SDR_TRUNCATED; break; }
        record_id = next;
    }
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.sdr", "version=%u records=%u parsed=%u flags=%u",
        out->version, out->record_count, out->count, out->flags);
    return BC_OK;
}

bc_status bc_ipmi_sensor_read(bc_ipmi_session *session, const bc_ipmi_sensor_record *record, bc_ipmi_sensor_reading *out) {
    if (!session || !record || !out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    uint8_t number = record->sensor_number, completion_code = 0, data[8];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_SENSOR, BC_IPMI_CMD_GET_SENSOR_READING,
        (bc_bytes){&number, 1}, &completion_code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (completion_code != BC_IPMI_COMPLETION_OK || length < 1) return BC_PROTOCOL_ERROR;
    out->raw_reading = data[0];
    if (length >= 2) out->status = data[1];
    if (out->status & 0x20u) {
        out->flags |= BC_IPMI_SENSOR_READING_UNAVAILABLE;
        return BC_OK;
    }
    if (!(out->status & 0x40u)) out->flags |= BC_IPMI_SENSOR_SCANNING_DISABLED;
    if (!(out->status & 0x80u)) out->flags |= BC_IPMI_SENSOR_EVENTS_DISABLED;
    if (record->analog_format == 3 || (record->flags & BC_IPMI_SENSOR_NONLINEAR)) {
        out->flags |= BC_IPMI_SENSOR_DISCRETE;
        return BC_OK;
    }
    double value = 0;
    status = bc_ipmi_sensor_convert(record, data[0], &value);
    if (status == BC_UNSUPPORTED) out->flags |= BC_IPMI_SENSOR_DISCRETE;
    else if (status != BC_OK) return status;
    else {
        out->reading = value;
        out->flags |= BC_IPMI_SENSOR_READING_PRESENT;
    }
    return BC_OK;
}

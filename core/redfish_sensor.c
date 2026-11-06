#include "redfish_internal.h"
#include "sensor_internal.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

static bc_status text(yyjson_val *root, const char *key, bc_string *out) {
    yyjson_val *value = yyjson_obj_get(root, key);
    if (!value || yyjson_is_null(value)) return BC_OK;
    const char *data = yyjson_get_str(value); size_t n = yyjson_get_len(value);
    if (!data || n > 1024 || strlen(data) != n) return BC_PROTOCOL_ERROR;
    char *owned = malloc(n + 1);
    if (!owned) return BC_NO_MEMORY;
    memcpy(owned, data, n + 1); *out = (bc_string){owned, n}; return BC_OK;
}
static bc_status number(yyjson_val *root, const char *key, double *out, uint32_t bit, uint32_t *flags) {
    yyjson_val *value = yyjson_obj_get(root, key);
    if (!value || yyjson_is_null(value)) return BC_OK;
    if (!yyjson_is_num(value)) return BC_PROTOCOL_ERROR;
    double n = yyjson_get_num(value);
    if (!isfinite(n)) return BC_PROTOCOL_ERROR;
    *out = n; *flags |= bit; return BC_OK;
}
void bc_redfish_clear_sensor(bc_redfish_sensor_info *info) {
    free((void *)info->reading_type.data); free((void *)info->units.data);
    free((void *)info->health.data); free((void *)info->state.data); free((void *)info->reading_time.data);
    free((void *)info->thresholds_json.data);
}
bc_status bc_redfish_parse_sensor(yyjson_val *root, bc_redfish_sensor_info *info) {
    bc_status status = number(root, "Reading", &info->reading, BC_SENSOR_READING_PRESENT, &info->flags);
    if (status == BC_OK) status = number(root, "ReadingRangeMin", &info->range_min, BC_SENSOR_RANGE_MIN_PRESENT, &info->flags);
    if (status == BC_OK) status = number(root, "ReadingRangeMax", &info->range_max, BC_SENSOR_RANGE_MAX_PRESENT, &info->flags);
    if (status == BC_OK) status = text(root, "ReadingType", &info->reading_type);
    if (status == BC_OK) status = text(root, "ReadingUnits", &info->units);
    if (status == BC_OK) status = text(root, "ReadingTime", &info->reading_time);
    yyjson_val *health = yyjson_obj_get(root, "Status");
    if (status == BC_OK && health) {
        if (!yyjson_is_obj(health)) status = BC_PROTOCOL_ERROR;
        else {
            status = text(health, "Health", &info->health);
            if (status == BC_OK) status = text(health, "State", &info->state);
        }
    }
    yyjson_val *thresholds = yyjson_obj_get(root, "Thresholds");
    if (status != BC_OK || !thresholds) return status;
    if (!yyjson_is_obj(thresholds)) return BC_PROTOCOL_ERROR;
    const char *names[] = {"LowerCaution", "LowerCritical", "LowerFatal", "UpperCaution", "UpperCritical", "UpperFatal"};
    for (uint32_t i = 0; i < BC_SENSOR_THRESHOLD_COUNT; ++i) {
        yyjson_val *threshold = yyjson_obj_get(thresholds, names[i]);
        if (!threshold) continue;
        if (!yyjson_is_obj(threshold)) return BC_PROTOCOL_ERROR;
        status = number(threshold, "Reading", &info->thresholds[i], UINT32_C(1) << i, &info->threshold_mask);
        if (status != BC_OK) return status;
    }
    size_t length = 0; char *json = yyjson_val_write(thresholds, 0, &length);
    if (!json) return BC_NO_MEMORY;
    info->thresholds_json = (bc_bytes){(const unsigned char *)json, length}; return BC_OK;
}

static int equals(bc_string value, const char *text) {
    return value.data && value.length == strlen(text) && !memcmp(value.data, text, (size_t)value.length);
}
static void field_number(yyjson_val *root, const char *key, bc_sensor_details *out, bc_sensor_field *field, double *value) {
    yyjson_val *v = yyjson_obj_get(root, key);
    if (!v) return;
    if (yyjson_is_null(v)) { field->state = BC_SENSOR_FIELD_UNAVAILABLE; return; }
    if (!yyjson_is_num(v) || !isfinite(yyjson_get_num(v))) {
        bc_sensor_field_set(out, field, BC_SENSOR_FIELD_ERROR, BC_PROTOCOL_ERROR); return;
    }
    *value = yyjson_get_num(v); field->state = BC_SENSOR_FIELD_READY;
}
bc_status bc_redfish_parse_sensor_details(yyjson_val *root, bc_redfish_sensor_info *owned, bc_sensor_details *out) {
    bc_sensor_details_reset(out);
    out->fields[BC_SENSOR_DETAIL_STATES] = (bc_sensor_field){BC_SENSOR_FIELD_UNSUPPORTED, BC_UNSUPPORTED};
    field_number(root, "Reading", out, &out->fields[BC_SENSOR_DETAIL_READING], &out->reading);
    if (out->fields[BC_SENSOR_DETAIL_READING].state == BC_SENSOR_FIELD_READY) out->flags |= BC_SENSOR_DETAIL_VALUE_PRESENT;
    const char *keys[] = {"ReadingUnits", "ReadingTime"};
    bc_string *strings[] = {&owned->units, &owned->reading_time};
    for (unsigned i = 0; i < 2; ++i) {
        bc_status status = text(root, keys[i], strings[i]);
        if (status == BC_NO_MEMORY) return status;
        if (status != BC_OK) bc_sensor_field_set(out, &out->fields[BC_SENSOR_DETAIL_METADATA], BC_SENSOR_FIELD_ERROR, status);
        else if (yyjson_obj_get(root, keys[i]) && out->fields[BC_SENSOR_DETAIL_METADATA].state != BC_SENSOR_FIELD_ERROR) out->fields[BC_SENSOR_DETAIL_METADATA].state = BC_SENSOR_FIELD_READY;
    }
    out->units = owned->units; out->reading_time = owned->reading_time;
    yyjson_val *status_obj = yyjson_obj_get(root, "Status");
    if (status_obj && !yyjson_is_obj(status_obj)) bc_sensor_field_set(out, &out->fields[BC_SENSOR_DETAIL_HEALTH], BC_SENSOR_FIELD_ERROR, BC_PROTOCOL_ERROR);
    else if (status_obj) {
        bc_status status = text(status_obj, "Health", &owned->health);
        if (status == BC_NO_MEMORY) return status;
        if (status != BC_OK) bc_sensor_field_set(out, &out->fields[BC_SENSOR_DETAIL_HEALTH], BC_SENSOR_FIELD_ERROR, status);
        else {
            yyjson_val *value = yyjson_obj_get(status_obj, "Health");
            out->fields[BC_SENSOR_DETAIL_HEALTH].state = !value ? BC_SENSOR_FIELD_NOT_REPORTED : yyjson_is_null(value) ? BC_SENSOR_FIELD_UNAVAILABLE : BC_SENSOR_FIELD_READY;
            out->health_text = owned->health;
            out->health = equals(owned->health, "OK") ? BC_SENSOR_HEALTH_OK : equals(owned->health, "Warning") ? BC_SENSOR_HEALTH_WARNING : equals(owned->health, "Critical") ? BC_SENSOR_HEALTH_CRITICAL : BC_SENSOR_HEALTH_UNKNOWN;
        }
        status = text(status_obj, "State", &owned->state);
        if (status == BC_NO_MEMORY) return status;
        if (status != BC_OK) bc_sensor_field_set(out, &out->fields[BC_SENSOR_DETAIL_METADATA], BC_SENSOR_FIELD_ERROR, status);
        out->state_text = owned->state;
    }
    yyjson_val *enabled = yyjson_obj_get(root, "Enabled");
    if (enabled && !yyjson_is_null(enabled) && !yyjson_is_bool(enabled)) bc_sensor_field_set(out, &out->fields[BC_SENSOR_DETAIL_METADATA], BC_SENSOR_FIELD_ERROR, BC_PROTOCOL_ERROR);
    if ((enabled && yyjson_is_false(enabled)) || equals(owned->state, "Disabled") || equals(owned->state, "Absent") || equals(owned->state, "UnavailableOffline")) {
        if (out->fields[BC_SENSOR_DETAIL_READING].state != BC_SENSOR_FIELD_ERROR) out->fields[BC_SENSOR_DETAIL_READING].state = BC_SENSOR_FIELD_UNAVAILABLE;
        out->flags &= ~BC_SENSOR_DETAIL_VALUE_PRESENT;
    }
    yyjson_val *thresholds = yyjson_obj_get(root, "Thresholds");
    if (!thresholds) return BC_OK;
    if (!yyjson_is_obj(thresholds)) {
        bc_sensor_field_set(out, &out->fields[BC_SENSOR_DETAIL_THRESHOLDS], BC_SENSOR_FIELD_ERROR, BC_PROTOCOL_ERROR); return BC_OK;
    }
    size_t length = 0; char *json = yyjson_val_write(thresholds, 0, &length);
    if (!json) return BC_NO_MEMORY;
    owned->thresholds_json = out->thresholds_json = (bc_bytes){(const uint8_t *)json, length};
    out->fields[BC_SENSOR_DETAIL_THRESHOLDS].state = BC_SENSOR_FIELD_READY;
    const char *names[] = {"LowerCaution", "LowerCritical", "LowerFatal", "UpperCaution", "UpperCritical", "UpperFatal"};
    for (unsigned i = 0; i < 6; ++i) {
        yyjson_val *value = yyjson_obj_get(thresholds, names[i]);
        if (!value) continue;
        if (!yyjson_is_obj(value)) bc_sensor_field_set(out, &out->threshold_fields[i], BC_SENSOR_FIELD_ERROR, BC_PROTOCOL_ERROR);
        else field_number(value, "Reading", out, &out->threshold_fields[i], &out->thresholds[i]);
        if (out->threshold_fields[i].state == BC_SENSOR_FIELD_READY) out->threshold_mask |= 1u << i;
        if (out->threshold_fields[i].state == BC_SENSOR_FIELD_ERROR) out->fields[BC_SENSOR_DETAIL_THRESHOLDS] = out->threshold_fields[i];
    }
    return BC_OK;
}
bc_status bc_redfish_temperature(const bc_redfish_sensor_info *sensor, const bc_redfish_context_info *context, uint32_t allow_cpu, bc_temperature_reading *out) {
    if ((context->flags & BC_REDFISH_CONTEXT_BASIS_PRESENT) && !equals(context->reading_basis, "Zero")) return BC_UNSUPPORTED;
    if ((context->flags & BC_REDFISH_CONTEXT_ENABLED_PRESENT) && !context->enabled) return BC_UNSUPPORTED;
    if (!equals(sensor->state, "Enabled") && !(sensor->state.length == 0 && (context->flags & BC_REDFISH_CONTEXT_ENABLED_PRESENT) && context->enabled)) return BC_UNSUPPORTED;
    if (!(sensor->flags & BC_SENSOR_READING_PRESENT) || (sensor->reading_type.length && !equals(sensor->reading_type, "Temperature"))) return BC_UNSUPPORTED;
    uint32_t unit = equals(sensor->units, "Cel") ? BC_TEMPERATURE_CELSIUS : equals(sensor->units, "[degF]") ? BC_TEMPERATURE_FAHRENHEIT : equals(sensor->units, "K") ? BC_TEMPERATURE_KELVIN : 0;
    if (!unit || ((sensor->flags & BC_SENSOR_RANGE_MIN_PRESENT) && sensor->reading < sensor->range_min) ||
        ((sensor->flags & BC_SENSOR_RANGE_MAX_PRESENT) && sensor->reading > sensor->range_max)) return BC_UNSUPPORTED;
    uint32_t flags = BC_TEMPERATURE_VALUE_PRESENT | BC_TEMPERATURE_ENABLED;
    if (equals(sensor->health, "OK")) flags |= BC_TEMPERATURE_HEALTH_OK;
    if (equals(sensor->health, "Warning") || equals(sensor->health, "Critical")) flags |= BC_TEMPERATURE_HEALTH_ABNORMAL;
    uint32_t role = bc_temperature_redfish_role(context->physical_context);
    flags |= allow_cpu ? role : role & ~BC_TEMPERATURE_CPU;
    *out = (bc_temperature_reading){sensor->reading, unit, flags}; return BC_OK;
}

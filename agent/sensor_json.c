#include "sensor_json.h"
static void string(yyjson_mut_doc *doc, yyjson_mut_val *out, const char *key, bc_string value) {
    if (value.data) yyjson_mut_obj_add_strncpy(doc, out, key, value.data, (size_t)value.length);
    else yyjson_mut_obj_add_null(doc, out, key);
}
void bc_agent_sensor_details_json(yyjson_mut_doc *doc, yyjson_mut_val *out, const bc_sensor_details *details) {
    static const char *names[] = {"reading", "states", "thresholds", "health", "metadata"};
    static const char *states[] = {"not_reported", "ready", "unavailable", "unsupported", "error"};
    yyjson_mut_obj_add_str(doc, out, "status", bc_status_string(details->status));
    yyjson_mut_val *fields = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, out, "fields", fields);
    for (unsigned i = 0; i < BC_SENSOR_DETAIL_FIELD_COUNT; ++i) {
        yyjson_mut_val *field = yyjson_mut_obj(doc); yyjson_mut_obj_add_val(doc, fields, names[i], field);
        uint32_t state = details->fields[i].state;
        yyjson_mut_obj_add_str(doc, field, "state", state < 5 ? states[state] : "unknown");
        yyjson_mut_obj_add_str(doc, field, "status", bc_status_string(details->fields[i].status));
    }
    yyjson_mut_obj_add_uint(doc, out, "flags", details->flags);
    if (details->flags & BC_SENSOR_DETAIL_VALUE_PRESENT) yyjson_mut_obj_add_real(doc, out, "reading", details->reading);
    else yyjson_mut_obj_add_null(doc, out, "reading");
    yyjson_mut_obj_add_uint(doc, out, "health", details->health);
    yyjson_mut_obj_add_uint(doc, out, "raw_status", details->raw_status);
    yyjson_mut_obj_add_uint(doc, out, "discrete_states", details->discrete_states);
    yyjson_mut_obj_add_uint(doc, out, "discrete_valid_mask", details->discrete_valid_mask);
    yyjson_mut_obj_add_uint(doc, out, "active_threshold_mask", details->active_threshold_mask);
    yyjson_mut_obj_add_uint(doc, out, "active_threshold_valid_mask", details->active_threshold_valid_mask);
    yyjson_mut_obj_add_uint(doc, out, "threshold_mask", details->threshold_mask);
    string(doc, out, "units", details->units); string(doc, out, "health_text", details->health_text);
    string(doc, out, "state_text", details->state_text); string(doc, out, "reading_time", details->reading_time);
    yyjson_mut_val *thresholds = yyjson_mut_arr(doc); yyjson_mut_obj_add_val(doc, out, "thresholds", thresholds);
    for (unsigned i = 0; i < 6; ++i) {
        yyjson_mut_val *field = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(thresholds, field);
        uint32_t state = details->threshold_fields[i].state;
        yyjson_mut_obj_add_str(doc, field, "state", state < 5 ? states[state] : "unknown");
        yyjson_mut_obj_add_str(doc, field, "status", bc_status_string(details->threshold_fields[i].status));
        if (details->threshold_mask & (1u << i)) yyjson_mut_obj_add_real(doc, field, "reading", details->thresholds[i]);
        else yyjson_mut_obj_add_null(doc, field, "reading");
    }
}

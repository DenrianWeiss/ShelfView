#include "bcontrol/temperature.h"
#include <math.h>
#include <string.h>

bc_status bc_temperature_summarize(const bc_temperature_reading *readings, uint32_t count, bc_temperature_summary *out) {
    if (!out || (count && !readings) || out->struct_size != sizeof(*out)) return BC_INVALID_ARGUMENT;
    bc_temperature_summary result;
    memset(&result, 0, sizeof(result)); result.struct_size = sizeof(result);
    result.cpu_index = result.normal_index = result.alert_index = BC_TEMPERATURE_NO_INDEX;
    for (uint32_t i = 0; i < count; ++i) {
        const bc_temperature_reading *reading = &readings[i];
        if ((reading->flags & ~63u) || ((reading->flags & BC_TEMPERATURE_HEALTH_OK) &&
            (reading->flags & BC_TEMPERATURE_HEALTH_ABNORMAL))) return BC_INVALID_ARGUMENT;
        if ((reading->flags & (BC_TEMPERATURE_VALUE_PRESENT | BC_TEMPERATURE_ENABLED)) !=
            (BC_TEMPERATURE_VALUE_PRESENT | BC_TEMPERATURE_ENABLED) || !isfinite(reading->value)) continue;
        double value = reading->value;
        switch (reading->unit) {
        case BC_TEMPERATURE_CELSIUS: break;
        case BC_TEMPERATURE_FAHRENHEIT: value = (value - 32.0) * (5.0 / 9.0); break;
        case BC_TEMPERATURE_KELVIN: value -= 273.15; break;
        default: continue;
        }
        if (!isfinite(value) || value < -273.15) continue;
        if ((reading->flags & BC_TEMPERATURE_CPU) &&
            (!(result.flags & BC_TEMPERATURE_CPU_PRESENT) || value > result.cpu_celsius)) {
            result.flags |= BC_TEMPERATURE_CPU_PRESENT; result.cpu_index = i; result.cpu_celsius = value;
        }
        if ((reading->flags & BC_TEMPERATURE_HEALTH_OK) &&
            (!(result.flags & BC_TEMPERATURE_NORMAL_PRESENT) || value > result.normal_celsius)) {
            result.flags |= BC_TEMPERATURE_NORMAL_PRESENT; result.normal_index = i; result.normal_celsius = value;
        }
        if ((reading->flags & BC_TEMPERATURE_HEALTH_ABNORMAL) &&
            (!(result.flags & BC_TEMPERATURE_ALERT_PRESENT) || value > result.alert_celsius)) {
            result.flags |= BC_TEMPERATURE_ALERT_PRESENT; result.alert_index = i; result.alert_celsius = value;
        }
    }
    *out = result;
    return BC_OK;
}

bc_status bc_temperature_select(const bc_temperature_reading *readings, uint32_t count, bc_temperature_selection *out) {
    if (!out || out->struct_size != sizeof(*out) || (count && !readings)) return BC_INVALID_ARGUMENT;
    bc_temperature_selection result = {sizeof(result), BC_TEMPERATURE_SOURCE_UNKNOWN, 0, BC_TEMPERATURE_NO_INDEX, 0};
    for (uint32_t i = 0; i < count; ++i) {
        bc_temperature_reading reading = readings[i];
        uint32_t source = reading.flags & BC_TEMPERATURE_CPU ? BC_TEMPERATURE_SOURCE_CPU :
            reading.flags & BC_TEMPERATURE_CHASSIS ? BC_TEMPERATURE_SOURCE_CHASSIS : BC_TEMPERATURE_SOURCE_UNKNOWN;
        /* Reuse the validity and unit conversion rules, independent of health. */
        bc_temperature_summary converted = {0};
        converted.struct_size = sizeof(converted);
        reading.flags |= BC_TEMPERATURE_CPU;
        bc_status status = bc_temperature_summarize(&reading, 1, &converted);
        if (status != BC_OK) return status;
        if (!source || !(converted.flags & BC_TEMPERATURE_CPU_PRESENT)) continue;
        if (!result.source || source < result.source ||
            (source == result.source && converted.cpu_celsius > result.celsius)) {
            result.source = source; result.index = i; result.celsius = converted.cpu_celsius;
            result.flags = source == BC_TEMPERATURE_SOURCE_CHASSIS ? BC_TEMPERATURE_FALLBACK : 0;
        }
    }
    *out = result;
    return BC_OK;
}

static int context_is(bc_string value, const char *text) {
    size_t length = strlen(text);
    return value.data && value.length == length && memcmp(value.data, text, length) == 0;
}
uint32_t bc_temperature_redfish_role(bc_string context) {
    if (context_is(context, "CPU") || context_is(context, "CPUSubsystem")) return BC_TEMPERATURE_CPU;
    if (context_is(context, "Chassis") || context_is(context, "Intake") || context_is(context, "Exhaust"))
        return BC_TEMPERATURE_CHASSIS;
    return 0;
}
uint32_t bc_temperature_ipmi_role(uint32_t entity) {
    if (entity == 3) return BC_TEMPERATURE_CPU;
    if (entity == 23) return BC_TEMPERATURE_CHASSIS;
    return 0;
}

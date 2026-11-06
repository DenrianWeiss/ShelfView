#ifndef BCONTROL_SENSOR_H
#define BCONTROL_SENSOR_H
#include "bcontrol.h"
#define BC_SENSOR_FIELD_NOT_REPORTED 0u
#define BC_SENSOR_FIELD_READY 1u
#define BC_SENSOR_FIELD_UNAVAILABLE 2u
#define BC_SENSOR_FIELD_UNSUPPORTED 3u
#define BC_SENSOR_FIELD_ERROR 4u
#define BC_SENSOR_DETAIL_READING 0u
#define BC_SENSOR_DETAIL_STATES 1u
#define BC_SENSOR_DETAIL_THRESHOLDS 2u
#define BC_SENSOR_DETAIL_HEALTH 3u
#define BC_SENSOR_DETAIL_METADATA 4u
#define BC_SENSOR_DETAIL_FIELD_COUNT 5u
#define BC_SENSOR_DETAIL_VALUE_PRESENT 1u
#define BC_SENSOR_DETAIL_ALARMS_PRESENT 2u
#define BC_SENSOR_DETAIL_SCANNING_DISABLED 4u
#define BC_SENSOR_DETAIL_EVENTS_DISABLED 8u
#define BC_SENSOR_HEALTH_UNKNOWN 0u
#define BC_SENSOR_HEALTH_OK 1u
#define BC_SENSOR_HEALTH_WARNING 2u
#define BC_SENSOR_HEALTH_CRITICAL 3u
#define BC_SENSOR_HEALTH_FATAL 4u
/* Threshold order: lower caution/critical/fatal, upper caution/critical/fatal. */
#define BC_SENSOR_DETAIL_THRESHOLD_COUNT 6u
typedef struct { uint32_t state; bc_status status; } bc_sensor_field;
typedef struct {
    uint32_t struct_size, abi_version;
    bc_status status;
    uint32_t flags;
    bc_sensor_field fields[BC_SENSOR_DETAIL_FIELD_COUNT];
    bc_sensor_field threshold_fields[BC_SENSOR_DETAIL_THRESHOLD_COUNT];
    double reading, thresholds[BC_SENSOR_DETAIL_THRESHOLD_COUNT];
    uint32_t threshold_mask, active_threshold_mask, active_threshold_valid_mask;
    uint32_t discrete_states, discrete_valid_mask, health;
    uint32_t raw_status;
    bc_string units, health_text, state_text, reading_time;
    bc_bytes thresholds_json;
} bc_sensor_details;
#endif

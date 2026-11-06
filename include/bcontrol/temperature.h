#ifndef BCONTROL_TEMPERATURE_H
#define BCONTROL_TEMPERATURE_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_TEMPERATURE_CELSIUS 1u
#define BC_TEMPERATURE_FAHRENHEIT 2u
#define BC_TEMPERATURE_KELVIN 3u
#define BC_TEMPERATURE_VALUE_PRESENT 1u
#define BC_TEMPERATURE_ENABLED 2u
#define BC_TEMPERATURE_HEALTH_OK 4u
#define BC_TEMPERATURE_HEALTH_ABNORMAL 8u
#define BC_TEMPERATURE_CPU 16u
#define BC_TEMPERATURE_CHASSIS 32u
#define BC_TEMPERATURE_SOURCE_UNKNOWN 0u
#define BC_TEMPERATURE_SOURCE_CPU 1u
#define BC_TEMPERATURE_SOURCE_CHASSIS 2u
#define BC_TEMPERATURE_FALLBACK 1u
#define BC_TEMPERATURE_CPU_PRESENT 1u
#define BC_TEMPERATURE_NORMAL_PRESENT 2u
#define BC_TEMPERATURE_ALERT_PRESENT 4u
#define BC_TEMPERATURE_NO_INDEX UINT32_MAX

typedef struct {
    double value;
    uint32_t unit;
    uint32_t flags;
} bc_temperature_reading;
typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    uint32_t cpu_index;
    uint32_t normal_index;
    uint32_t alert_index;
    uint32_t reserved;
    double cpu_celsius;
    double normal_celsius;
    double alert_celsius;
} bc_temperature_summary;
/* Indices refer to the caller's readings; absent values keep NO_INDEX.
 * CPU role and device health come from discovery, not name guessing. */
BC_API bc_status bc_temperature_summarize(const bc_temperature_reading *, uint32_t count, bc_temperature_summary *);
typedef struct {
    uint32_t struct_size, source, flags, index;
    double celsius;
} bc_temperature_selection;
/* Select the hottest valid CPU, otherwise the hottest identified chassis sensor.
 * Unclassified component temperatures are never presented as chassis readings. */
BC_API bc_status bc_temperature_select(const bc_temperature_reading *, uint32_t count, bc_temperature_selection *);
BC_API uint32_t bc_temperature_redfish_role(bc_string physical_context);
BC_API uint32_t bc_temperature_ipmi_role(uint32_t entity_id);
#ifdef __cplusplus
}
#endif
#endif

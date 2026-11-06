#ifndef BCONTROL_IPMI_SENSOR_H
#define BCONTROL_IPMI_SENSOR_H
#include "ipmi_session.h"
#include "sensor.h"
#ifdef __cplusplus
extern "C" {
#endif

#define BC_IPMI_MAX_SENSORS 256u
#define BC_IPMI_SENSOR_READING_PRESENT 1u
#define BC_IPMI_SENSOR_READING_UNAVAILABLE 2u
#define BC_IPMI_SENSOR_SCANNING_DISABLED 4u
#define BC_IPMI_SENSOR_EVENTS_DISABLED 8u
#define BC_IPMI_SENSOR_DISCRETE 16u
#define BC_IPMI_SENSOR_NONLINEAR 32u

#define BC_IPMI_SENSOR_TYPE_TEMPERATURE 0x01u
#define BC_IPMI_SENSOR_TYPE_VOLTAGE 0x02u
#define BC_IPMI_SENSOR_TYPE_CURRENT 0x03u
#define BC_IPMI_SENSOR_TYPE_FAN 0x04u
#define BC_IPMI_SENSOR_TYPE_POWER_SUPPLY 0x08u
#define BC_IPMI_SENSOR_TYPE_POWER_UNIT 0x09u
#define BC_IPMI_SENSOR_TYPE_OTHER 0xC0u

#define BC_IPMI_THRESHOLD_LOWER_NON_RECOVERABLE 0u
#define BC_IPMI_THRESHOLD_LOWER_CRITICAL 1u
#define BC_IPMI_THRESHOLD_LOWER_NON_CRITICAL 2u
#define BC_IPMI_THRESHOLD_UPPER_NON_CRITICAL 3u
#define BC_IPMI_THRESHOLD_UPPER_CRITICAL 4u
#define BC_IPMI_THRESHOLD_UPPER_NON_RECOVERABLE 5u
#define BC_IPMI_THRESHOLD_COUNT 6u

#define BC_IPMI_SDR_RECORD_FULL_SENSOR 0x01u
#define BC_IPMI_SDR_RECORD_COMPACT_SENSOR 0x02u
#define BC_IPMI_SDR_RECORD_EVENT_ONLY 0x03u
#define BC_IPMI_SDR_TRUNCATED 1u

typedef struct {
    uint32_t flags;
    uint8_t sensor_number;
    uint8_t sensor_type;
    uint8_t event_type;
    uint8_t entity_id;
    uint8_t entity_instance;
    uint8_t owner_id;
    uint8_t owner_lun;
    uint8_t linearization;
    uint8_t analog_format;
    uint8_t unit_base;
    uint8_t unit_modifier_type;
    uint8_t unit_rate;
    uint8_t unit_modifier;
    uint8_t unit_percentage;
    uint8_t units[3];
    int32_t m;
    int32_t b;
    int32_t k1;
    int32_t k2;
    uint32_t accuracy;
    uint8_t nominal_read;
    uint8_t normal_max;
    uint8_t normal_min;
    uint8_t sensor_max;
    uint8_t sensor_min;
    uint8_t raw_thresholds[BC_IPMI_THRESHOLD_COUNT];
    double threshold_values[BC_IPMI_THRESHOLD_COUNT];
    uint32_t threshold_mask;
    char id[17];
    uint8_t id_length;
    uint8_t reserved[2];
} bc_ipmi_sensor_record;

typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    uint8_t version;
    uint32_t record_count;
    uint32_t count;
    bc_ipmi_sensor_record sensors[BC_IPMI_MAX_SENSORS];
} bc_ipmi_sensor_list;

typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    uint8_t raw_reading;
    uint8_t status;
    uint8_t reserved[2];
    double reading;
} bc_ipmi_sensor_reading;

/* Parse one full SDR record (record header + body). */
BC_IPMI_API bc_status bc_ipmi_sdr_parse_record(const uint8_t *record, uint64_t length, bc_ipmi_sensor_record *);
BC_IPMI_API bc_status bc_ipmi_sdr_scan(bc_ipmi_session *, bc_ipmi_sensor_list *);
BC_IPMI_API bc_status bc_ipmi_sensor_convert(const bc_ipmi_sensor_record *, uint8_t raw_reading, double *value);
BC_IPMI_API bc_status bc_ipmi_sensor_read(bc_ipmi_session *, const bc_ipmi_sensor_record *, bc_ipmi_sensor_reading *);
typedef struct {
    uint32_t struct_size, abi_version;
    bc_ipmi_sensor_record sensor;
    uint16_t record_id, readable_mask;
    uint8_t record_type, owner_channel, share_index, share_count;
    uint8_t capabilities, id_encoding, raw_id_length, comparison_mask;
    uint8_t raw_id[16];
    bc_status name_status;
    char name[64];
} bc_ipmi_sensor_descriptor;
typedef struct {
    uint32_t struct_size, abi_version, flags, record_count, count;
    bc_ipmi_sensor_descriptor sensors[BC_IPMI_MAX_SENSORS];
} bc_ipmi_sensor_catalog;
/* index selects a member of a shared record; index zero exposes share_count. */
BC_IPMI_API bc_status bc_ipmi_sdr_sensor_parse(bc_bytes record, uint32_t index, bc_ipmi_sensor_descriptor *);
/* Whole-record traversal only; no cache or reservation-recovery policy. */
BC_IPMI_API bc_status bc_ipmi_sensor_catalog_get(bc_ipmi_session *, bc_ipmi_sensor_catalog *);
/* Populates per-field errors and returns their aggregate. Partial values survive.
 * IPMI strings point to static storage. Event-only/remote-owner records are not queried. */
BC_IPMI_API bc_status bc_ipmi_sensor_details_get(bc_ipmi_session *, const bc_ipmi_sensor_descriptor *, bc_sensor_details *);
#ifdef __cplusplus
}
#endif
#endif

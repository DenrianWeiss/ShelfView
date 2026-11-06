#ifndef BC_REDFISH_INTERNAL_H
#define BC_REDFISH_INTERNAL_H
#include "bcontrol/redfish.h"
#include "yyjson.h"
int bc_redfish_uri_valid(bc_string);
int bc_redfish_same_origin_path(bc_string origin, bc_string value, bc_string *out);
bc_status bc_redfish_task_identity_capture(bc_bytes, unsigned char *, uint32_t, uint32_t *);
int bc_redfish_resource_type(yyjson_val *, const char *, const char *);
bc_status bc_redfish_parse_sensor(yyjson_val *, bc_redfish_sensor_info *);
bc_status bc_redfish_parse_sensor_details(yyjson_val *, bc_redfish_sensor_info *, bc_sensor_details *);
bc_status bc_redfish_temperature(const bc_redfish_sensor_info *, const bc_redfish_context_info *, uint32_t, bc_temperature_reading *);
void bc_redfish_parse_context(yyjson_val *, bc_string, bc_redfish_context_info *);
void bc_redfish_clear_context(bc_redfish_context_info *);
void bc_redfish_clear_sensor(bc_redfish_sensor_info *);
/* VERBOSE-only sanitized request summary; never emits credentials or bodies
 * verbatim. */
void bc_redfish_log_request(const char *, const bc_endpoint *, uint32_t, bc_string, bc_bytes);
#endif

#ifndef BCONTROL_SENSOR_COMPAT_H
#define BCONTROL_SENSOR_COMPAT_H
#include "redfish.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_sensor_compat bc_sensor_compat;
#define BC_SENSOR_COMPAT_THRESHOLDS 1u
#define BC_SENSOR_COMPAT_DISCRETE 2u
/* Normalize advertised older sensor schemas to the common read-only model. */
BC_REDFISH_API bc_status bc_sensor_compat_create(bc_bytes, bc_sensor_compat **);
BC_REDFISH_API bc_bytes bc_sensor_compat_json(const bc_sensor_compat *);
BC_REDFISH_API bc_string bc_sensor_compat_link(const bc_sensor_compat *, uint32_t kind);
BC_REDFISH_API void bc_sensor_compat_destroy(bc_sensor_compat *);
BC_REDFISH_API int bc_redfish_logout_response_succeeded(uint32_t http_status, bc_bytes);
#ifdef __cplusplus
}
#endif
#endif

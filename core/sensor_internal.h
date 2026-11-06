#ifndef BC_SENSOR_INTERNAL_H
#define BC_SENSOR_INTERNAL_H
#include "bcontrol/sensor.h"
#include <string.h>
static inline int bc_sensor_details_valid(const bc_sensor_details *out) {
    return out && out->struct_size == sizeof(*out) && out->abi_version == BC_ABI_VERSION;
}
static inline void bc_sensor_details_reset(bc_sensor_details *out) {
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->abi_version = BC_ABI_VERSION;
}
static inline void bc_sensor_field_set(bc_sensor_details *out, bc_sensor_field *field, uint32_t state, bc_status status) {
    field->state = state; field->status = status;
    if (state == BC_SENSOR_FIELD_ERROR && out->status == BC_OK) out->status = status;
}
static inline void bc_sensor_details_error(bc_sensor_details *out, bc_status status) {
    out->status = status;
    for (unsigned i = 0; i < BC_SENSOR_DETAIL_FIELD_COUNT; ++i)
        bc_sensor_field_set(out, &out->fields[i], status == BC_UNSUPPORTED ? BC_SENSOR_FIELD_UNSUPPORTED : BC_SENSOR_FIELD_ERROR, status);
}
#endif

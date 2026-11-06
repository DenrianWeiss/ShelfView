#ifndef BC_SENSOR_COMPAT_INTERNAL_H
#define BC_SENSOR_COMPAT_INTERNAL_H
#include "bcontrol/sensor_compat.h"
#include "yyjson.h"
bc_status bc_huawei_sensor_normalize(yyjson_mut_doc *, yyjson_mut_val *, char links[2][1025]);
#endif

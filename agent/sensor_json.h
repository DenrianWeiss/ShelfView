#ifndef BC_SENSOR_JSON_H
#define BC_SENSOR_JSON_H
#include "bcontrol/sensor.h"
#include "yyjson.h"
void bc_agent_sensor_details_json(yyjson_mut_doc *, yyjson_mut_val *, const bc_sensor_details *);
#endif

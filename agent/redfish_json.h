#ifndef BC_AGENT_REDFISH_JSON_H
#define BC_AGENT_REDFISH_JSON_H
#include "bcontrol/redfish.h"
#include "yyjson.h"
void bc_agent_redfish_json(yyjson_mut_doc *, const bc_redfish_operation *, const bc_redfish_result *);
const char *bc_agent_reset_name(uint32_t);
#endif

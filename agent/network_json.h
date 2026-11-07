#ifndef BC_AGENT_NETWORK_JSON_H
#define BC_AGENT_NETWORK_JSON_H
#include "bcontrol/redfish.h"
#include "yyjson.h"
void bc_agent_network_rows_json(yyjson_mut_doc *, const bc_redfish_operation *);
#endif

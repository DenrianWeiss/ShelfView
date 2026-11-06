#ifndef BC_ENDPOINT_INTERNAL_H
#define BC_ENDPOINT_INTERNAL_H
#include "bcontrol/bcontrol.h"
#define BC_REDFISH_PROFILE_INSPUR 1u
BC_API void bc_endpoint_redfish_profile_set(bc_endpoint *, uint32_t);
BC_API uint32_t bc_endpoint_redfish_profile(const bc_endpoint *);
#endif

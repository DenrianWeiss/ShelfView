#ifndef BC_MEGARAC_PROBE_INTERNAL_H
#define BC_MEGARAC_PROBE_INTERNAL_H
#include "bcontrol/megarac.h"
bc_status bc_megarac_probe_start_form(bc_endpoint *, const bc_megarac_probe_options *, bc_bytes,
    bc_megarac_probe_completion, void *, bc_megarac_probe **);
#endif

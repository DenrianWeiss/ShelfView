#ifndef BC_MEGARAC_PROBE_INTERNAL_H
#define BC_MEGARAC_PROBE_INTERNAL_H
#include "bcontrol/megarac.h"
typedef bc_status (*bc_megarac_h5_mode_fn)(const bc_response *, int *use_h5);
bc_status bc_megarac_probe_start_form(bc_endpoint *, const bc_megarac_probe_options *, bc_bytes,
    const char *mode_path, bc_megarac_h5_mode_fn,
    bc_megarac_probe_completion, void *, bc_megarac_probe **);
#endif

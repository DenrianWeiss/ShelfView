#ifndef BCONTROL_MEGARAC_LAUNCH_H
#define BCONTROL_MEGARAC_LAUNCH_H
#include "console_factory.h"
#include "megarac.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Transitional discovery bridge. Copies all configuration; no borrowed fields
 * survive the call. The resulting launch is consumed by the generic factory. */
BC_CONSOLE_API bc_status bc_console_launch_from_megarac(const bc_megarac_session_options *, uint32_t keyboard_mode,
    bc_console_launch **);
#ifdef __cplusplus
}
#endif
#endif

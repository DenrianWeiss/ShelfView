#ifndef BCONTROL_CONSOLE_IDRAC_LAUNCH_H
#define BCONTROL_CONSOLE_IDRAC_LAUNCH_H
#include "console_factory.h"
#include "idrac_kvm.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Copies the discovered secondary credential directly into an opaque launch. */
BC_CONSOLE_API bc_status bc_console_launch_from_idrac(const bc_idrac_console_launch *, bc_console_launch **);
/* Creates the short media-ticket exchange without exporting its startup credential. */
BC_CONSOLE_API bc_status bc_console_launch_idrac_auth(const bc_console_launch *, bc_idrac_console_auth **);
#ifdef __cplusplus
}
#endif
#endif

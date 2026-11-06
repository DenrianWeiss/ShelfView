#ifndef BCONTROL_CONSOLE_ENTRY_H
#define BCONTROL_CONSOLE_ENTRY_H
#include "huawei_launch.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Selects an HTTP startup family from connection-bound metadata only.
 * This does not authorize a KVM handshake; its descriptor must still be checked.
 * A nonzero Huawei format must come from its parsed ActionInfo contract. */
BC_DISCOVERY_API bc_status bc_console_http_family_select(const bc_service_profile *, uint32_t count,
    bc_string huawei_export, bc_string huawei_download, uint32_t huawei_format,
    uint32_t huawei_modes, uint32_t *family);
/* Only for an unknown, credential-free public entry before any login attempt.
 * Hard authentication/busy/lock/transport failures can never become a chooser. */
BC_DISCOVERY_API int bc_console_entry_can_select_manually(bc_status, uint32_t http_status);
#ifdef __cplusplus
}
#endif
#endif

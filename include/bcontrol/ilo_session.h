#ifndef BCONTROL_ILO_SESSION_H
#define BCONTROL_ILO_SESSION_H
#include "ilo.h"
#include "console_session.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Owns decoder and independent input state. Token is copied during creation;
 * emit/user must remain valid until the unified session is destroyed. */
BC_ILO_API bc_status bc_ilo_session_create(uint32_t generation, bc_string token, uint32_t max_width,
    uint32_t max_height, bc_console_emit, void *, bc_console_session **);
/* Borrowed decoder and input state must outlive the wrapper. Emit is one binary
 * message on the video/input WebSocket; command-channel replies remain separate. */
BC_ILO_API bc_status bc_ilo_session_wrap(bc_ilo_kvm *, bc_ilo_input *, bc_console_emit, void *, bc_console_session **);
#ifdef __cplusplus
}
#endif
#endif

#ifndef BCONTROL_AVOCENT_SESSION_H
#define BCONTROL_AVOCENT_SESSION_H
#include "avocent.h"
#include "console_session.h"
#ifdef __cplusplus
extern "C" {
#endif
BC_AVOCENT_API bc_status bc_avocent_session_create(bc_string username, bc_string password,
    uint32_t client_id, uint32_t max_width, uint32_t max_height,
    bc_console_emit, void *, bc_console_session **);
#ifdef __cplusplus
}
#endif
#endif

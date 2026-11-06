#ifndef BCONTROL_MEDIA_PROVIDER_H
#define BCONTROL_MEDIA_PROVIDER_H
#include "media_session.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t struct_size;
    bc_status (*feed)(void *, bc_bytes);
    bc_status (*poll)(void *, uint32_t);
    bc_status (*control)(void *, uint32_t);
    bc_status (*info)(const void *, bc_media_session_info *);
    bc_status (*attach)(void *, const bc_media_source *);
    void (*destroy)(void *);
    const bc_service_profile *(*profile)(const void *);
    const bc_console_failure *(*failure)(const void *);
} bc_media_provider;
BC_API bc_status bc_media_session_wrap(const bc_media_provider *, void *, bc_media_session **);
/* Factory-only transfer after a successful wrap. */
BC_API void bc_media_session_own(bc_media_session *);
#ifdef __cplusplus
}
#endif
#endif

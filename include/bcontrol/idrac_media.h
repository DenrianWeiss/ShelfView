#ifndef BCONTROL_IDRAC_MEDIA_H
#define BCONTROL_IDRAC_MEDIA_H
#include "idrac_kvm.h"
#include "media_session.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_idrac_media bc_idrac_media;
/* Callbacks are synchronous; buffers are borrowed for the duration of the call.
 * emit must preserve each invocation as a distinct binary WebSocket message. */
typedef bc_status (*bc_idrac_media_emit)(void *, const uint8_t *, uint32_t);
typedef bc_status (*bc_idrac_media_read)(void *, uint64_t, uint32_t, uint8_t *);
typedef struct bc_idrac_media_source {
    uint64_t size;
    void *userdata;
    bc_idrac_media_read read;
} bc_idrac_media_source;
typedef struct bc_idrac_media_state {
    uint32_t ready, connected, attached, mounted, ejecting, server_status;
    uint64_t bytes_read;
} bc_idrac_media_state;
/* key is the media key2 from the console's 247/172 notification, not VCSID2.
 * The device may request the reply before sending type 16. */
BC_IDRAC_API bc_status bc_idrac_media_create(bc_idrac_media_emit, void *, bc_string key, bc_idrac_media **);
BC_IDRAC_API bc_status bc_idrac_media_feed_message(bc_idrac_media *, const uint8_t *, uint32_t);
BC_IDRAC_API bc_status bc_idrac_media_attach_cd(bc_idrac_media *, const bc_idrac_media_source *);
BC_IDRAC_API bc_status bc_idrac_media_eject(bc_idrac_media *);
BC_IDRAC_API bc_status bc_idrac_media_heartbeat(bc_idrac_media *);
/* Best-effort device unmap used when the media window closes before eject. */
BC_IDRAC_API bc_status bc_idrac_media_unmap(bc_idrac_media *);
BC_IDRAC_API const bc_idrac_media_state *bc_idrac_media_state_get(const bc_idrac_media *);
BC_IDRAC_API const bc_service_profile *bc_idrac_media_profile_get(const bc_idrac_media *);
BC_IDRAC_API const bc_console_failure *bc_idrac_media_failure_get(const bc_idrac_media *);
/* Destroy releases local resources only; it does not imply a confirmed eject. */
BC_IDRAC_API void bc_idrac_media_destroy(bc_idrac_media *);
BC_IDRAC_API bc_status bc_idrac_media_wrap(bc_idrac_media *, bc_media_session **);
#ifdef __cplusplus
}
#endif
#endif

#ifndef BCONTROL_ILO_MEDIA_H
#define BCONTROL_ILO_MEDIA_H
#include "ilo.h"
#include "media_session.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_ILO_MEDIA_FLOPPY 2u
#define BC_ILO_MEDIA_CD 3u
#define BC_ILO_MEDIA_USB 4u
typedef struct bc_ilo_media bc_ilo_media;
typedef bc_status (*bc_ilo_media_emit)(void *, const uint8_t *, uint32_t);
typedef bc_status (*bc_ilo_media_read)(void *, uint64_t offset, uint32_t length, uint8_t *);
typedef struct {
    uint64_t size;
    void *userdata;
    bc_ilo_media_read read;
} bc_ilo_media_source;
typedef struct {
    uint32_t authenticated, attached, server_status;
    uint64_t bytes_read;
} bc_ilo_media_state;
/* Read-only sources; callbacks are synchronous and preserve WebSocket boundaries.
 * Create sends the hello. Feed receives one complete binary message at a time. */
BC_ILO_API bc_status bc_ilo_media_create(uint32_t kind, bc_string token,
    const bc_ilo_media_source *, bc_ilo_media_emit, void *, bc_ilo_media **);
BC_ILO_API bc_status bc_ilo_media_feed(bc_ilo_media *, const uint8_t *, uint32_t);
BC_ILO_API bc_status bc_ilo_media_heartbeat(bc_ilo_media *);
BC_ILO_API bc_status bc_ilo_media_eject(bc_ilo_media *);
BC_ILO_API const bc_ilo_media_state *bc_ilo_media_state_get(const bc_ilo_media *);
/* Destroy only releases local resources, not a confirmed remote eject. */
BC_ILO_API void bc_ilo_media_destroy(bc_ilo_media *);
BC_ILO_API bc_status bc_ilo_media_wrap(bc_ilo_media *, bc_media_session **);
#ifdef __cplusplus
}
#endif
#endif

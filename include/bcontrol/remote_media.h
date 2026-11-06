#ifndef BCONTROL_REMOTE_MEDIA_H
#define BCONTROL_REMOTE_MEDIA_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_remote_media_registry bc_remote_media_registry;
/* One registry belongs to one device identity; its owner serializes calls.
 * Begin precedes submission. Clear requires definitive rejection or empty-slot
 * readback. Release preserves ownership across management connections. */
BC_API bc_status bc_remote_media_registry_create(uint32_t capacity, bc_remote_media_registry **);
BC_API bc_status bc_remote_media_registry_begin(bc_remote_media_registry *, bc_string owner, bc_string connection, bc_string uri);
/* URI is borrowed until clear/destroy. BUSY means another connection holds it. */
BC_API bc_status bc_remote_media_registry_bind(bc_remote_media_registry *, bc_string owner, bc_string connection, bc_string *uri);
BC_API bc_status bc_remote_media_registry_can_mount(const bc_remote_media_registry *, bc_string uri);
/* Explicit eject may borrow an unbound record without changing its owner. */
BC_API bc_status bc_remote_media_registry_claim_eject(bc_remote_media_registry *, bc_string owner, bc_string connection, bc_string uri);
BC_API void bc_remote_media_registry_release(bc_remote_media_registry *, bc_string connection);
BC_API void bc_remote_media_registry_clear(bc_remote_media_registry *, bc_string connection);
BC_API void bc_remote_media_registry_destroy(bc_remote_media_registry *);
#ifdef __cplusplus
}
#endif
#endif

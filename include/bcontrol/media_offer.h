#ifndef BCONTROL_MEDIA_OFFER_H
#define BCONTROL_MEDIA_OFFER_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_media_offer bc_media_offer;
#define BC_MEDIA_OFFER_READY 1u
typedef struct { uint32_t struct_size, flags, port; } bc_media_offer_info;
/* Immutable, independently owned credential snapshot. No credential accessors
 * are exposed to platform code. Release after media creation has finished. */
BC_API bc_status bc_media_offer_info_get(const bc_media_offer *, bc_media_offer_info *);
BC_API void bc_media_offer_destroy(bc_media_offer *);
#ifdef __cplusplus
}
#endif
#endif

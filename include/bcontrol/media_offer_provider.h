#ifndef BCONTROL_MEDIA_OFFER_PROVIDER_H
#define BCONTROL_MEDIA_OFFER_PROVIDER_H
#include "media_offer.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_MEDIA_OFFER_HUAWEI 1u
#define BC_MEDIA_OFFER_ILO 2u
#define BC_MEDIA_OFFER_IDRAC 3u
#define BC_MEDIA_OFFER_MEGARAC 4u
#define BC_MEDIA_OFFER_AVOCENT 6u
#define BC_MEDIA_OFFER_ATEN 7u
#define BC_MEDIA_OFFER_NBD 8u
typedef struct { uint32_t length, kind; char token[256]; } bc_media_ticket;
BC_API bc_status bc_media_offer_token_create(uint32_t protocol, uint32_t kind, bc_string, bc_media_offer **);
/* Adapter-only creation and access. Copies payload; destroy wipes it. */
BC_API bc_status bc_media_offer_create(uint32_t protocol, const bc_media_offer_info *, const void *, uint32_t, bc_media_offer **);
BC_API uint32_t bc_media_offer_protocol(const bc_media_offer *);
BC_API const void *bc_media_offer_payload(const bc_media_offer *, uint32_t protocol, uint32_t size);
#ifdef __cplusplus
}
#endif
#endif

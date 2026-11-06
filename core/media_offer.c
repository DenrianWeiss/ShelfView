#include "bcontrol/media_offer_provider.h"
#include <stdlib.h>
#include <string.h>
struct bc_media_offer {
    uint32_t protocol, size;
    bc_media_offer_info info;
    void *payload;
};
bc_status bc_media_offer_create(uint32_t protocol, const bc_media_offer_info *info,
    const void *payload, uint32_t size, bc_media_offer **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!protocol || !info || info->struct_size != sizeof(*info) || !payload || !size) return BC_INVALID_ARGUMENT;
    bc_media_offer *offer = calloc(1, sizeof(*offer));
    if (!offer) return BC_NO_MEMORY;
    offer->payload = malloc(size);
    if (!offer->payload) { free(offer); return BC_NO_MEMORY; }
    memcpy(offer->payload, payload, size);
    offer->protocol = protocol; offer->size = size; offer->info = *info;
    *out = offer;
    return BC_OK;
}
uint32_t bc_media_offer_protocol(const bc_media_offer *offer) { return offer ? offer->protocol : 0; }
const void *bc_media_offer_payload(const bc_media_offer *offer, uint32_t protocol, uint32_t size) {
    return offer && offer->protocol == protocol && offer->size == size ? offer->payload : NULL;
}
bc_status bc_media_offer_info_get(const bc_media_offer *offer, bc_media_offer_info *out) {
    if (!offer || !out || out->struct_size != sizeof(*out)) return BC_INVALID_ARGUMENT;
    *out = offer->info;
    return BC_OK;
}
void bc_media_offer_destroy(bc_media_offer *offer) {
    if (!offer) return;
    volatile unsigned char *bytes = offer->payload;
    for (uint32_t i = 0; i < offer->size; ++i) bytes[i] = 0;
    free(offer->payload); free(offer);
}

bc_status bc_media_offer_token_create(uint32_t protocol, uint32_t kind, bc_string token, bc_media_offer **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (protocol < BC_MEDIA_OFFER_ILO || protocol > BC_MEDIA_OFFER_MEGARAC ||
        !token.data || !token.length || token.length > 256) return BC_INVALID_ARGUMENT;
    bc_media_ticket ticket = {0}; ticket.length = (uint32_t)token.length; ticket.kind = kind ? kind : 3;
    memcpy(ticket.token, token.data, (size_t)token.length);
    bc_media_offer_info info = {sizeof(info), BC_MEDIA_OFFER_READY, 0};
    bc_status status = bc_media_offer_create(protocol, &info, &ticket, sizeof(ticket), out);
    volatile unsigned char *wipe = (volatile unsigned char *)&ticket;
    for (size_t i = 0; i < sizeof(ticket); ++i) wipe[i] = 0;
    return status;
}

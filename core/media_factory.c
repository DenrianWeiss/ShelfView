#include "bcontrol/media_factory.h"
#include "bcontrol/media_provider.h"
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/ilo_media.h"
#include "bcontrol/avocent_media.h"
#include "bcontrol/aten.h"
#include "bcontrol/nbd_media.h"
#include "bcontrol/idrac_media.h"
#include "bcontrol/megarac.h"
#include "bcontrol/huawei_session.h"
#include <string.h>
#include "bcontrol/media_output_provider.h"

bc_status bc_media_offer_from_token(uint32_t protocol, uint32_t kind, bc_string token, bc_media_offer **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (protocol != BC_CONSOLE_PROTOCOL_ILO && protocol != BC_CONSOLE_PROTOCOL_IDRAC &&
        protocol != BC_CONSOLE_PROTOCOL_MEGARAC) return BC_UNSUPPORTED;
    return bc_media_offer_token_create(protocol, kind, token, out);
}

static bc_status create(const bc_media_options *o, bc_media_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!o || o->struct_size != sizeof(*o) || o->abi_version != BC_ABI_VERSION || !o->offer || !o->emit ||
        (o->flags & ~(BC_MEDIA_TRANSPORT_WEBSOCKET | BC_MEDIA_TRANSPORT_JVIEWER_TUNNEL)) || o->instance > 255 ||
        (o->source && (o->source->struct_size != sizeof(*o->source) || !o->source->read))) return BC_INVALID_ARGUMENT;
    uint32_t protocol = bc_media_offer_protocol(o->offer);
    if ((o->flags & BC_MEDIA_TRANSPORT_JVIEWER_TUNNEL) &&
        (protocol != BC_CONSOLE_PROTOCOL_MEGARAC || (o->flags & BC_MEDIA_TRANSPORT_WEBSOCKET))) return BC_INVALID_ARGUMENT;
    const bc_media_ticket *ticket = bc_media_offer_payload(o->offer, protocol, sizeof(bc_media_ticket));
    bc_string token = ticket ? (bc_string){ticket->token, ticket->length} : (bc_string){NULL, 0};
    bc_status status;
    if (protocol == BC_MEDIA_OFFER_NBD) {
        status = bc_nbd_media_create(o, out);
    } else if (protocol == BC_MEDIA_OFFER_ATEN) {
        status = bc_aten_media_create(o, out);
    } else if (protocol == BC_MEDIA_OFFER_AVOCENT) {
        status = bc_avocent_media_create(o, out);
    } else if (protocol == BC_CONSOLE_PROTOCOL_ILO) {
        if (!ticket || !o->source) return BC_INVALID_ARGUMENT;
        bc_ilo_media_source source = {o->source->size, o->source->userdata, o->source->read};
        bc_ilo_media *media = NULL;
        status = bc_ilo_media_create(ticket->kind, token, &source, o->emit, o->user, &media);
        if (status != BC_OK) return status;
        status = bc_ilo_media_wrap(media, out);
        if (status != BC_OK) bc_ilo_media_destroy(media);
    } else if (protocol == BC_CONSOLE_PROTOCOL_IDRAC) {
        if (!ticket) return BC_INVALID_ARGUMENT;
        bc_idrac_media *media = NULL;
        status = bc_idrac_media_create(o->emit, o->user, token, &media);
        if (status != BC_OK) return status;
        status = bc_idrac_media_wrap(media, out);
        if (status != BC_OK) bc_idrac_media_destroy(media);
    } else if (protocol == BC_CONSOLE_PROTOCOL_MEGARAC) {
        if (!ticket || !o->source || !o->receive || !o->clock || !o->timeout_ms) return BC_INVALID_ARGUMENT;
        bc_megarac_cd_source source = {sizeof(source), o->source->userdata, o->source->size, o->source->read};
        uint32_t flags = o->flags ? BC_MEGARAC_MEDIA_SEND_DISCONNECT : 0;
        if (o->flags & BC_MEDIA_TRANSPORT_JVIEWER_TUNNEL) flags |= BC_MEGARAC_MEDIA_TUNNEL_PREFIX;
        bc_megarac_media_service_options options = {sizeof(options), BC_ABI_VERSION, &source, token, flags,
            o->instance, o->timeout_ms};
        bc_megarac_media_io io = {o->user, o->emit, o->receive, o->clock};
        bc_megarac_media_service *media = NULL;
        status = bc_megarac_media_service_create(&options, &io, &media);
        if (status != BC_OK) return status;
        status = bc_megarac_media_wrap(media, out);
        if (status != BC_OK) bc_megarac_media_service_destroy(media);
    } else if (protocol == BC_MEDIA_OFFER_HUAWEI) {
        if (!o->source || !o->receive || !o->clock || !o->timeout_ms) return BC_INVALID_ARGUMENT;
        bc_huawei_vmm_source source = {sizeof(source), o->source->userdata, o->source->size, o->source->read};
        bc_huawei_media_options options = {0};
        options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION; options.source = &source;
        options.timeout_ms = o->timeout_ms; options.heartbeat_interval_ms = o->heartbeat_interval_ms;
        options.clock = o->clock; options.clock_user = o->user;
        bc_huawei_io io = {o->user, o->emit, o->receive};
        bc_huawei_media *media = NULL;
        status = bc_huawei_media_create_offer(o->offer, &options, &io, &media);
        if (status != BC_OK) return status;
        status = bc_huawei_media_wrap(media, out);
        if (status != BC_OK) bc_huawei_media_destroy(media);
    } else return BC_UNSUPPORTED;
    if (status == BC_OK) bc_media_session_own(*out);
    return status;
}

bc_status bc_media_session_create(const bc_media_options *options, bc_media_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options)) return BC_INVALID_ARGUMENT;
    if (options->emit) return create(options, out);
    uint32_t protocol = bc_media_offer_protocol(options->offer);
    if (protocol != BC_MEDIA_OFFER_ILO && protocol != BC_MEDIA_OFFER_IDRAC) return BC_INVALID_ARGUMENT;
    bc_media_output *output = NULL;
    bc_status status = bc_media_output_create(&output);
    if (status != BC_OK) return status;
    bc_media_options buffered = *options; buffered.emit = bc_media_output_emit; buffered.user = output;
    status = create(&buffered, out);
    if (status == BC_OK) bc_media_session_bind_output(*out, output);
    else bc_media_output_destroy(output);
    return status;
}

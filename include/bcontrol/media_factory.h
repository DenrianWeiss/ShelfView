#ifndef BCONTROL_MEDIA_FACTORY_H
#define BCONTROL_MEDIA_FACTORY_H
#include "console_factory.h"
#include "media_session.h"
#include "media_offer.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_MEDIA_TRANSPORT_WEBSOCKET 1u
#define BC_MEDIA_TRANSPORT_JVIEWER_TUNNEL 2u
/* Transitional discovery bridge. Protocol uses BC_CONSOLE_PROTOCOL_*; kind is
 * the source device kind (zero selects CD). Copies and wipes the ticket. */
BC_CONSOLE_API bc_status bc_media_offer_from_token(uint32_t protocol, uint32_t kind,
    bc_string token, bc_media_offer **);
typedef struct {
    uint32_t struct_size, abi_version;
    const bc_media_offer *offer;
    const bc_media_source *source;
    bc_console_emit emit;
    bc_console_receive receive;
    bc_console_clock clock;
    void *user;
    uint32_t timeout_ms, heartbeat_interval_ms, flags, instance;
} bc_media_options;
/* A NULL emit selects the bounded core output queue for feed-driven adapters.
 * Copies offer/source descriptors; callbacks and their owners remain borrowed.
 * START drives callback transports; feed-driven transports may emit a hello at
 * creation. Close explicitly before destroy when network cleanup is needed. */
BC_CONSOLE_API bc_status bc_media_session_create(const bc_media_options *, bc_media_session **);
#ifdef __cplusplus
}
#endif
#endif

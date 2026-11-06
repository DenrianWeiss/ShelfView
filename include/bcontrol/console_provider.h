#ifndef BCONTROL_CONSOLE_PROVIDER_H
#define BCONTROL_CONSOLE_PROVIDER_H
#include "console_session.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t struct_size, display_modes, input_capabilities;
    bc_status (*input)(void *, const bc_console_input *);
    bc_status (*tile)(void *, bc_display_tile *);
    bc_status (*media)(void *, bc_display_stream_packet *);
    void (*ack_display)(void *);
    void (*destroy)(void *);
    bc_status (*feed)(void *, uint32_t channel, const uint8_t *, uint32_t);
    bc_status (*output)(void *, uint32_t channel, uint8_t *, uint32_t, uint32_t *);
    uint32_t controls;
    bc_status (*control)(void *, uint32_t);
    bc_status (*info)(void *, bc_console_info *);
    bc_status (*feed_some)(void *, uint32_t, const uint8_t *, uint32_t, uint32_t *);
    bc_string (*name)(void *);
    bc_status (*poll)(void *, uint32_t);
    bc_status (*tick)(void *, uint64_t);
    bc_status (*statistics)(void *, bc_console_statistics *);
    bc_status (*media_offer)(void *, bc_media_offer **);
} bc_console_provider;
/* Provider is copied; context ownership transfers only on success. Its input
 * callback must not touch mutable state owned by the display lane.
 * display_modes=0 describes an input-only session; display callbacks may be NULL. */
BC_API bc_status bc_console_session_wrap(const bc_console_provider *, void *, bc_console_session **);
#ifdef __cplusplus
}
#endif
#endif

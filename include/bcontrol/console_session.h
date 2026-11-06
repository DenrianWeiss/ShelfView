#ifndef BCONTROL_CONSOLE_SESSION_H
#define BCONTROL_CONSOLE_SESSION_H
#include "display.h"
#include "console.h"
#include "media_offer.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_CONSOLE_INPUT_KEY 1u
#define BC_CONSOLE_INPUT_POINTER 2u
#define BC_CONSOLE_INPUT_SCROLL 3u
#define BC_CONSOLE_INPUT_HAS_SCROLL 1u

#define BC_CONSOLE_CONTROL_REFRESH 1u
#define BC_CONSOLE_CONTROL_HEARTBEAT 2u
#define BC_CONSOLE_CONTROL_QUERY_INPUT_STATE 4u
#define BC_CONSOLE_CONTROL_CLOSE 8u
#define BC_CONSOLE_CONTROL_START 16u
/* Media-channel notifications only; success does not confirm a remote mount or removal. */
#define BC_CONSOLE_CONTROL_MEDIA_ENABLE 32u
#define BC_CONSOLE_CONTROL_MEDIA_DISABLE 64u
#define BC_CONSOLE_CONTROL_SOURCE_ATTACH 128u
#define BC_CONSOLE_CONTROL_SOURCE_DETACH 256u

#define BC_CONSOLE_INFO_READY_KNOWN 1u
#define BC_CONSOLE_INFO_READY 2u
#define BC_CONSOLE_INFO_LEDS_VALID 4u
#define BC_CONSOLE_INFO_PROFILE_VALID 8u
#define BC_CONSOLE_INFO_FAILURE_VALID 16u
/* Local terminal states, not remote cleanup confirmation. Unset means unreported. */
#define BC_CONSOLE_INFO_CLOSED 32u
#define BC_CONSOLE_INFO_FAILED 64u
#define BC_CONSOLE_INFO_MEDIA_STATE_VALID 128u
#define BC_CONSOLE_INFO_MEDIA_REMOVAL_UNCONFIRMED 256u
#define BC_CONSOLE_INFO_MEDIA_MODE_REQUESTED 512u
#define BC_CONSOLE_INFO_MEDIA_SOURCE_ANNOUNCED 1024u
typedef struct {
    uint32_t struct_size, flags, keyboard_leds;
    /* Recommended maximum delay between tick calls; zero means no periodic tick needed. */
    uint32_t tick_interval_ms;
    bc_service_profile profile;
    bc_console_failure failure;
} bc_console_info;

/* Protocol-lane counters only; independently decoded/presented frames are
 * counted by the display scheduler. Unsupported adapters report unsupported. */
typedef struct {
    uint32_t struct_size, reserved;
    uint64_t received_bytes, image_packets, heartbeats, dropped_frames;
} bc_console_statistics;

typedef struct bc_console_session bc_console_session;
typedef bc_status (*bc_console_emit)(void *, const uint8_t *, uint32_t);
/* Pointer buttons: left=1, right=2, middle=4. Coordinates and canvas dimensions
 * describe the displayed snapshot, so input never reads mutable decoder state. */
typedef struct {
    uint32_t struct_size, type, keysym, down, buttons, x, y, width, height;
    int32_t wheel;
} bc_console_input;
/* The platform serializes each lane separately. Input may run concurrently with
 * display acquisition/acknowledgement and decoder feed. It never calls display.
 * Gate calls on connection readiness, and quiesce both lanes before destruction. */
BC_API bc_status bc_console_session_input(bc_console_session *, const bc_console_input *);
BC_API bc_status bc_console_session_chord(bc_console_session *, const uint32_t *, uint32_t count);
BC_API uint32_t bc_console_session_input_capabilities(const bc_console_session *);
BC_API uint32_t bc_console_session_display_modes(const bc_console_session *);
/* Borrowed tile/packet storage belongs to the display lane. Copy/consume before
 * ack or advancing the decoder; no drawing callback runs inside the core. */
/* Decode-lane transport input/output. Preserve transport message boundaries;
 * stream adapters also accept partial chunks. Channel identifiers come from the
 * connection setup. Drain output after feeding; written=0 means no pending data.
 * These operations never invoke the input-lane emit callback. */
/* Controls run on the decode/protocol owner lane, never the input lane.
 * CLOSE queues protocol notification only; it does not confirm remote cleanup
 * or destroy the session. Drain output before closing the transport. */
/* Read on the decoder owner lane; the returned snapshot owns no borrowed pointers. */
/* Copies name bytes on the decoder lane; no NUL terminator is added.
 * written reports required capacity on BC_LIMIT_EXCEEDED. */
BC_API bc_status bc_console_session_name(const bc_console_session *, uint8_t *, uint32_t capacity, uint32_t *written);
/* Read on the protocol lane; success returns an independently owned offer. */
BC_API bc_status bc_console_session_media_offer(const bc_console_session *, bc_media_offer **);
BC_API bc_status bc_console_session_statistics_get(const bc_console_session *, bc_console_statistics *);
BC_API bc_status bc_console_session_info_get(const bc_console_session *, bc_console_info *);
BC_API uint32_t bc_console_session_controls(const bc_console_session *);
BC_API bc_status bc_console_session_control(bc_console_session *, uint32_t control);
/* Platform schedules these on the protocol owner lane. poll uses the bound
 * transport callbacks; tick advances input timers using monotonic milliseconds.
 * Unsupported scheduling modes return BC_UNSUPPORTED. */
BC_API bc_status bc_console_session_poll(bc_console_session *, uint32_t timeout_ms);
BC_API bc_status bc_console_session_tick(bc_console_session *, uint64_t now_ms);
BC_API bc_status bc_console_session_feed(bc_console_session *, uint32_t channel, const uint8_t *, uint32_t);
/* May stop at a frame boundary. Consume the frame before feeding the remainder. */
BC_API bc_status bc_console_session_feed_some(bc_console_session *, uint32_t channel, const uint8_t *, uint32_t, uint32_t *consumed);
BC_API bc_status bc_console_session_output(bc_console_session *, uint32_t channel, uint8_t *, uint32_t, uint32_t *);
BC_API bc_status bc_console_session_tile(bc_console_session *, bc_display_tile *);
BC_API bc_status bc_console_session_media(bc_console_session *, bc_display_stream_packet *);
BC_API void bc_console_session_ack_display(bc_console_session *);
/* Releases adapter-owned resources. Borrowed transports/decoders remain owned
 * by their callers; owned creation helpers release their protocol objects. */
BC_API void bc_console_session_destroy(bc_console_session *);
#ifdef __cplusplus
}
#endif
#endif

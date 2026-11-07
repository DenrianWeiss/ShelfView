#ifndef BCONTROL_CONSOLE_FACTORY_H
#define BCONTROL_CONSOLE_FACTORY_H
#include "console_session.h"
#include "kvm.h"
#include "decode_job.h"
#include "media_offer.h"
#if defined(_WIN32)
# ifdef BC_CONSOLE_BUILD
#  define BC_CONSOLE_API __declspec(dllexport)
# else
#  define BC_CONSOLE_API __declspec(dllimport)
# endif
#else
# define BC_CONSOLE_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define BC_CONSOLE_PROTOCOL_RFB 1u
#define BC_CONSOLE_PROTOCOL_ILO 2u
#define BC_CONSOLE_PROTOCOL_IDRAC 3u
#define BC_CONSOLE_PROTOCOL_MEGARAC 4u
#define BC_CONSOLE_PROTOCOL_HUAWEI 5u
#define BC_CONSOLE_PROTOCOL_AVOCENT 6u
#define BC_CONSOLE_PROTOCOL_ATEN 7u
typedef uint8_t (*bc_console_led_snapshot)(void *);
typedef struct bc_console_launch bc_console_launch;
typedef struct bc_console_bootstrap bc_console_bootstrap;
/* A short, frame-free prerequisite exchange selected by the launch adapter. */
BC_CONSOLE_API bc_status bc_console_bootstrap_create(const bc_console_launch *, bc_console_bootstrap **);
BC_CONSOLE_API bc_status bc_console_bootstrap_feed(bc_console_bootstrap *, bc_bytes);
BC_CONSOLE_API bc_status bc_console_bootstrap_output(bc_console_bootstrap *, uint8_t *, uint32_t, uint32_t *);
BC_CONSOLE_API bc_status bc_console_bootstrap_media_offer(const bc_console_bootstrap *, bc_media_offer **);
BC_CONSOLE_API bc_status bc_console_bootstrap_close(bc_console_bootstrap *);
BC_CONSOLE_API const bc_console_failure *bc_console_bootstrap_failure_get(const bc_console_bootstrap *);
BC_CONSOLE_API void bc_console_bootstrap_destroy(bc_console_bootstrap *);
typedef bc_status (*bc_console_receive)(void *, uint8_t *, uint32_t, uint32_t *, uint32_t);
typedef uint64_t (*bc_console_clock)(void *);
/* Transitional bridge for token-based discovery. Copies credentials; the
 * descriptor has no field accessors and is wiped on release. */
BC_CONSOLE_API bc_status bc_console_launch_from_token(uint32_t protocol, uint32_t generation,
    bc_string token, bc_console_launch **);
/* AVSP 2.41 temporary credentials, obtained from the device's launch service. */
BC_CONSOLE_API bc_status bc_console_launch_from_avocent(bc_string username, bc_string password,
    uint32_t client_id, bc_console_launch **);
BC_CONSOLE_API void bc_console_launch_destroy(bc_console_launch *);
/* Launch is borrowed only during creation. The resulting session owns its
 * credential copy; framebuffer and callback context outlive the session. */
typedef struct {
    uint32_t struct_size, abi_version;
    bc_kvm_options display;
    const bc_console_launch *launch;
    bc_console_emit emit;
    bc_console_led_snapshot leds;
    void *user;
    bc_decode_submit submit;
    /* Callback-driven transports use emit/receive with transport_user; the
     * decode scheduler uses submit/user. Clock is monotonic milliseconds. */
    bc_console_receive receive;
    void *transport_user;
    bc_console_clock clock;
    void *clock_user;
    uint32_t handshake_timeout_ms, heartbeat_interval_ms;
} bc_console_options;
BC_CONSOLE_API bc_status bc_console_session_create(const bc_console_options *, bc_console_session **);
#ifdef __cplusplus
}
#endif
#endif

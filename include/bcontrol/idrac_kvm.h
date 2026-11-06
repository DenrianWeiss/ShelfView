#ifndef BCONTROL_IDRAC_KVM_H
#define BCONTROL_IDRAC_KVM_H
#include "kvm.h"
#include "console.h"
#if defined(_WIN32)
# ifdef BC_IDRAC_BUILD
#  define BC_IDRAC_API __declspec(dllexport)
# else
#  define BC_IDRAC_API __declspec(dllimport)
# endif
#else
# define BC_IDRAC_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_idrac_kvm bc_idrac_kvm;
#define BC_IDRAC_LAUNCH_USERINFO 1u
#define BC_IDRAC_LAUNCH_FRAGMENT 2u
/* URL components from the platform URL parser. Query is percent-encoded without '?';
 * host uses the same representation as the original endpoint host. Port zero means 443. */
typedef struct {
    uint32_t struct_size, flags;
    bc_string scheme, host, path, query;
    uint32_t port;
} bc_idrac_launch_uri;
typedef struct {
    uint32_t struct_size, kvm_port;
    char primary_key[257], secondary_key[257];
} bc_idrac_console_launch;
/* Extracts the unique Location string from the launch JSON. NUL-terminates on
 * success; written excludes NUL. This is not yet protocol or origin evidence. */
BC_IDRAC_API bc_status bc_idrac_kvm_launch_location(const uint8_t *, uint32_t,
    char *out, uint32_t capacity, uint32_t *written);
/* Validates an eHTML5 launch against the original HTTPS endpoint. No URL is followed.
 * Output contains short-lived secrets: keep in memory, never log, clear after use.
 * Does not establish local-media support or interpret secondary_key as a media key. */
BC_IDRAC_API bc_status bc_idrac_kvm_discover_launch(const bc_idrac_launch_uri *,
    bc_string endpoint_host, uint32_t endpoint_port, bc_idrac_console_launch *, bc_service_profile *);
/* Reads the configured plugin from a known DellAttributes schema. Only a hint
 * for selecting the web-auth contract; cannot authorize a console handshake.
 * Missing/unknown plugin stays unsupported, including firmware that removed it. */
BC_IDRAC_API bc_status bc_idrac_kvm_discover_attributes(const uint8_t *, uint32_t, bc_service_profile *);
/* Bounded console-ticket exchange used before independent media authentication.
 * Does not run RFB, request frames/input, or prove local-media support. Feed one
 * complete binary WebSocket message; drain output before the next feed. */
typedef struct bc_idrac_console_auth bc_idrac_console_auth;
BC_IDRAC_API bc_status bc_idrac_console_auth_create(bc_string secondary_key, bc_idrac_console_auth **);
BC_IDRAC_API bc_status bc_idrac_console_auth_feed_message(bc_idrac_console_auth *, const uint8_t *, uint32_t);
BC_IDRAC_API bc_status bc_idrac_console_auth_output(bc_idrac_console_auth *, uint8_t *, uint32_t, uint32_t *);
/* Borrowed short-lived media key (at most six 4-byte words), empty until ready. */
BC_IDRAC_API bc_string bc_idrac_console_auth_key_get(const bc_idrac_console_auth *);
BC_IDRAC_API const bc_console_failure *bc_idrac_console_auth_failure_get(const bc_idrac_console_auth *);
BC_IDRAC_API bc_status bc_idrac_console_auth_close_session(bc_idrac_console_auth *);
BC_IDRAC_API void bc_idrac_console_auth_destroy(bc_idrac_console_auth *);
BC_IDRAC_API bc_status bc_idrac_kvm_create(const bc_kvm_options *, bc_string secondary_key, bc_idrac_kvm **);
/* Feed exactly one reassembled binary WebSocket message. */
BC_IDRAC_API bc_status bc_idrac_kvm_feed_message(bc_idrac_kvm *, const uint8_t *, uint32_t);
BC_IDRAC_API const bc_service_profile *bc_idrac_kvm_profile_get(const bc_idrac_kvm *);
BC_IDRAC_API const bc_console_failure *bc_idrac_kvm_failure_get(const bc_idrac_kvm *);
BC_IDRAC_API bc_status bc_idrac_kvm_output(bc_idrac_kvm *, uint8_t *, uint32_t, uint32_t *);
BC_IDRAC_API const bc_kvm_frame *bc_idrac_kvm_frame_get(const bc_idrac_kvm *);
BC_IDRAC_API void bc_idrac_kvm_ack_frame(bc_idrac_kvm *);
/* Requests the device's keyboard LED status (247/0/178); the reply updates led_status. */
BC_IDRAC_API bc_status bc_idrac_kvm_query_led(bc_idrac_kvm *);
/* Last keyboard LED status reported by the device (247/178). */
BC_IDRAC_API int bc_idrac_kvm_ready(const bc_idrac_kvm *);
BC_IDRAC_API int bc_idrac_kvm_led_known(const bc_idrac_kvm *);
BC_IDRAC_API int bc_idrac_kvm_led_status(const bc_idrac_kvm *);
/* Sends the device's Dell key message (type 246) carrying the last LED status. */
BC_IDRAC_API bc_status bc_idrac_kvm_key_encode(int down, uint32_t keysym, uint8_t led, uint8_t *out, uint32_t capacity);
BC_IDRAC_API bc_status bc_idrac_kvm_key_event(bc_idrac_kvm *, int down, uint32_t keysym);
BC_IDRAC_API bc_status bc_idrac_kvm_pointer_event(bc_idrac_kvm *, uint8_t buttons, uint16_t x, uint16_t y);
BC_IDRAC_API bc_status bc_idrac_kvm_heartbeat(bc_idrac_kvm *);
/* Queues the device's window-close notification; leaves local teardown to the caller. */
BC_IDRAC_API bc_status bc_idrac_kvm_close_session(bc_idrac_kvm *);
BC_IDRAC_API void bc_idrac_kvm_destroy(bc_idrac_kvm *);
#ifdef __cplusplus
}
#endif
#endif

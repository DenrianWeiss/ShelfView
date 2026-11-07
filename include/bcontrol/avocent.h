#ifndef BCONTROL_AVOCENT_H
#define BCONTROL_AVOCENT_H
#include "bcontrol.h"
#include "kvm.h"
#if defined(_WIN32)
# ifdef BC_AVOCENT_BUILD
#  define BC_AVOCENT_API __declspec(dllexport)
# else
#  define BC_AVOCENT_API __declspec(dllimport)
# endif
#else
# define BC_AVOCENT_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define BC_AVOCENT_MEDIA 2u
#define BC_AVOCENT_CONTROL 3u
#define BC_AVOCENT_VIDEO 4u
#define BC_AVOCENT_TRANSPORT_PLAIN 1u
#define BC_AVOCENT_TRANSPORT_TLS 4u
#define BC_AVOCENT_APCP_SIZE 53u
#define BC_AVOCENT_APCP_EXTENDED_SIZE 68u
#define BC_AVOCENT_APCP_WEBSOCKET_MEDIA 0x0103u
typedef struct {
    uint32_t struct_size, service, port, video_port, apcp;
    char host[256], username[97], password[97];
} bc_avocent_launch;
typedef struct {
    uint32_t struct_size, major, minor, transports, port, challenge_length;
    uint8_t challenge[32];
} bc_avocent_setup;
/* Descriptor metadata only; callers separately select a supported service profile. */
BC_AVOCENT_API bc_status bc_avocent_launch_parse(const uint8_t *, uint32_t, bc_avocent_launch *);
/* Caller supplies random bytes and enforces its endpoint's transport policy. */
BC_AVOCENT_API bc_status bc_avocent_apcp_request(uint32_t channel, uint32_t transports,
    const uint8_t nonce[32], uint8_t out[BC_AVOCENT_APCP_SIZE]);
BC_AVOCENT_API bc_status bc_avocent_apcp_parse(const uint8_t *, uint32_t, bc_avocent_setup *);
/* APCP 1.4 over an established secure WebSocket, AVSP 2.41. */
BC_AVOCENT_API bc_status bc_avocent_apcp_websocket_request(uint32_t channel,
    uint32_t session_id, uint8_t out[BC_AVOCENT_APCP_EXTENDED_SIZE]);
typedef struct {
    uint32_t struct_size, status, session_id, flags;
} bc_avocent_login_result;
/* Call only after the selected transport is established. Credentials are fresh
 * JNLP tickets. No preemption or exclusive-session option is enabled. */
BC_AVOCENT_API bc_status bc_avocent_login_encode(const bc_avocent_launch *, uint32_t client_id,
    uint8_t *out, uint32_t capacity, uint32_t *written);
/* AVSP 2.41 temporary credentials, default non-exclusive login. */
BC_AVOCENT_API bc_status bc_avocent_login_v4_encode(bc_string username, bc_string password,
    uint32_t client_id, uint8_t *out, uint32_t capacity, uint32_t *written);
BC_AVOCENT_API bc_status bc_avocent_media_login_v4_encode(bc_string username, bc_string password,
    uint8_t *out, uint32_t capacity, uint32_t *written);
BC_AVOCENT_API bc_status bc_avocent_login_parse(uint32_t service, const uint8_t *, uint32_t,
    bc_avocent_login_result *);
/* USB HID usage; each press must be paired with a release. */
BC_AVOCENT_API bc_status bc_avocent_key_encode(uint32_t usage, uint32_t pressed, uint8_t out[16]);
/* Absolute device coordinates; buttons left=1, right=2, middle=4. */
BC_AVOCENT_API bc_status bc_avocent_pointer_encode(uint32_t x, uint32_t y,
    uint32_t buttons, int32_t wheel, uint8_t out[16]);
/* Decode one DVC23 block into packed 23-bit pixels. Existing pixels are the
 * reference for skip runs. On failure the caller must discard the block. */
BC_AVOCENT_API bc_status bc_avocent_dvc23_decode(const uint8_t *data, uint32_t length,
    uint32_t width, uint32_t height, uint32_t *pixels, uint32_t capacity);
typedef struct bc_avocent_video bc_avocent_video;
BC_AVOCENT_API bc_status bc_avocent_video_create(uint32_t max_width, uint32_t max_height, bc_avocent_video **);
/* One complete AVSP RVAS video message, including its eight-byte header. */
BC_AVOCENT_API bc_status bc_avocent_video_feed(bc_avocent_video *, const uint8_t *, uint32_t);
BC_AVOCENT_API const bc_kvm_frame *bc_avocent_video_frame(const bc_avocent_video *);
BC_AVOCENT_API void bc_avocent_video_ack(bc_avocent_video *);
BC_AVOCENT_API void bc_avocent_video_destroy(bc_avocent_video *);
typedef struct bc_avocent_kvm bc_avocent_kvm;
/* Channels 0 and 1 are secure control and video WebSockets. */
BC_AVOCENT_API bc_status bc_avocent_kvm_create(bc_string, bc_string, uint32_t client_id,
    uint32_t max_width, uint32_t max_height, bc_avocent_kvm **);
BC_AVOCENT_API void bc_avocent_kvm_destroy(bc_avocent_kvm *);
BC_AVOCENT_API bc_status bc_avocent_kvm_feed(bc_avocent_kvm *, uint32_t channel, const uint8_t *, uint32_t);
BC_AVOCENT_API bc_status bc_avocent_kvm_output(bc_avocent_kvm *, uint32_t channel, uint8_t *, uint32_t, uint32_t *);
BC_AVOCENT_API const bc_kvm_frame *bc_avocent_kvm_frame(const bc_avocent_kvm *);
BC_AVOCENT_API void bc_avocent_kvm_ack(bc_avocent_kvm *);
BC_AVOCENT_API bc_status bc_avocent_kvm_heartbeat(bc_avocent_kvm *);
#ifdef __cplusplus
}
#endif
#endif

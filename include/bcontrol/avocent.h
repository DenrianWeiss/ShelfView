#ifndef BCONTROL_AVOCENT_H
#define BCONTROL_AVOCENT_H
#include "bcontrol.h"
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
typedef struct {
    uint32_t struct_size, status, session_id, flags;
} bc_avocent_login_result;
/* Call only after the selected transport is established. Credentials are fresh
 * JNLP tickets. No preemption or exclusive-session option is enabled. */
BC_AVOCENT_API bc_status bc_avocent_login_encode(const bc_avocent_launch *, uint32_t client_id,
    uint8_t *out, uint32_t capacity, uint32_t *written);
BC_AVOCENT_API bc_status bc_avocent_login_parse(uint32_t service, const uint8_t *, uint32_t,
    bc_avocent_login_result *);
/* USB HID usage; each press must be paired with a release. */
BC_AVOCENT_API bc_status bc_avocent_key_encode(uint32_t usage, uint32_t pressed, uint8_t out[16]);
#ifdef __cplusplus
}
#endif
#endif

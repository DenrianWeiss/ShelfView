#ifndef BCONTROL_CONSOLE_CLIENT_H
#define BCONTROL_CONSOLE_CLIENT_H
#include "console_factory.h"
#include "media_session.h"
#include "socks5.h"
#include "detection.h"
#if defined(_WIN32)
# ifdef BC_CLIENT_BUILD
#  define BC_CLIENT_API __declspec(dllexport)
# else
#  define BC_CLIENT_API __declspec(dllimport)
# endif
#else
# define BC_CLIENT_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define BC_CLIENT_CONSOLE 1u
#define BC_CLIENT_MEDIA 2u
#define BC_CLIENT_PREPARE 3u
/* Discover an independent media offer without connecting or mounting a source. */
#define BC_CLIENT_PREPARE_MEDIA 4u
#define BC_CLIENT_CREATED 0u
#define BC_CLIENT_OPENING 1u
#define BC_CLIENT_ACTIVE 2u
#define BC_CLIENT_CLOSED 3u
#define BC_CLIENT_FAILED 4u
#define BC_CLIENT_SCROLL 1u
#define BC_CLIENT_LOCAL_MEDIA 2u
#define BC_CLIENT_SOURCE_ATTACHED 4u
#define BC_CLIENT_MOUNT_CONFIRMED 8u
#define BC_CLIENT_REMOVAL_UNCONFIRMED 16u
#define BC_CLIENT_HTTP_CHOICE 32u
#define BC_CLIENT_LAYOUT_CHOICE 64u
#define BC_CLIENT_DEPENDENT 128u
typedef struct bc_console_client bc_console_client;
typedef struct {
    uint32_t struct_size, abi_version, service, timeout_ms;
    bc_string address, username, password, ca_file;
    uint32_t cert_policy, tls_min, tls_max, http_contract;
    const bc_socks5_proxy *proxy;
    const bc_media_source *source;
    bc_decode_submit submit;
    void *user;
    int (*cancelled)(void *);
    /* Called only on the startup lane, with the remaining operation budget.
     * A true result authorizes one attempt on the existing authenticated owner. */
    int (*confirm)(void *, uint32_t remaining_ms);
    bc_service_profile preferred;
} bc_console_client_options;
typedef struct {
    uint32_t struct_size, state, flags;
    bc_status status, cleanup_status;
    bc_service_profile profile;
    bc_console_failure failure;
    uint64_t bytes_read;
} bc_console_client_info;
typedef struct { uint32_t id; bc_service_profile profile; char title[64]; } bc_console_client_choice;
#define BC_CONSOLE_MODE_HTML5 1u
#define BC_CONSOLE_MODE_JAVA 2u
#define BC_CONSOLE_MODE_SUPPORT_HTML5 1u
#define BC_CONSOLE_MODE_SUPPORT_JAVA 2u
typedef struct {
    uint32_t struct_size, current, supported_modes;
} bc_console_mode_info;
/* target == 0 reads only. A write requires the expected current mode and returns
 * the observed mode when available. This operation never opens a KVM session. */
BC_CLIENT_API bc_status bc_console_client_mode(const bc_console_client_options *,
    uint32_t expected, uint32_t target, bc_console_mode_info *);
/* A mode that may resolve the given startup failure, or zero if none is known. */
BC_CLIENT_API uint32_t bc_console_client_recommended_mode(const bc_console_failure *);
BC_CLIENT_API bc_status bc_console_client_choices(bc_console_client_choice *, uint32_t capacity, uint32_t *count);
BC_CLIENT_API bc_status bc_console_client_detect_media(bc_context *, bc_endpoint *, uint32_t timeout_ms, bc_detection_result *);
#define BC_CLIENT_ASSET_STARTUP 1u
#define BC_CLIENT_ASSET_ARCHIVE 2u
/* RAM-only copies of already fetched, provenance-checked resources. Borrow on
 * the I/O lane until destroy. Export still requires explicit user selection. */
BC_CLIENT_API bc_bytes bc_console_client_asset(const bc_console_client *, uint32_t kind);
/* Call start/poll/close on one I/O lane. Input enqueues independently of decode.
 * Execute submitted decode jobs in order on another lane and drain them before
 * close/destroy. Tile/ack access belongs exclusively to that decode lane. */
BC_CLIENT_API bc_status bc_console_client_create(const bc_console_client_options *, bc_console_client **);
BC_CLIENT_API bc_status bc_console_client_start(bc_console_client *);
BC_CLIENT_API bc_status bc_console_client_poll(bc_console_client *, uint32_t timeout_ms);
BC_CLIENT_API bc_status bc_console_client_input(bc_console_client *, const bc_console_input *);
BC_CLIENT_API bc_status bc_console_client_chord(bc_console_client *, const uint32_t *, uint32_t);
BC_CLIENT_API bc_status bc_console_client_tile(bc_console_client *, bc_display_tile *);
BC_CLIENT_API void bc_console_client_ack_display(bc_console_client *);
BC_CLIENT_API bc_status bc_console_client_info_get(const bc_console_client *, bc_console_client_info *);
BC_CLIENT_API bc_status bc_console_client_eject(bc_console_client *);
BC_CLIENT_API bc_status bc_console_client_close(bc_console_client *);
BC_CLIENT_API void bc_console_client_destroy(bc_console_client *);
/* Parent remains active on its I/O lane and outlives the child. */
BC_CLIENT_API bc_status bc_console_client_media_create(bc_console_client *, const bc_console_client_options *, bc_console_client **);
#ifdef __cplusplus
}
#endif
#endif

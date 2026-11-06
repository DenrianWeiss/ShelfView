#ifndef BCONTROL_MEGARAC_H
#define BCONTROL_MEGARAC_H
#include "bcontrol/kvm.h"
#include "bcontrol/console.h"
#include "bcontrol/service_profile.h"
#include "media_session.h"
#if defined(_WIN32)
# ifdef BC_MEGARAC_BUILD
#  define BC_MEGARAC_API __declspec(dllexport)
# else
#  define BC_MEGARAC_API __declspec(dllimport)
# endif
#else
# define BC_MEGARAC_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define BC_MEGARAC_KVM_JVIEWER 1u
#define BC_MEGARAC_KVM_JVIEWER_195 3u
#define BC_MEGARAC_KVM_H5VIEWER 2u
#define BC_MEGARAC_KVM_H5VIEWER_373 4u
#define BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION 5u
#define BC_MEGARAC_KVM_JVIEWER_IRMC 6u
#define BC_MEGARAC_IS_JVIEWER_373(kind) ((kind) == BC_MEGARAC_KVM_JVIEWER || (kind) == BC_MEGARAC_KVM_JVIEWER_IRMC)
#define BC_MEGARAC_IS_H5(kind) ((kind) == BC_MEGARAC_KVM_H5VIEWER || (kind) == BC_MEGARAC_KVM_H5VIEWER_373)
#define BC_MEGARAC_IS_JVIEWER_195(kind) ((kind) == BC_MEGARAC_KVM_JVIEWER_195 || (kind) == BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION)

#define BC_MEGARAC_OP_HID 1u
#define BC_MEGARAC_OP_PAUSE 4u
#define BC_MEGARAC_OP_REFRESH 5u
#define BC_MEGARAC_OP_RESUME 6u
#define BC_MEGARAC_OP_STOP 8u
#define BC_MEGARAC_OP_BLANK 9u
#define BC_MEGARAC_OP_VALIDATE 18u
#define BC_MEGARAC_OP_VALIDATE_RESPONSE 19u
#define BC_MEGARAC_OP_KEYBOARD_LEDS 20u
#define BC_MEGARAC_OP_WEB_SESSION 21u
#define BC_MEGARAC_OP_CONNECTION_ALLOWED 23u
#define BC_MEGARAC_OP_MEDIA_STATE 24u
#define BC_MEGARAC_OP_MEDIA_MODE 128u
#define BC_MEGARAC_OP_VIDEO_FRAGMENT 25u
#define BC_MEGARAC_OP_POWER_STATUS 34u
#define BC_MEGARAC_OP_KEEP_ALIVE 57u
#define BC_MEGARAC_OP_CONNECTION_COMPLETE 58u

#define BC_MEGARAC_IVTP_HEADER_SIZE 8u
#define BC_MEGARAC_JVIEWER_AUTH_SIZE 373u
#define BC_MEGARAC_JVIEWER_RECONNECT_SIZE 374u
#define BC_MEGARAC_H5VIEWER_AUTH_SIZE 438u
#define BC_MEGARAC_AST_HEADER_SIZE 86u
#define BC_MEGARAC_MAX_HOST 128u
#define BC_MEGARAC_MAX_TOKEN 256u
#define BC_MEGARAC_MAX_IP 64u

typedef struct {
    uint16_t type;
    uint16_t status;
    uint32_t length;
} bc_megarac_ivtp;

typedef struct {
    uint32_t struct_size;
    uint32_t kind;
    char host[BC_MEGARAC_MAX_HOST];
    char token[BC_MEGARAC_MAX_TOKEN];
    char cookie[BC_MEGARAC_MAX_TOKEN];
    char session[BC_MEGARAC_MAX_TOKEN];
    char client_ip[BC_MEGARAC_MAX_IP];
    char server_ip[BC_MEGARAC_MAX_IP];
    uint32_t port;
    uint32_t secure;
    uint32_t single_port;
} bc_megarac_kvm_info;

typedef struct {
    uint32_t struct_size;
    uint32_t width;
    uint32_t height;
    uint32_t source_width;
    uint32_t source_height;
    uint32_t compressed_size;
    uint32_t frame_number;
    uint32_t flags;
} bc_megarac_video_header;

#define BC_MEGARAC_VIDEO_RC4 1u
#define BC_MEGARAC_VIDEO_SOC 4u
#define BC_MEGARAC_VIDEO_420 2u
/* AST quantization selectors, as decoded by the assembler. */
#define BC_MEGARAC_VIDEO_JPEG_TABLE_SHIFT 8u
#define BC_MEGARAC_VIDEO_ADVANCE_TABLE_SHIFT 11u
#define BC_MEGARAC_VIDEO_YUV_TABLE_MAPPING (1u << 14)

typedef struct {
    uint32_t struct_size;
    uint32_t state;
    uint32_t received;
    uint8_t *buffer;
    uint32_t capacity;
    bc_megarac_video_header header;
} bc_megarac_assembler;

BC_MEGARAC_API bc_status bc_megarac_ivtp_encode(const bc_megarac_ivtp *, const uint8_t *payload, uint8_t *out, uint32_t capacity, uint32_t *written);
BC_MEGARAC_API bc_status bc_megarac_ivtp_decode(const uint8_t *data, uint32_t length, bc_megarac_ivtp *header, const uint8_t **payload, uint32_t *consumed);

BC_MEGARAC_API bc_status bc_megarac_parse_jnlp(const uint8_t *data, uint32_t length, bc_megarac_kvm_info *);
BC_MEGARAC_API bc_status bc_megarac_parse_h5_config(const uint8_t *data, uint32_t length, bc_megarac_kvm_info *);
BC_MEGARAC_API bc_status bc_megarac_jviewer_auth(const bc_megarac_kvm_info *, const char *client_ip, const char *username, const char *mac, uint8_t *out, uint32_t capacity);
BC_MEGARAC_API bc_status bc_megarac_jviewer_reconnect(const bc_megarac_kvm_info *, const char *client_ip, const char *username, const char *mac, uint8_t session_id, uint8_t *out, uint32_t capacity);
BC_MEGARAC_API bc_status bc_megarac_h5viewer_auth(const bc_megarac_kvm_info *, const char *client_ip, const char *username, const char *mac, uint8_t *out, uint32_t capacity);

BC_MEGARAC_API bc_status bc_megarac_soc_decode(const uint8_t *, uint32_t, uint8_t *, uint32_t, uint32_t *, uint32_t *);
typedef struct bc_megarac_soc_video bc_megarac_soc_video;
BC_MEGARAC_API bc_status bc_megarac_soc_video_create(bc_megarac_soc_video **);
BC_MEGARAC_API void bc_megarac_soc_video_destroy(bc_megarac_soc_video *);
BC_MEGARAC_API bc_status bc_megarac_soc_frame_size(const uint8_t *, uint32_t, uint32_t *, uint32_t *);
BC_MEGARAC_API bc_status bc_megarac_soc_video_decode(bc_megarac_soc_video *, const uint8_t *, uint32_t,
    uint8_t *, uint32_t, uint32_t *, uint32_t *);

BC_MEGARAC_API bc_status bc_megarac_hid_keyboard(uint32_t sequence, uint8_t modifiers, const uint8_t usages[6], uint8_t *out, uint32_t capacity, uint32_t *written);
BC_MEGARAC_API bc_status bc_megarac_hid_mouse(uint32_t sequence, uint8_t buttons, uint16_t x, uint16_t y, int8_t wheel, uint8_t *out, uint32_t capacity, uint32_t *written);
BC_MEGARAC_API bc_status bc_megarac_assembler_init(bc_megarac_assembler *, uint8_t *buffer, uint32_t capacity);
BC_MEGARAC_API bc_status bc_megarac_assembler_push(bc_megarac_assembler *, const uint8_t *fragment, uint32_t length);
BC_MEGARAC_API const bc_megarac_video_header *bc_megarac_assembler_frame(const bc_megarac_assembler *);

#define BC_MEGARAC_MEDIA_LEGACY_STATUS 1u
#define BC_MEGARAC_MEDIA_LEGACY_CONTROL 2u
#define BC_MEGARAC_MEDIA_HEADER28_CHECKSUM 4u
#define BC_MEGARAC_MEDIA_LEGACY_SCSI 8u

typedef struct {
    uint32_t struct_size, sequence, flags;
    uint8_t instance, device, protocol, direction;
    bc_bytes payload;
} bc_megarac_media_packet;

#define BC_MEGARAC_MEDIA_WEBSOCKET 128u
#define BC_MEGARAC_MEDIA_TOKEN_TYPE_PRESENT 1u
#define BC_MEGARAC_MEDIA_SECURE_PRESENT 2u
#define BC_MEGARAC_MEDIA_PORT_PRESENT 4u
#define BC_MEGARAC_MEDIA_DEVICES_PRESENT 8u
#define BC_MEGARAC_MEDIA_SINGLE_PORT_PRESENT 16u
#define BC_MEGARAC_MEDIA_TOKEN_TYPE_RESOURCE_DEFAULT 32u
#define BC_MEGARAC_MEDIA_SINGLE_PORT_RESOURCE_DEFAULT 64u
typedef struct {
    uint32_t struct_size, flags, token_type, port, secure, devices, single_port;
} bc_megarac_media_parameters;
/* Explicit JViewer startup inputs only, not a profile or handshake proof.
 * Missing token type remains absent, even when token_type is zero-initialized. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_media_parameters(const uint8_t *, uint32_t, bc_megarac_media_parameters *);
/* Resolve an omitted application main class using the same-origin JAR manifest. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_media_parameters_with_jar(const uint8_t *, uint32_t, bc_bytes, bc_megarac_media_parameters *);
/* Routing configuration for multi-port WEB-token or explicitly described H5
 * WebSocket media. Does not prove authentication or grant a verified profile. */
BC_MEGARAC_API int bc_megarac_media_parameters_transport_usable(const bc_megarac_media_parameters *);
BC_MEGARAC_API bc_status bc_megarac_h5_media_parameters(const uint8_t *, uint32_t, bc_megarac_media_parameters *);
#define BC_MEGARAC_TUNNEL_VIDEO 1u
#define BC_MEGARAC_TUNNEL_CD 2u
BC_MEGARAC_API bc_status bc_megarac_tunnel_request(const bc_megarac_kvm_info *, uint32_t service,
    uint8_t *, uint32_t, uint32_t *);
/* BC_BUSY means an incomplete HTTP response. The optional trailing NUL is not consumed. */
BC_MEGARAC_API bc_status bc_megarac_tunnel_status_line(const uint8_t *, uint32_t, uint32_t *);
BC_MEGARAC_API bc_status bc_megarac_tunnel_response(const uint8_t *, uint32_t, uint32_t *);
BC_MEGARAC_API bc_status bc_megarac_media_disconnect(uint8_t instance, uint8_t *, uint32_t, uint32_t *);
BC_MEGARAC_API bc_status bc_megarac_media_auth(bc_string token, uint8_t instance, uint8_t *out, uint32_t capacity, uint32_t *written);
/* Incoming IUSB evidence, independent of KVM. Sending an auth packet is not proof.
 * Recognized status success confirms authentication; SCSI/control only confirms format. */
BC_MEGARAC_API bc_status bc_megarac_media_discover(const uint8_t *, uint32_t,
    bc_service_profile *, bc_console_failure *);
BC_MEGARAC_API bc_status bc_megarac_media_packet_decode(const uint8_t *, uint32_t, bc_megarac_media_packet *);

typedef struct {
    uint32_t struct_size;
    void *userdata;
    uint64_t size;
    bc_status (*read)(void *userdata, uint64_t offset, uint32_t length, uint8_t *out);
} bc_megarac_cd_source;

BC_MEGARAC_API bc_status bc_megarac_cd_respond(const uint8_t *, uint32_t,
    const bc_megarac_cd_source *, uint8_t *, uint32_t, uint32_t *);

typedef struct bc_megarac_cd bc_megarac_cd;
#define BC_MEGARAC_CD_PRESENT 1u
#define BC_MEGARAC_CD_REMOVAL_PREVENTED 2u
#define BC_MEGARAC_CD_EVENT_PENDING 4u
typedef struct {
    uint32_t struct_size, flags;
    uint8_t sense_key, asc, ascq, reserved;
} bc_megarac_cd_info;
/* The source callback/userdata remain owned by the caller until destroy. */
BC_MEGARAC_API bc_status bc_megarac_cd_create(const bc_megarac_cd_source *, bc_megarac_cd **);
BC_MEGARAC_API void bc_megarac_cd_destroy(bc_megarac_cd *);
BC_MEGARAC_API bc_status bc_megarac_cd_info_get(const bc_megarac_cd *, bc_megarac_cd_info *);
BC_MEGARAC_API bc_status bc_megarac_cd_handle(bc_megarac_cd *, const uint8_t *, uint32_t,
    uint8_t *, uint32_t, uint32_t *);

/* Serialized, caller-owned transport callbacks. The source and callback userdata
 * must outlive the service. Destroy releases memory only; close sends disconnect. */
typedef struct {
    void *userdata;
    bc_status (*send)(void *, const uint8_t *, uint32_t);
    bc_status (*recv)(void *, uint8_t *, uint32_t, uint32_t *, uint32_t);
    uint64_t (*clock_ms)(void *);
} bc_megarac_media_io;
#define BC_MEGARAC_MEDIA_SEND_DISCONNECT 1u
#define BC_MEGARAC_MEDIA_TUNNEL_PREFIX 2u
#define BC_MEGARAC_MEDIA_AUTHENTICATED 1u
#define BC_MEGARAC_MEDIA_REMOVAL_UNCONFIRMED 2u
typedef struct {
    uint32_t struct_size, abi_version;
    const bc_megarac_cd_source *source;
    bc_string token;
    uint32_t flags, instance, authentication_timeout_ms;
} bc_megarac_media_service_options;
typedef struct {
    uint32_t struct_size, state, flags, instance;
    uint64_t packets, requests, bytes;
} bc_megarac_media_service_info;
typedef struct bc_megarac_media_service bc_megarac_media_service;
BC_MEGARAC_API bc_status bc_megarac_media_service_create(const bc_megarac_media_service_options *,
    const bc_megarac_media_io *, bc_megarac_media_service **);
BC_MEGARAC_API bc_status bc_megarac_media_service_start(bc_megarac_media_service *);
/* BC_TIMEOUT is a receive timeout until state becomes ERROR (authentication deadline). */
BC_MEGARAC_API bc_status bc_megarac_media_service_poll(bc_megarac_media_service *, uint32_t timeout_ms);
BC_MEGARAC_API bc_status bc_megarac_media_service_close(bc_megarac_media_service *);
BC_MEGARAC_API bc_status bc_megarac_media_service_info_get(const bc_megarac_media_service *, bc_megarac_media_service_info *);
BC_MEGARAC_API const bc_service_profile *bc_megarac_media_service_profile_get(const bc_megarac_media_service *);
BC_MEGARAC_API const bc_console_failure *bc_megarac_media_service_failure_get(const bc_megarac_media_service *);
BC_MEGARAC_API void bc_megarac_media_service_destroy(bc_megarac_media_service *);
BC_MEGARAC_API bc_status bc_megarac_media_wrap(bc_megarac_media_service *, bc_media_session **);

#define BC_MEGARAC_STATE_IDLE 0u
#define BC_MEGARAC_STATE_AUTH 1u
#define BC_MEGARAC_STATE_STREAMING 2u
#define BC_MEGARAC_STATE_CLOSED 3u
#define BC_MEGARAC_STATE_ERROR 4u
#define BC_MEGARAC_FRAME_READY 1u
#define BC_MEGARAC_BLANK 2u
#define BC_MEGARAC_KEYBOARD_AUTOBREAK 4u

typedef struct bc_megarac_session bc_megarac_session;

typedef struct {
    uint32_t struct_size;
    uint32_t kind;
    const bc_megarac_kvm_info *info;
    const char *client_ip;
    const char *username;
    const char *client_mac;
    uint8_t *frame_buffer;
    uint32_t frame_capacity;
} bc_megarac_session_options;

BC_MEGARAC_API bc_status bc_megarac_session_create(const bc_megarac_session_options *, bc_megarac_session **);
BC_MEGARAC_API bc_status bc_megarac_session_start(bc_megarac_session *);
BC_MEGARAC_API bc_status bc_megarac_session_feed(bc_megarac_session *, const uint8_t *, uint32_t);
BC_MEGARAC_API const bc_console_failure *bc_megarac_session_failure_get(const bc_megarac_session *);
BC_MEGARAC_API const bc_service_profile *bc_megarac_session_profile_get(const bc_megarac_session *);
/* Stops at a completed frame. Process and acknowledge it before feeding the unconsumed tail. */
BC_MEGARAC_API bc_status bc_megarac_session_feed_frame(bc_megarac_session *, const uint8_t *, uint32_t, uint32_t *consumed);
BC_MEGARAC_API bc_status bc_megarac_session_output(bc_megarac_session *, uint8_t *, uint32_t, uint32_t *);
#define BC_MEGARAC_KEYBOARD_DEFAULT 0u
#define BC_MEGARAC_KEYBOARD_REPORT 1u
#define BC_MEGARAC_KEYBOARD_AUTO_BREAK 2u
/* Configure before start, using bound viewer evidence or explicit caller selection. */
BC_MEGARAC_API bc_status bc_megarac_session_keyboard_mode(bc_megarac_session *, uint32_t mode);
BC_MEGARAC_API bc_status bc_megarac_session_keyboard(bc_megarac_session *, uint8_t modifiers, const uint8_t usages[6]);
/* Releases all keys and cancels client repeats; use on focus loss. */
BC_MEGARAC_API bc_status bc_megarac_session_keyboard_release(bc_megarac_session *);
/* Drive client key repeat and deferred modifier synchronization with monotonic milliseconds. */
BC_MEGARAC_API bc_status bc_megarac_session_tick(bc_megarac_session *, uint64_t now_ms);
BC_MEGARAC_API bc_status bc_megarac_session_mouse(bc_megarac_session *, uint8_t buttons, uint16_t x, uint16_t y, int8_t wheel);
BC_MEGARAC_API bc_status bc_megarac_session_keepalive(bc_megarac_session *);
BC_MEGARAC_API bc_status bc_megarac_session_media_state(bc_megarac_session *, uint8_t connected);
BC_MEGARAC_API bc_status bc_megarac_session_media_mode(bc_megarac_session *, uint8_t enabled);
/* A queued enable/attach may have reached the device. Disable/detach or local
 * teardown is not confirmation of remote removal. */
BC_MEGARAC_API uint32_t bc_megarac_session_media_removal_unconfirmed(const bc_megarac_session *);
BC_MEGARAC_API bc_status bc_megarac_session_close(bc_megarac_session *);
BC_MEGARAC_API uint32_t bc_megarac_session_state(const bc_megarac_session *);
BC_MEGARAC_API uint32_t bc_megarac_session_flags(const bc_megarac_session *);
BC_MEGARAC_API const bc_megarac_video_header *bc_megarac_session_frame(const bc_megarac_session *);
BC_MEGARAC_API const uint8_t *bc_megarac_session_pixels(const bc_megarac_session *);
BC_MEGARAC_API void bc_megarac_session_ack_frame(bc_megarac_session *);
BC_MEGARAC_API void bc_megarac_session_destroy(bc_megarac_session *);

#define BC_MEGARAC_HTTP_H5VIEWER 1u
#define BC_MEGARAC_HTTP_JVIEWER 2u
typedef struct bc_megarac_probe bc_megarac_probe;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    bc_string host;
    bc_string username;
    bc_string password;
    uint32_t timeout_ms;
    /* Eight random decimal digits for ExpressScope login; generated by the platform. */
    bc_string client_id;
} bc_megarac_probe_options;

typedef struct {
    uint32_t struct_size;
    bc_status status;
    uint32_t http_status;
    uint32_t kind;
    bc_megarac_kvm_info info;
    bc_string cookie;
    bc_string error_body;
    bc_status cleanup_status;
} bc_megarac_probe_result;

typedef void (*bc_megarac_probe_completion)(bc_megarac_probe *, const bc_megarac_probe_result *, void *);

BC_MEGARAC_API bc_status bc_megarac_probe_start(bc_endpoint *, const bc_megarac_probe_options *, bc_megarac_probe_completion, void *, bc_megarac_probe **);
BC_MEGARAC_API bc_status bc_inspur_kvm_probe_start(bc_endpoint *, const bc_megarac_probe_options *, bc_megarac_probe_completion, void *, bc_megarac_probe **);
BC_MEGARAC_API bc_status bc_inspur_rpc_kvm_probe_start(bc_endpoint *, const bc_megarac_probe_options *, bc_megarac_probe_completion, void *, bc_megarac_probe **);
/* Borrow the authenticated launch endpoint while the successful probe owns it. */
BC_MEGARAC_API bc_endpoint *bc_megarac_probe_endpoint(const bc_megarac_probe *);
/* No page-brand classification. NULL profile discovers H5 then legacy startup
 * metadata; unknown legacy auth layouts remain variant zero, never guessed. */
BC_MEGARAC_API bc_status bc_megarac_probe_start_discovery(bc_endpoint *, const bc_megarac_probe_options *,
    const bc_service_profile *, bc_megarac_probe_completion, void *, bc_megarac_probe **);
#define BC_MEGARAC_LOGIN_LEGACY_RPC 1u
#define BC_MEGARAC_LOGIN_H5_SESSION 2u
#define BC_MEGARAC_LOGIN_CLIENT_ID 1u
#define BC_MEGARAC_LOGIN_TRANSPORT_TYPE 2u
#define BC_MEGARAC_LOGIN_CSRF_COOKIE 4u
typedef struct { uint32_t struct_size, kind, flags; } bc_megarac_login_contract;
/* Explicit, previously confirmed web contract. No brand identification or login
 * fallback. These flags never select a KVM layout; legacy startup remains
 * variant zero until independent resource analysis. A public HINT alone is not
 * permission to call this entry point. */
BC_MEGARAC_API bc_status bc_megarac_probe_start_with_login(bc_endpoint *, const bc_megarac_probe_options *,
    const bc_megarac_login_contract *, bc_megarac_probe_completion, void *, bc_megarac_probe **);
/* The independently selected wire profile never changes the HTTP contract or
 * grants a layout when NULL. Explicit H5 requires flags0 and never falls back. */
BC_MEGARAC_API bc_status bc_megarac_probe_start_with_login_profile(bc_endpoint *, const bc_megarac_probe_options *,
    const bc_megarac_login_contract *, const bc_service_profile *, bc_megarac_probe_completion, void *, bc_megarac_probe **);
/* Borrowed successful JNLP request while this probe owns its web session.
 * Contains secrets; retain before asynchronous use, never log or persist. */
BC_MEGARAC_API bc_request *bc_megarac_probe_launch_request(const bc_megarac_probe *);
/* Reads only the current owned JNLP or H5 configuration; no additional I/O. */
BC_MEGARAC_API uint32_t bc_megarac_probe_keyboard_mode(const bc_megarac_probe *);
BC_MEGARAC_API bc_status bc_megarac_probe_media_parameters(const bc_megarac_probe *, bc_megarac_media_parameters *);

/* Logs out only the HTTP session created by this probe; call after KVM/media close. */
BC_MEGARAC_API bc_status bc_megarac_probe_logout(bc_megarac_probe *, bc_megarac_probe_completion, void *);
BC_MEGARAC_API const bc_megarac_probe_result *bc_megarac_probe_result_get(const bc_megarac_probe *);
BC_MEGARAC_API const bc_console_failure *bc_megarac_probe_failure_get(const bc_megarac_probe *);
BC_MEGARAC_API const bc_service_profile *bc_megarac_probe_profile_get(const bc_megarac_probe *);
BC_MEGARAC_API bc_status bc_megarac_discover_h5_config(const uint8_t *, uint32_t,
    bc_megarac_kvm_info *, bc_service_profile *);
BC_MEGARAC_API bc_status bc_megarac_discover_jnlp(const uint8_t *, uint32_t,
    bc_megarac_kvm_info *, bc_service_profile *);
/* Read-only ClassFile evidence; does not execute Java or prove authentication.
 * Caller binds both classes to the same current, same-origin startup artifact. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_evidence(const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, bc_service_profile *);
/* Bounded in-memory ZIP/JAR extraction; same HINT-only semantics. Requires zlib. */
/* Initializer metadata only, not whole-program or media protocol evidence. */
/* Constructor-path metadata only: does not prove wire serialization/auth or permit media. */
/* Field serialization/checksum metadata only; no byte-order or authentication grant. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_media_serialization_hint(const uint8_t *, uint32_t, bc_service_profile *);
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_media_header_hint(const uint8_t *, uint32_t, bc_service_profile *);
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_token_default(const uint8_t *, uint32_t, uint32_t *);
/* Combined header/default-constructor/serialization metadata from the header
 * and its parent. Authentication, byte order and permission are not established. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_media_hint(const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, bc_service_profile *);
/* Buffer alias/order setup metadata only; later connection/auth paths remain unverified. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_media_order_hint(const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, bc_service_profile *);
/* WEB/SSI branch and authentication construction metadata only; no proof of
 * runtime token-type propagation, packet serialization or transport delivery. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_media_auth_hint(const uint8_t *, uint32_t, bc_service_profile *);
/* Entry argument/connection field/getter relationship metadata, not a proof of
 * all runtime mutations or later authentication/transport behavior. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_media_runtime_hint(const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, bc_service_profile *);
/* SCSI prebuffered branch and output-array/socket relationship metadata only;
 * constructor/read state and successful network delivery remain unverified. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_media_send_hint(const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, bc_service_profile *);
/* Canonical-signature header read and SCSI constructor input-state metadata.
 * Does not grant permission or prove arbitrary runtime/network behavior. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_media_state_hint(const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, const uint8_t *, uint32_t, bc_service_profile *);
/* Explicit false initializer plus matching getter; not a media profile. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_class_single_port_default(const uint8_t *, uint32_t, uint32_t *);
BC_MEGARAC_API bc_status bc_megarac_jviewer_jar_single_port_default(const uint8_t *, uint32_t, uint32_t *);
/* Same-archive media metadata; duplicate/overridden target classes stop analysis. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_jar_media_hint(const uint8_t *, uint32_t, bc_service_profile *);
BC_MEGARAC_API bc_status bc_megarac_jviewer_jar_token_default(const uint8_t *, uint32_t, uint32_t *);
BC_MEGARAC_API bc_status bc_megarac_jviewer_jar_evidence(const uint8_t *, uint32_t, bc_service_profile *);
/* Resolve a declared, unqualified main/sole JAR to a same-origin safe path.
 * origin is the original HTTPS endpoint; launch_path excludes its query. */
BC_MEGARAC_API bc_status bc_megarac_jviewer_resource_path(const uint8_t *, uint32_t,
    bc_string origin, bc_string launch_path, char *, uint32_t capacity);
BC_MEGARAC_API void bc_megarac_probe_release(bc_megarac_probe *);

typedef struct bc_megarac_video bc_megarac_video;
BC_MEGARAC_API bc_status bc_megarac_video_create(bc_megarac_video **);
BC_MEGARAC_API bc_status bc_megarac_video_decode(bc_megarac_video *, const uint8_t *frame, uint32_t length,
    uint8_t *rgba, uint32_t capacity, uint32_t *width, uint32_t *height);
/* Decode the AST payload exposed by the session without rebuilding a wire header. */
BC_MEGARAC_API bc_status bc_megarac_video_decode_payload(bc_megarac_video *, const bc_megarac_video_header *,
    const uint8_t *, uint32_t length, uint8_t *rgba, uint32_t capacity, uint32_t *width, uint32_t *height);
BC_MEGARAC_API void bc_megarac_video_destroy(bc_megarac_video *);
#ifdef __cplusplus
}
#endif
#endif

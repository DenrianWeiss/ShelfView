#ifndef BCONTROL_HUAWEI_KVM_H
#define BCONTROL_HUAWEI_KVM_H
#include "bcontrol/bcontrol.h"
#include "bcontrol/console.h"
#include "media_session.h"
#if defined(_WIN32)
# ifdef BC_HUAWEI_BUILD
#  define BC_HUAWEI_API __declspec(dllexport)
# else
#  define BC_HUAWEI_API __declspec(dllimport)
# endif
#else
# define BC_HUAWEI_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define BC_HUAWEI_HOST_MAX 64u
#define BC_HUAWEI_VERIFY_MAX 16u
#define BC_HUAWEI_VERIFY_EXT_MAX 36u
#define BC_HUAWEI_DECRYKEY_MAX 68u
#define BC_HUAWEI_TITLE_MAX 160u
#define BC_HUAWEI_ERROR_MAX 200u
#define BC_HUAWEI_KEY_MAX 16u
#define BC_HUAWEI_AUTH_MAX 24u
#define BC_HUAWEI_RECONNECT_MAX 128u
#define BC_HUAWEI_TILE 64u
#define BC_HUAWEI_FRAGMENT 220u
#define BC_HUAWEI_MAX_DIMENSION 4096u

/* ---------------------------------------------------------------------------------------------
 * Startup parameters (JNLP) and low-level packet helpers.
 * ------------------------------------------------------------------------------------------- */

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    char host[BC_HUAWEI_HOST_MAX];
    uint16_t port;
    uint16_t vmm_port;
    uint32_t privilege;
    uint32_t compress;
    char verify_value[BC_HUAWEI_VERIFY_MAX];
    char verify_value_ext[BC_HUAWEI_VERIFY_EXT_MAX];
    char decrykey[BC_HUAWEI_DECRYKEY_MAX];
    char title[BC_HUAWEI_TITLE_MAX];
    uint32_t reserved;
} bc_huawei_kvm_params;

/* Parses the private KVM startup JNLP returned by Redfish ExportKvmStartupFile.
 * The caller performs the HTTP exchange; this function is dependency-free XML scanning. */
BC_HUAWEI_API bc_status bc_huawei_kvm_params_from_jnlp(const uint8_t *data, uint64_t length,
    bc_huawei_kvm_params *params, char *error, uint32_t error_capacity);
/* Strict in-memory discovery. Output host is metadata, not a redirect authority.
 * vmmPort is not independent evidence that local media is supported. */
BC_HUAWEI_API bc_status bc_huawei_kvm_discover_jnlp(const uint8_t *data, uint32_t length,
    bc_huawei_kvm_params *params, bc_service_profile *profile);

typedef struct {
    uint32_t hmac;       /* 2 = SHA-1, 3 = SHA-256 (iBMC identifiers) */
    uint32_t iterations;
    uint8_t auth[BC_HUAWEI_AUTH_MAX];
    uint8_t key[BC_HUAWEI_KEY_MAX];
    uint8_t key_ext[BC_HUAWEI_KEY_MAX];
    uint8_t iv[BC_HUAWEI_KEY_MAX];
    uint8_t reconnect[BC_HUAWEI_RECONNECT_MAX];
    uint32_t flags;
} bc_huawei_kvm_keys;

#define BC_HUAWEI_KEY_AUTH 1u
#define BC_HUAWEI_KEY_CONTENT 2u
#define BC_HUAWEI_KEY_RECONNECT 4u

/* PBKDF2(verifyValueExt or verifyValue, decrykey[16..32], 24, PRF, iterations) with the
 * CryptoJS four-byte group reversal. */
BC_HUAWEI_API bc_status bc_huawei_kvm_auth_code(const bc_huawei_kvm_params *params, uint32_t hmac,
    uint32_t iterations, uint8_t out[BC_HUAWEI_AUTH_MAX]);
/* Content keys from a 48-byte key negotiation block (AES-CBC decrypt, PBKDF2, group reversal). */
BC_HUAWEI_API bc_status bc_huawei_kvm_content_keys(const uint8_t *negotiation, uint32_t length,
    const bc_huawei_kvm_params *params, uint32_t hmac, uint32_t iterations, bc_huawei_kvm_keys *keys);

/* Client packet builders; `out` receives a complete 0xFE 0xF6 framed packet. */
BC_HUAWEI_API bc_status bc_huawei_kvm_get_suite_packet(const bc_huawei_kvm_params *params,
    uint8_t *out, uint32_t capacity, uint32_t *written);
BC_HUAWEI_API bc_status bc_huawei_kvm_set_suite_packet(const bc_huawei_kvm_params *params,
    uint32_t hmac, uint32_t iterations, uint8_t *out, uint32_t capacity, uint32_t *written);
BC_HUAWEI_API bc_status bc_huawei_kvm_connect_packet(const bc_huawei_kvm_params *params,
    const uint8_t auth[BC_HUAWEI_AUTH_MAX], const uint8_t *reconnect, uint32_t reconnect_length,
    uint8_t *out, uint32_t capacity, uint32_t *written);
BC_HUAWEI_API bc_status bc_huawei_kvm_heartbeat_packet(const bc_huawei_kvm_params *params,
    uint8_t *out, uint32_t capacity, uint32_t *written);
/* Input packet: `command` is 0x03 (keyboard) or 0x05 (mouse), `payload` the HID report. */
BC_HUAWEI_API bc_status bc_huawei_kvm_input_packet(const bc_huawei_kvm_params *params,
    const bc_huawei_kvm_keys *keys, uint32_t command, const uint8_t *payload, uint32_t length,
    uint8_t *out, uint32_t capacity, uint32_t *written);
BC_HUAWEI_API bc_status bc_huawei_kvm_mouse_mode_packet(const bc_huawei_kvm_params *params,
    uint32_t absolute, uint8_t *out, uint32_t capacity, uint32_t *written);
/* X11 keysym to USB HID usage mapping; returns 0 when unsupported. */
BC_HUAWEI_API uint32_t bc_huawei_kvm_keysym_to_usage(uint32_t keysym, uint8_t *modifiers);
/* Video helpers: decode one 64x64 JPEG tile (only the entropy-coded scan is provided) and compose
 * a full tile stream into caller-provided RGBA memory. `quantization` is the frame quality byte. */
BC_HUAWEI_API bc_status bc_huawei_kvm_video_tile(const uint8_t *scan, uint32_t length, uint32_t quantization,
    uint8_t *rgba, uint32_t capacity);
BC_HUAWEI_API bc_status bc_huawei_kvm_video_render(const uint8_t *blocks, uint32_t length, uint32_t width,
    uint32_t height, uint32_t quantization, uint8_t *frame, uint32_t capacity);


/* ---------------------------------------------------------------------------------------------
 * Byte transport abstraction. The core library performs no socket, TLS or platform calls.
 * ------------------------------------------------------------------------------------------- */

typedef struct {
    void *user;
    bc_status (*send)(void *user, const uint8_t *data, uint32_t length);
    bc_status (*recv)(void *user, uint8_t *data, uint32_t capacity, uint32_t *received, uint32_t timeout_ms);
} bc_huawei_io;

typedef struct {
    uint32_t struct_size;
    uint32_t state;      /* BC_HUAWEI_VMM_STATE_* */
    uint32_t port;
    uint32_t flags;      /* BC_HUAWEI_VMM_FLAG_ENCRYPTED when the device wants encrypted data */
    uint8_t auth[BC_HUAWEI_AUTH_MAX];
    uint8_t key[BC_HUAWEI_KEY_MAX];
    uint8_t iv[BC_HUAWEI_KEY_MAX];
    uint32_t reserved;
} bc_huawei_vmm_info;

#define BC_HUAWEI_VMM_STATE_DISABLED 0u
#define BC_HUAWEI_VMM_STATE_CONNECTING 1u
#define BC_HUAWEI_VMM_STATE_ENABLED 2u
#define BC_HUAWEI_VMM_FLAG_ENCRYPTED 1u

/* ---------------------------------------------------------------------------------------------
 * KVM session (video, keyboard, mouse). No power, reset or media-write commands exist here.
 * ------------------------------------------------------------------------------------------- */

typedef struct bc_huawei_kvm_session bc_huawei_kvm_session;
typedef struct bc_huawei_video_decoder bc_huawei_video_decoder;
/* Borrowed blocks are valid only during the callback. Copy before returning
 * for asynchronous decoding; preserve order because blocks may be deltas. */
typedef bc_status (*bc_huawei_video_sink)(void *user, const uint8_t *blocks, uint32_t length,
    uint32_t width, uint32_t height, uint32_t quantization, uint32_t sequence, uint32_t flags);
/* Set only before start. NULL retains synchronous decoding for legacy callers. */
BC_HUAWEI_API bc_status bc_huawei_kvm_session_set_video_sink(bc_huawei_kvm_session *, bc_huawei_video_sink, void *user);
BC_HUAWEI_API bc_status bc_huawei_video_decoder_create(uint8_t *frame, uint32_t capacity, bc_huawei_video_decoder **);
BC_HUAWEI_API bc_status bc_huawei_video_decoder_draw(bc_huawei_video_decoder *, const uint8_t *blocks,
    uint32_t length, uint32_t width, uint32_t height, uint32_t quantization);
BC_HUAWEI_API void bc_huawei_video_decoder_destroy(bc_huawei_video_decoder *);

/* Borrowed protocol evidence; independent of the current connection state. */
BC_HUAWEI_API const bc_service_profile *bc_huawei_kvm_session_profile_get(const bc_huawei_kvm_session *session);
BC_HUAWEI_API const bc_console_failure *bc_huawei_kvm_session_failure_get(const bc_huawei_kvm_session *session);

#define BC_HUAWEI_KVM_STATE_CREATED 0u
#define BC_HUAWEI_KVM_STATE_CONNECTING 1u
#define BC_HUAWEI_KVM_STATE_STREAMING 2u
#define BC_HUAWEI_KVM_STATE_CLOSED 3u
#define BC_HUAWEI_KVM_STATE_ERROR 4u

#define BC_HUAWEI_FRAME_READY 1u
#define BC_HUAWEI_FRAME_KEY 2u

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t handshake_timeout_ms;
    uint32_t heartbeat_interval_ms;
    uint8_t *frame_buffer;
    uint32_t frame_capacity;
    /* Optional monotonic clock in milliseconds; required for exact heartbeat timing. */
    uint64_t (*clock)(void *user);
    void *clock_user;
    uint32_t flags;
    uint32_t reserved;
} bc_huawei_kvm_options;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t flags;
    uint32_t sequence;
    uint32_t quantization;
    const uint8_t *pixels;
    uint32_t pixel_bytes;
} bc_huawei_kvm_frame;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t received_bytes;
    uint32_t image_packets;
    uint32_t decoded_frames;
    uint32_t heartbeats;
    uint32_t dropped_frames;
} bc_huawei_kvm_stats;

/* Creates a session. `io` and the frame buffer remain owned by the caller. */
BC_HUAWEI_API bc_status bc_huawei_kvm_session_create(const bc_huawei_kvm_params *params,
    const bc_huawei_io *io, const bc_huawei_kvm_options *options, bc_huawei_kvm_session **session);
/* Blocking GetSuite/SetSuite/Connect/key-negotiation handshake; returns when keys are ready. */
BC_HUAWEI_API bc_status bc_huawei_kvm_session_start(bc_huawei_kvm_session *session);
/* One receive step: reads from the io, decodes video, sends heartbeats when due. */
BC_HUAWEI_API bc_status bc_huawei_kvm_session_poll(bc_huawei_kvm_session *session, uint32_t timeout_ms);
/* Latest decoded frame, valid until the next poll/ack. */
BC_HUAWEI_API bc_status bc_huawei_kvm_session_frame(bc_huawei_kvm_session *session, bc_huawei_kvm_frame *frame);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_ack_frame(bc_huawei_kvm_session *session);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_key(bc_huawei_kvm_session *session, uint32_t keysym, uint32_t down);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_key_usage(bc_huawei_kvm_session *session, uint8_t usage,
    uint8_t modifiers, uint32_t down);
/* Absolute pointer in framebuffer pixels of the most recent frame; the core scales to the iBMC
 * 0...3000 device range. Before the first frame the values are treated as device units. */
BC_HUAWEI_API bc_status bc_huawei_kvm_session_pointer(bc_huawei_kvm_session *session, uint16_t x, uint16_t y,
    uint8_t buttons);
/* Absolute pointer using the device's own 0...3000 range. */
BC_HUAWEI_API bc_status bc_huawei_kvm_session_pointer_device(bc_huawei_kvm_session *session, uint16_t x,
    uint16_t y, uint8_t buttons);
/* Converts one framebuffer axis position to the device's 0...3000 absolute range. */
BC_HUAWEI_API uint32_t bc_huawei_kvm_pointer_scale(uint32_t pixel, uint32_t extent);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_pointer_delta(bc_huawei_kvm_session *session, int32_t dx,
    int32_t dy, uint8_t buttons);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_mouse_mode(bc_huawei_kvm_session *session, uint32_t absolute);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_state(const bc_huawei_kvm_session *session, uint32_t *state);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_stats(const bc_huawei_kvm_session *session, bc_huawei_kvm_stats *stats);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_error(const bc_huawei_kvm_session *session, char *out,
    uint32_t capacity);
/* Requests the VMM (virtual media) credentials over the KVM channel; results are collected by
 * session_poll and published through bc_huawei_kvm_session_vmm_info. */
BC_HUAWEI_API bc_status bc_huawei_kvm_session_vmm_request(bc_huawei_kvm_session *session);
BC_HUAWEI_API bc_status bc_huawei_kvm_session_vmm_info(const bc_huawei_kvm_session *session,
    bc_huawei_vmm_info *info);
BC_HUAWEI_API void bc_huawei_kvm_session_destroy(bc_huawei_kvm_session *session);

/* ---------------------------------------------------------------------------------------------
 * VMM virtual media: read-only CD-ROM (device type 2). No write CDBs are accepted.
 * ------------------------------------------------------------------------------------------- */

#define BC_HUAWEI_MEDIA_STATE_CREATED 0u
#define BC_HUAWEI_MEDIA_STATE_CONNECTING 1u
#define BC_HUAWEI_MEDIA_STATE_ESTABLISHED 2u
#define BC_HUAWEI_MEDIA_STATE_CLOSED 3u
#define BC_HUAWEI_MEDIA_STATE_ERROR 4u

typedef struct {
    uint32_t struct_size;
    void *userdata;
    uint64_t size;
    /* Must only read from the image; the core never issues writes. */
    bc_status (*read)(void *userdata, uint64_t offset, uint32_t length, uint8_t *out);
} bc_huawei_vmm_source;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    const bc_huawei_vmm_info *info;
    const bc_huawei_vmm_source *source;
    uint32_t timeout_ms;
    uint32_t heartbeat_interval_ms;
    uint64_t (*clock)(void *user);
    void *clock_user;
} bc_huawei_media_options;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t bytes_read;
    uint32_t commands;
    uint32_t heartbeats;
    uint32_t sense_key;
    uint8_t asc;
    uint8_t ascq;
    uint8_t reserved[2];
} bc_huawei_media_statistics;

typedef struct bc_huawei_media bc_huawei_media;
BC_HUAWEI_API const bc_service_profile *bc_huawei_media_profile_get(const bc_huawei_media *media);

/* Creates a read-only CD-ROM media session. The io must already be connected to the VMM
 * websocket endpoint (wss://<host>:<vmm_info.port>/websocket). */
BC_HUAWEI_API bc_status bc_huawei_media_create(const bc_huawei_media_options *options,
    const bc_huawei_io *io, bc_huawei_media **media);
/* Registers with the VMM service and opens the CD-ROM device (SFF/SCSI). Blocking. */
BC_HUAWEI_API bc_status bc_huawei_media_connect(bc_huawei_media *media);
/* Serves one batch of SCSI commands, sends data-in replies and heartbeats. */
BC_HUAWEI_API bc_status bc_huawei_media_poll(bc_huawei_media *media, uint32_t timeout_ms);
/* Sends a close request; CLOSED is local lifecycle state, not confirmed removal.
 * The io stays owned by the caller; a send failure is returned. */
BC_HUAWEI_API bc_status bc_huawei_media_close(bc_huawei_media *media);
/* True after a device-create attempt; local close/destroy is not device confirmation. */
BC_HUAWEI_API uint32_t bc_huawei_media_removal_unconfirmed(const bc_huawei_media *media);
BC_HUAWEI_API bc_status bc_huawei_media_state(const bc_huawei_media *media, uint32_t *state);
BC_HUAWEI_API bc_status bc_huawei_media_stats(const bc_huawei_media *media, bc_huawei_media_statistics *stats);
BC_HUAWEI_API bc_status bc_huawei_media_error(const bc_huawei_media *media, char *out, uint32_t capacity);
BC_HUAWEI_API void bc_huawei_media_destroy(bc_huawei_media *media);
BC_HUAWEI_API bc_status bc_huawei_media_wrap(bc_huawei_media *, bc_media_session **);

#ifdef __cplusplus
}
#endif
#endif

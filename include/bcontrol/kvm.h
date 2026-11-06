#ifndef BCONTROL_KVM_H
#define BCONTROL_KVM_H
#include "bcontrol.h"
#if defined(_WIN32)
# ifdef BC_KVM_BUILD
#  define BC_KVM_API __declspec(dllexport)
# else
#  define BC_KVM_API __declspec(dllimport)
# endif
#else
# define BC_KVM_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define BC_KVM_DEFAULT_MAX_WIDTH 1920u
#define BC_KVM_DEFAULT_MAX_HEIGHT 1200u
#define BC_KVM_MAX_NAME 1024u
#define BC_KVM_KEY_EVENT_SIZE 8u
#define BC_KVM_POINTER_EVENT_SIZE 6u

#define BC_KVM_VENDOR_UNKNOWN 0u
#define BC_KVM_VENDOR_GENERIC 1u
#define BC_KVM_VENDOR_OPENBMC 2u
#define BC_KVM_VENDOR_MEGARAC 3u
#define BC_KVM_VENDOR_ILO 4u
#define BC_KVM_VENDOR_IDRAC 5u
#define BC_KVM_VENDOR_IBMC 6u
#define BC_KVM_VENDOR_ILOM 7u
#define BC_KVM_VENDOR_SUPERMICRO 8u
#define BC_KVM_VENDOR_AVOCENT 9u
#define BC_KVM_CONSOLE_RFB 1u
#define BC_KVM_CONSOLE_WS_RFB 2u
#define BC_KVM_CONSOLE_JVNL 4u
#define BC_KVM_CONSOLE_HTML5 8u
#define BC_KVM_DETECTION_INFERRED 1u

typedef struct {
    uint32_t struct_size;
    uint32_t vendor;
    uint32_t protocol;
    uint32_t flags;
} bc_kvm_detection;

#define BC_KVM_READY 1u
#define BC_KVM_FRAME_READY 2u
#define BC_KVM_DESKTOP_RESIZED 4u

typedef struct bc_kvm bc_kvm;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t max_width;
    uint32_t max_height;
    uint32_t reserved;
    /* NULL with zero capacity lets the decoder allocate as dimensions arrive.
     * In this mode, zero limits use the decoder's built-in safety limits. */
    uint8_t *framebuffer;
    uint64_t framebuffer_capacity;
} bc_kvm_options;

typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t name_length;
    bc_string name;
    const uint8_t *pixels;
} bc_kvm_frame;

/* Optional vendor message parser. consumed=0/written=0 requests more bytes.
 * Invoked only at RFB message boundaries, never inside framebuffer pixels.
 * The caller owns userdata until the decoder is destroyed. */
typedef bc_status (*bc_kvm_extension_handler)(void *userdata, const uint8_t *data,
    uint32_t length, uint32_t *consumed, uint8_t *output, uint32_t capacity, uint32_t *written);
BC_KVM_API bc_status bc_kvm_set_extension_handler(bc_kvm *, uint8_t message_type,
    bc_kvm_extension_handler, void *userdata);

BC_KVM_API int bc_kvm_extension_boundary(const bc_kvm *);
/* 1 once the RFB handshake completed and client messages may be sent. */
BC_KVM_API int bc_kvm_handshake_complete(const bc_kvm *);

/* Push parser: feed server bytes, drain client bytes with bc_kvm_output. */
BC_KVM_API bc_status bc_kvm_create(const bc_kvm_options *, bc_kvm **);
BC_KVM_API bc_status bc_kvm_feed(bc_kvm *, const uint8_t *data, uint32_t length);
BC_KVM_API bc_status bc_kvm_output(bc_kvm *, uint8_t *data, uint32_t capacity, uint32_t *written);
/* Decoder-owned pixels may move on the next feed. */
BC_KVM_API const bc_kvm_frame *bc_kvm_frame_get(const bc_kvm *);
BC_KVM_API void bc_kvm_ack_frame(bc_kvm *);
/* Classify a console descriptor such as JNLP or HTML5 bootstrap content. */
BC_KVM_API bc_status bc_kvm_classify_console(const uint8_t *, uint32_t length, bc_kvm_detection *);
BC_KVM_API const char *bc_kvm_vendor_name(uint32_t vendor);
BC_KVM_API const char *bc_kvm_console_name(uint32_t protocol);
/* Stateless encoders for an independently scheduled input stream. The owner
 * gates on handshake readiness and serializes transport writes. */
BC_KVM_API bc_status bc_kvm_key_encode(int down, uint32_t keysym, uint8_t *out, uint32_t capacity);
BC_KVM_API bc_status bc_kvm_pointer_encode(uint8_t buttons, uint16_t x, uint16_t y,
    uint32_t width, uint32_t height, uint8_t *out, uint32_t capacity);
BC_KVM_API bc_status bc_kvm_key_event(bc_kvm *, int down, uint32_t keysym);
BC_KVM_API bc_status bc_kvm_pointer_event(bc_kvm *, uint8_t buttons, uint16_t x, uint16_t y);
BC_KVM_API bc_status bc_kvm_close(bc_kvm *);
BC_KVM_API void bc_kvm_destroy(bc_kvm *);
#ifdef __cplusplus
}
#endif
#endif

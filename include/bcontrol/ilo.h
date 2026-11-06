#ifndef BCONTROL_ILO_H
#define BCONTROL_ILO_H
#include "kvm.h"
#if defined(_WIN32)
# ifdef BC_ILO_BUILD
#  define BC_ILO_API __declspec(dllexport)
# else
#  define BC_ILO_API __declspec(dllimport)
# endif
#else
# define BC_ILO_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Root metadata hint only; login and console handshake remain separate gates. */
BC_ILO_API bc_status bc_ilo_discover_generation(const uint8_t *, uint32_t, uint32_t *);
#define BC_ILO_VIDEO_CHANNEL 0u
#define BC_ILO_COMMAND_CHANNEL 1u
typedef struct bc_ilo_kvm bc_ilo_kvm;
typedef struct bc_ilo_input bc_ilo_input;
/* Independent input state, owned by one ordered input consumer. The owner
 * gates on handshake readiness and serializes each 10-byte transport write. */
BC_ILO_API bc_status bc_ilo_input_create(bc_ilo_input **);
BC_ILO_API bc_status bc_ilo_keyboard_encode(const uint8_t hid[8], uint8_t *out, uint32_t capacity);
BC_ILO_API bc_status bc_ilo_input_key(bc_ilo_input *, uint32_t keysym, int down,
    uint8_t *out, uint32_t capacity);
BC_ILO_API bc_status bc_ilo_input_pointer(bc_ilo_input *, uint16_t x, uint16_t y,
    uint32_t width, uint32_t height, uint8_t buttons, int8_t wheel,
    uint8_t *out, uint32_t capacity);
BC_ILO_API void bc_ilo_input_destroy(bc_ilo_input *);
/* iLO 5 only. Transport owns both WebSockets and the Redfish session. All calls
 * are serialized. Output contains secrets until the initial handshake drains. */
BC_ILO_API bc_status bc_ilo_kvm_create(uint32_t generation, bc_string token,
    uint32_t max_width, uint32_t max_height, bc_ilo_kvm **);
BC_ILO_API bc_status bc_ilo_kvm_feed(bc_ilo_kvm *, uint32_t channel, const uint8_t *, uint32_t);
/* Returns one binary WebSocket message, or written=0. Drain each channel after feed. */
BC_ILO_API bc_status bc_ilo_kvm_output(bc_ilo_kvm *, uint32_t channel, uint8_t *, uint32_t, uint32_t *written);
BC_ILO_API int bc_ilo_kvm_ready(const bc_ilo_kvm *);
BC_ILO_API const bc_kvm_frame *bc_ilo_kvm_frame(const bc_ilo_kvm *);
BC_ILO_API void bc_ilo_kvm_ack_frame(bc_ilo_kvm *);
BC_ILO_API bc_status bc_ilo_kvm_keyboard(bc_ilo_kvm *, const uint8_t hid[8]);
/* Stateful US-layout keysym input; release all keys with keysym=0, down=0. */
BC_ILO_API bc_status bc_ilo_kvm_key_event(bc_ilo_kvm *, uint32_t keysym, int down);
BC_ILO_API bc_status bc_ilo_kvm_pointer(bc_ilo_kvm *, uint16_t x, uint16_t y,
    int8_t dx, int8_t dy, uint8_t buttons, int8_t wheel);
/* Frame pixel coordinates; buttons use USB HID left=1, right=2, middle=4. */
BC_ILO_API bc_status bc_ilo_kvm_pointer_event(bc_ilo_kvm *, uint16_t x, uint16_t y,
    uint8_t buttons, int8_t wheel);
BC_ILO_API bc_status bc_ilo_kvm_refresh(bc_ilo_kvm *);
BC_ILO_API void bc_ilo_kvm_destroy(bc_ilo_kvm *);
#ifdef __cplusplus
}
#endif
#endif

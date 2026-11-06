#ifndef BCONTROL_KEYBOARD_H
#define BCONTROL_KEYBOARD_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
/* US-layout X11 keysym to USB HID usage; 0 means unsupported. */
BC_API uint32_t bc_keyboard_keysym_to_usage(uint32_t keysym, uint8_t *modifiers);
/* Zero-initialize pressed once. Reports are USB HID modifier/reserved/six usages.
 * Unsupported input or overflow leaves both state and output unchanged. */
BC_API bc_status bc_keyboard_report(uint32_t pressed[32], uint32_t keysym, int down, uint8_t out[8]);
#ifdef __cplusplus
}
#endif
#endif

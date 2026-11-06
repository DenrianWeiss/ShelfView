#ifndef BCONTROL_IDRAC_SESSION_H
#define BCONTROL_IDRAC_SESSION_H
#include "idrac_kvm.h"
#include "console_session.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Called on the input lane. The platform publishes LED replies independently
 * from decoder ownership; this callback must not read a concurrently fed decoder. */
typedef uint8_t (*bc_idrac_led_snapshot)(void *);
/* Owns the decoder; options->framebuffer and emit/LED callback state remain
 * borrowed and must outlive the session. The secondary key is copied. */
BC_IDRAC_API bc_status bc_idrac_session_create(const bc_kvm_options *, bc_string secondary_key,
    bc_console_emit, bc_idrac_led_snapshot, void *, bc_console_session **);
BC_IDRAC_API bc_status bc_idrac_session_wrap(bc_idrac_kvm *, bc_console_emit,
    bc_idrac_led_snapshot, void *, bc_console_session **);
#ifdef __cplusplus
}
#endif
#endif

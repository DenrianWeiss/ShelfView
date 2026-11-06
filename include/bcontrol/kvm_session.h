#ifndef BCONTROL_KVM_SESSION_H
#define BCONTROL_KVM_SESSION_H
#include "console_session.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Emit runs on the input lane. The platform orders writes with protocol replies.
 * Decoder is borrowed and must outlive the returned unified session. */
BC_KVM_API bc_status bc_kvm_session_wrap(bc_kvm *, bc_console_emit, void *, bc_console_session **);
/* Owns the decoder; framebuffer and callback context remain borrowed. */
BC_KVM_API bc_status bc_kvm_session_create(const bc_kvm_options *, bc_console_emit, void *, bc_console_session **);
/* Input-only session for a separately hosted decoder. No display or decoder
 * storage is allocated; the caller gates readiness and supplies canvas size. */
BC_KVM_API bc_status bc_kvm_input_wrap(bc_console_emit, void *, bc_console_session **);
#ifdef __cplusplus
}
#endif
#endif

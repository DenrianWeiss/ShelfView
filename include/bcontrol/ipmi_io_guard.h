#ifndef BCONTROL_IPMI_IO_GUARD_H
#define BCONTROL_IPMI_IO_GUARD_H
#include "ipmi_session.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct bc_ipmi_io_guard bc_ipmi_io_guard;
/* Called on the session owner, never concurrently by this wrapper. check returns
 * the shared operation's remaining budget, or cancellation/failure. It may use
 * UINT32_MAX when no operation deadline applies. The caller keeps user and the
 * upstream transport alive until all session I/O has stopped. */
typedef uint64_t (*bc_ipmi_io_clock)(void *user);
typedef bc_status (*bc_ipmi_io_check)(void *user, uint32_t *remaining_ms);
BC_IPMI_API bc_status bc_ipmi_io_guard_create(const bc_ipmi_io *upstream,
    bc_ipmi_io_clock, bc_ipmi_io_check, void *user, bc_ipmi_io_guard **);
BC_IPMI_API const bc_ipmi_io *bc_ipmi_io_guard_get(const bc_ipmi_io_guard *);
/* Owner-only, non-nested scope for cleanup. The original check/cancellation is
 * restored by end_cleanup; its deadline continues advancing during cleanup. */
BC_IPMI_API bc_status bc_ipmi_io_guard_begin_cleanup(bc_ipmi_io_guard *, uint32_t timeout_ms);
BC_IPMI_API void bc_ipmi_io_guard_end_cleanup(bc_ipmi_io_guard *);
/* guard must be the session's I/O guard. Only release of a confirmed acquired
 * boot lock gets a separate 3000 ms budget; reads/writes retain the business budget. */
BC_IPMI_API bc_status bc_ipmi_boot_set_once_guarded(bc_ipmi_session *, uint32_t target,
    uint32_t mode, bc_ipmi_io_guard *, bc_ipmi_boot_result *);
/* Does not destroy the borrowed upstream. Receive checks cancellation at most
 * 25 ms apart when upstream honors its timeout. Send checks before submission;
 * interrupting an in-flight send remains the platform transport's responsibility. */
BC_IPMI_API void bc_ipmi_io_guard_destroy(bc_ipmi_io_guard *);
#ifdef __cplusplus
}
#endif
#endif

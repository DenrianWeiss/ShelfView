#ifndef BCONTROL_CONSOLE_H
#define BCONTROL_CONSOLE_H
#include "bcontrol.h"
#include "service_profile.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_CONSOLE_PHASE_DISCOVERY 1u
#define BC_CONSOLE_PHASE_LOGIN 2u
#define BC_CONSOLE_PHASE_LAUNCH 3u
#define BC_CONSOLE_PHASE_TRANSPORT 4u
#define BC_CONSOLE_PHASE_VALIDATION 5u
#define BC_CONSOLE_PHASE_MEDIA 6u
#define BC_CONSOLE_CAUSE_UNKNOWN 0u
#define BC_CONSOLE_CAUSE_CREDENTIALS 1u
#define BC_CONSOLE_CAUSE_ACCESS_DENIED 2u
#define BC_CONSOLE_CAUSE_SESSION_REJECTED 3u
#define BC_CONSOLE_CAUSE_SESSION_EXPIRED 4u
#define BC_CONSOLE_CAUSE_PROTOCOL 5u
#define BC_CONSOLE_CAUSE_BUSY 6u
#define BC_CONSOLE_CAUSE_LOCKED 7u
#define BC_CONSOLE_CAUSE_AUTH_REJECTED 8u
#define BC_CONSOLE_CAUSE_CLEANUP_UNCONFIRMED 9u
#define BC_CONSOLE_CAUSE_LICENSE_REQUIRED 10u
#define BC_CONSOLE_CAUSE_NOT_CONFIGURED 11u
#define BC_CONSOLE_RECOVERY_STOP 0u
#define BC_CONSOLE_RECOVERY_REFRESH_TICKET 1u
#define BC_CONSOLE_RECOVERY_ALTERNATE 2u
#define BC_CONSOLE_RECOVERY_RECONNECT_SAME 3u

typedef struct {
    uint32_t struct_size;
    bc_status status;
    uint32_t phase, cause, profile, http_status;
    int32_t device_code;
    uint32_t service, family;
} bc_console_failure;
typedef struct {
    uint32_t struct_size;
    uint32_t ticket_refreshes, profile_fallbacks;
} bc_console_retry_budget;
/* alternate_confirmed requires independent protocol evidence, not a brand or
 * an earlier failure. The caller consumes an action only when starting it. */
BC_API uint32_t bc_console_recovery(const bc_console_failure *, int web_authenticated,
    int alternate_confirmed, const bc_console_retry_budget *);

#define BC_CONSOLE_RECOVERY_ACTIVE 1u
#define BC_CONSOLE_RECOVERY_CLEANUP 2u
#define BC_CONSOLE_RECOVERY_STOPPED 3u
#define BC_CONSOLE_RECOVERY_SUCCEEDED 4u
#define BC_CONSOLE_RECOVERY_CANCELLED 5u
typedef struct bc_console_recovery_op bc_console_recovery_op;
typedef struct {
    uint32_t struct_size, state, attempt;
    bc_service_profile profile;
    bc_console_retry_budget budget;
} bc_console_recovery_view;
/* One serialized operation across asynchronous transports. Times are monotonic
 * milliseconds; callers choose the total timeout. No callbacks or I/O run here. */
BC_API bc_status bc_console_recovery_op_create(const bc_service_profile *, uint64_t now_ms,
    uint32_t timeout_ms, bc_console_recovery_op **);
/* Remaining time for the current transport or cleanup, never a fresh timeout.
 * Expiry or a regressing clock stops the operation; stale attempts return no time. */
BC_API bc_status bc_console_recovery_op_remaining(bc_console_recovery_op *, uint32_t attempt,
    uint64_t now_ms, uint32_t *remaining_ms);
/* Only a succeeded KVM connection can begin a runtime incident. Its timeout and
 * retry counters restart here, not at each failed retry. Ordinary transport
 * I/O/timeout with UNKNOWN cause allows one same-protocol reconnect; explicit
 * transport SESSION_EXPIRED uses bounded ticket recovery. Both require cleanup. */
BC_API bc_status bc_console_recovery_op_disconnected(bc_console_recovery_op *, uint32_t attempt,
    const bc_console_failure *, int web_authenticated, const bc_service_profile *alternate,
    int media_active, uint64_t now_ms, uint32_t timeout_ms, uint32_t *action);
/* Reserves the next action before cleanup. An alternate needs descriptor/handshake
 * evidence; a manual override alone does not justify automatic fallback.
 * media_active means media depends on this connection and must not be disrupted. */
BC_API bc_status bc_console_recovery_op_failed(bc_console_recovery_op *, uint32_t attempt,
    const bc_console_failure *, int web_authenticated, const bc_service_profile *alternate,
    int media_active, uint64_t now_ms, uint32_t *action);
/* Start a reserved action only after this returns OK. Cleanup is bounded by the
 * caller; an unconfirmed cleanup stops recovery. Read the new attempt from view. */
BC_API bc_status bc_console_recovery_op_resume(bc_console_recovery_op *, uint32_t attempt,
    int cleanup_confirmed, uint64_t now_ms, bc_service_profile *next);
BC_API bc_status bc_console_recovery_op_succeeded(bc_console_recovery_op *, uint32_t attempt, uint64_t now_ms);
BC_API void bc_console_recovery_op_cancel(bc_console_recovery_op *);
/* Borrowed snapshots; serialize access with the operation's transport callbacks. */
BC_API const bc_console_recovery_view *bc_console_recovery_op_view_get(const bc_console_recovery_op *);
BC_API const bc_console_failure *bc_console_recovery_op_failure_get(const bc_console_recovery_op *);
BC_API void bc_console_recovery_op_destroy(bc_console_recovery_op *);
#ifdef __cplusplus
}
#endif
#endif

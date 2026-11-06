#ifndef BCONTROL_OPERATION_H
#define BCONTROL_OPERATION_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct bc_operation bc_operation;
/* Drive on the owning scheduler. All times use the same monotonic clock in ms.
 * Cancellation is terminal; the platform also cancels outstanding network I/O. */
BC_API bc_status bc_operation_create(uint64_t now_ms, uint32_t timeout_ms, bc_operation **);
BC_API bc_status bc_operation_remaining(bc_operation *, uint64_t now_ms, uint32_t *remaining_ms);
BC_API void bc_operation_cancel(bc_operation *);
BC_API void bc_operation_destroy(bc_operation *);

#ifdef __cplusplus
}
#endif
#endif

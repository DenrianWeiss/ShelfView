#include "bcontrol/console.h"
#include "bcontrol/operation.h"
#include <stdlib.h>
#include <string.h>

struct bc_console_recovery_op {
    bc_console_recovery_view view;
    bc_console_failure failure;
    bc_service_profile next;
    uint64_t last_time;
    bc_operation *operation;
    int runtime, network_only, reconnected;
};
static bc_status stop(bc_console_recovery_op *op, bc_status status, uint32_t cause) {
    op->view.state = BC_CONSOLE_RECOVERY_STOPPED;
    op->failure = (bc_console_failure){sizeof(op->failure), status, BC_CONSOLE_PHASE_TRANSPORT,
        cause, op->view.profile.variant, 0, 0, op->view.profile.service, op->view.profile.family};
    return status;
}
static bc_status check(bc_console_recovery_op *op, uint32_t attempt, uint64_t now) {
    if (!op) return BC_INVALID_ARGUMENT;
    if (attempt != op->view.attempt || (op->view.state != BC_CONSOLE_RECOVERY_ACTIVE &&
        op->view.state != BC_CONSOLE_RECOVERY_CLEANUP)) return BC_CANCELLED;
    uint32_t remaining;
    bc_status status = bc_operation_remaining(op->operation, now, &remaining);
    if (status != BC_OK) return stop(op, status, BC_CONSOLE_CAUSE_UNKNOWN);
    op->last_time = now;
    return BC_OK;
}
bc_status bc_console_recovery_op_create(const bc_service_profile *profile, uint64_t now,
    uint32_t timeout, bc_console_recovery_op **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!profile || profile->struct_size != sizeof(*profile) || !timeout) return BC_INVALID_ARGUMENT;
    if (!bc_service_profile_can_attempt(profile, profile->service)) return BC_UNSUPPORTED;
    bc_console_recovery_op *op = calloc(1, sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    op->view = (bc_console_recovery_view){sizeof(op->view), BC_CONSOLE_RECOVERY_ACTIVE, 1,
        *profile, {sizeof(bc_console_retry_budget), 0, 0}};
    bc_status status = bc_operation_create(now, timeout, &op->operation);
    if (status != BC_OK) { free(op); return status; }
    op->last_time = now;
    *out = op; return BC_OK;
}
bc_status bc_console_recovery_op_remaining(bc_console_recovery_op *op, uint32_t attempt,
    uint64_t now, uint32_t *remaining) {
    if (!remaining) return BC_INVALID_ARGUMENT;
    *remaining = 0;
    bc_status status = check(op, attempt, now);
    if (status != BC_OK) return status;
    return bc_operation_remaining(op->operation, now, remaining);
}
static int matches(const bc_console_failure *failure, const bc_service_profile *profile) {
    return failure && failure->struct_size == sizeof(*failure) && failure->status != BC_OK &&
        failure->service == profile->service && failure->family == profile->family &&
        (!failure->profile || failure->profile == profile->variant);
}
bc_status bc_console_recovery_op_disconnected(bc_console_recovery_op *op, uint32_t attempt,
    const bc_console_failure *failure, int authenticated, const bc_service_profile *alternate,
    int media_active, uint64_t now, uint32_t timeout, uint32_t *action) {
    if (!action) return BC_INVALID_ARGUMENT;
    *action = BC_CONSOLE_RECOVERY_STOP;
    if (!op || !timeout) return BC_INVALID_ARGUMENT;
    if (attempt != op->view.attempt || op->view.state != BC_CONSOLE_RECOVERY_SUCCEEDED) return BC_CANCELLED;
    if (!matches(failure, &op->view.profile)) return BC_INVALID_ARGUMENT;
    if (op->view.profile.service != BC_SERVICE_KVM) return BC_UNSUPPORTED;
    if (now < op->last_time) return stop(op, BC_INVALID_ARGUMENT, BC_CONSOLE_CAUSE_UNKNOWN);
    bc_operation *operation = NULL;
    bc_status status = bc_operation_create(now, timeout, &operation);
    if (status != BC_OK) return status;
    bc_operation_destroy(op->operation);
    op->operation = operation;
    op->last_time = now;
    op->view.budget.ticket_refreshes = op->view.budget.profile_fallbacks = 0;
    op->runtime = 1;
    op->reconnected = 0;
    op->network_only = failure->phase == BC_CONSOLE_PHASE_TRANSPORT &&
        failure->cause == BC_CONSOLE_CAUSE_UNKNOWN &&
        (failure->status == BC_IO_ERROR || failure->status == BC_TIMEOUT);
    op->view.state = BC_CONSOLE_RECOVERY_ACTIVE;
    return bc_console_recovery_op_failed(op, attempt, failure, authenticated, alternate,
        media_active, now, action);
}
bc_status bc_console_recovery_op_failed(bc_console_recovery_op *op, uint32_t attempt,
    const bc_console_failure *failure, int authenticated, const bc_service_profile *alternate,
    int media_active, uint64_t now, uint32_t *action) {
    if (!action) return BC_INVALID_ARGUMENT;
    *action = BC_CONSOLE_RECOVERY_STOP;
    bc_status status = check(op, attempt, now);
    if (status != BC_OK) return status;
    if (op->view.state != BC_CONSOLE_RECOVERY_ACTIVE) return BC_BUSY;
    const bc_service_profile *current = &op->view.profile;
    if (!matches(failure, current)) return BC_INVALID_ARGUMENT;
    op->failure = *failure;
    int confirmed = bc_service_profile_can_attempt(alternate, current->service) &&
        (alternate->evidence & (BC_SERVICE_EVIDENCE_DESCRIPTOR | BC_SERVICE_EVIDENCE_HANDSHAKE)) &&
        (alternate->family != current->family || alternate->variant != current->variant);
    if (!media_active) {
        bc_console_failure classified = *failure;
        if (op->runtime && failure->phase == BC_CONSOLE_PHASE_TRANSPORT &&
            failure->cause == BC_CONSOLE_CAUSE_SESSION_EXPIRED)
            classified.phase = BC_CONSOLE_PHASE_VALIDATION;
        if (op->runtime && op->network_only && !op->reconnected && authenticated &&
            failure->phase == BC_CONSOLE_PHASE_TRANSPORT && failure->cause == BC_CONSOLE_CAUSE_UNKNOWN &&
            (failure->status == BC_IO_ERROR || failure->status == BC_TIMEOUT))
            *action = BC_CONSOLE_RECOVERY_RECONNECT_SAME;
        else *action = bc_console_recovery(&classified, authenticated,
            confirmed && !op->network_only, &op->view.budget);
    }
    if (*action == BC_CONSOLE_RECOVERY_STOP) { op->view.state = BC_CONSOLE_RECOVERY_STOPPED; return BC_OK; }
    op->next = *action == BC_CONSOLE_RECOVERY_ALTERNATE ? *alternate : *current;
    /* Evidence belongs to the protocol, not to the next transport's live state. */
    if (*action == BC_CONSOLE_RECOVERY_REFRESH_TICKET) ++op->view.budget.ticket_refreshes;
    else if (*action == BC_CONSOLE_RECOVERY_ALTERNATE) ++op->view.budget.profile_fallbacks;
    else op->reconnected = 1;
    op->view.state = BC_CONSOLE_RECOVERY_CLEANUP;
    return BC_OK;
}
bc_status bc_console_recovery_op_resume(bc_console_recovery_op *op, uint32_t attempt,
    int cleaned, uint64_t now, bc_service_profile *next) {
    if (!next) return BC_INVALID_ARGUMENT;
    memset(next, 0, sizeof(*next));
    bc_status status = check(op, attempt, now);
    if (status != BC_OK) return status;
    if (op->view.state != BC_CONSOLE_RECOVERY_CLEANUP) return BC_BUSY;
    if (!cleaned) return stop(op, BC_IO_ERROR, BC_CONSOLE_CAUSE_CLEANUP_UNCONFIRMED);
    op->view.profile = op->next; *next = op->next;
    ++op->view.attempt; op->view.state = BC_CONSOLE_RECOVERY_ACTIVE;
    return BC_OK;
}
bc_status bc_console_recovery_op_succeeded(bc_console_recovery_op *op, uint32_t attempt, uint64_t now) {
    bc_status status = check(op, attempt, now);
    if (status != BC_OK) return status;
    if (op->view.state != BC_CONSOLE_RECOVERY_ACTIVE) return BC_BUSY;
    op->view.state = BC_CONSOLE_RECOVERY_SUCCEEDED;
    memset(&op->failure, 0, sizeof(op->failure));
    return BC_OK;
}
void bc_console_recovery_op_cancel(bc_console_recovery_op *op) {
    if (op && (op->view.state == BC_CONSOLE_RECOVERY_ACTIVE || op->view.state == BC_CONSOLE_RECOVERY_CLEANUP ||
        op->view.state == BC_CONSOLE_RECOVERY_SUCCEEDED))
        op->view.state = BC_CONSOLE_RECOVERY_CANCELLED;
}
const bc_console_recovery_view *bc_console_recovery_op_view_get(const bc_console_recovery_op *op) {
    return op ? &op->view : NULL;
}
const bc_console_failure *bc_console_recovery_op_failure_get(const bc_console_recovery_op *op) {
    return op && op->failure.struct_size ? &op->failure : NULL;
}
void bc_console_recovery_op_destroy(bc_console_recovery_op *op) {
    if (op) bc_operation_destroy(op->operation);
    free(op);
}

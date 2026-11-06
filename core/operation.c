#include "bcontrol/operation.h"
#include <stdlib.h>

struct bc_operation {
    uint64_t started, last;
    uint32_t timeout;
    bc_status status;
};

bc_status bc_operation_create(uint64_t now, uint32_t timeout, bc_operation **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!timeout) return BC_INVALID_ARGUMENT;
    bc_operation *op = malloc(sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    *op = (bc_operation){now, now, timeout, BC_OK};
    *out = op;
    return BC_OK;
}

bc_status bc_operation_remaining(bc_operation *op, uint64_t now, uint32_t *remaining) {
    if (!remaining) return BC_INVALID_ARGUMENT;
    *remaining = 0;
    if (!op) return BC_INVALID_ARGUMENT;
    if (op->status != BC_OK) return op->status;
    if (now < op->last) return op->status = BC_INVALID_ARGUMENT;
    op->last = now;
    if (now - op->started >= op->timeout) return op->status = BC_TIMEOUT;
    *remaining = op->timeout - (uint32_t)(now - op->started);
    return BC_OK;
}

void bc_operation_cancel(bc_operation *op) {
    if (op && op->status == BC_OK) op->status = BC_CANCELLED;
}

void bc_operation_destroy(bc_operation *op) { free(op); }

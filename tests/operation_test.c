#include "bcontrol/operation.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

int main(void) {
    bc_operation *op = NULL;
    uint32_t remaining = 1;
    CHECK(bc_operation_create(100, 0, &op) == BC_INVALID_ARGUMENT && !op);
    CHECK(bc_operation_create(100, 50, &op) == BC_OK);
    CHECK(bc_operation_remaining(op, 120, &remaining) == BC_OK && remaining == 30);
    CHECK(bc_operation_remaining(op, 149, &remaining) == BC_OK && remaining == 1);
    CHECK(bc_operation_remaining(op, 150, &remaining) == BC_TIMEOUT && remaining == 0);
    CHECK(bc_operation_remaining(op, 100, &remaining) == BC_TIMEOUT);
    bc_operation_destroy(op);
    CHECK(bc_operation_create(UINT64_MAX - 100, 50, &op) == BC_OK);
    CHECK(bc_operation_remaining(op, UINT64_MAX - 75, &remaining) == BC_OK && remaining == 25);
    bc_operation_cancel(op);
    CHECK(bc_operation_remaining(op, UINT64_MAX - 70, &remaining) == BC_CANCELLED && remaining == 0);
    bc_operation_destroy(op);
    CHECK(bc_operation_create(100, 50, &op) == BC_OK);
    CHECK(bc_operation_remaining(op, 99, &remaining) == BC_INVALID_ARGUMENT && remaining == 0);
    CHECK(bc_operation_remaining(op, 101, &remaining) == BC_INVALID_ARGUMENT);
    bc_operation_destroy(op);
    puts("operation: shared deadline, terminal cancellation and monotonic clock passed");
    return 0;
}

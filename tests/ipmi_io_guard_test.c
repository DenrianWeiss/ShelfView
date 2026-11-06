#include "bcontrol/ipmi_io_guard.h"
#include "bcontrol/operation.h"
#include <assert.h>
#include <stddef.h>

typedef struct { uint64_t now; unsigned reads, sends; int cancel_after_read; bc_operation *operation; } fixture;
static uint64_t clock_ms(void *user) { return ((fixture *)user)->now; }
static bc_status check_budget(void *user, uint32_t *remaining) {
    fixture *f = user;
    return bc_operation_remaining(f->operation, f->now, remaining);
}
static bc_status send_packet(void *user, const uint8_t *data, uint32_t length) {
    (void)data; (void)length; ((fixture *)user)->sends++; return BC_OK;
}
static bc_status receive_packet(void *user, uint8_t *data, uint32_t capacity, uint32_t *length, uint32_t timeout) {
    (void)data; (void)capacity;
    fixture *f = user; f->reads++; f->now += timeout; *length = 0;
    assert(timeout <= 25);
    if (f->cancel_after_read) bc_operation_cancel(f->operation);
    return BC_TIMEOUT;
}
int main(void) {
    fixture f = {0};
    assert(bc_operation_create(0, 60, &f.operation) == BC_OK);
    bc_ipmi_io upstream = {sizeof(upstream), BC_ABI_VERSION, &f, send_packet, receive_packet};
    bc_ipmi_io_guard *guard = NULL;
    assert(bc_ipmi_io_guard_create(&upstream, clock_ms, check_budget, &f, &guard) == BC_OK);
    const bc_ipmi_io *io = bc_ipmi_io_guard_get(guard);
    uint8_t data[8]; uint32_t length;
    assert(io->receive(io->userdata, data, sizeof(data), &length, 40) == BC_TIMEOUT);
    assert(f.now == 40 && f.reads == 2);
    assert(io->send(io->userdata, data, 1) == BC_OK && f.sends == 1);
    assert(io->receive(io->userdata, data, sizeof(data), &length, 3000) == BC_TIMEOUT);
    assert(f.now == 60 && f.reads == 3);
    assert(io->send(io->userdata, data, 1) == BC_TIMEOUT && f.sends == 1);
    bc_operation_destroy(f.operation);
    assert(bc_operation_create(f.now, 3000, &f.operation) == BC_OK);
    f.cancel_after_read = 1;
    assert(io->receive(io->userdata, data, sizeof(data), &length, 3000) == BC_CANCELLED);
    assert(f.now == 85 && f.reads == 4);
    assert(io->send(io->userdata, data, 1) == BC_CANCELLED && f.sends == 1);
    bc_operation_destroy(f.operation);
    assert(bc_operation_create(f.now, 100, &f.operation) == BC_OK);
    f.cancel_after_read = 0;
    assert(io->receive(io->userdata, data, sizeof(data), &length, 0) == BC_TIMEOUT);
    assert(f.now == 85 && f.reads == 5);
    bc_operation_cancel(f.operation);
    assert(bc_ipmi_io_guard_begin_cleanup(guard, 3000) == BC_OK);
    assert(bc_ipmi_io_guard_begin_cleanup(guard, 3000) == BC_BUSY);
    assert(io->send(io->userdata, data, 1) == BC_OK);
    assert(io->receive(io->userdata, data, sizeof(data), &length, 5000) == BC_TIMEOUT);
    assert(f.now == 3085);
    assert(io->send(io->userdata, data, 1) == BC_TIMEOUT);
    bc_ipmi_io_guard_end_cleanup(guard);
    assert(io->send(io->userdata, data, 1) == BC_CANCELLED);
    bc_ipmi_io_guard_destroy(guard);
    bc_operation_destroy(f.operation);
    return 0;
}

#include "bcontrol/ipmi_io_guard.h"
#include <stdlib.h>

struct bc_ipmi_io_guard {
    bc_ipmi_io io;
    const bc_ipmi_io *upstream;
    bc_ipmi_io_clock clock;
    bc_ipmi_io_check check;
    void *user;
    uint64_t cleanup_started;
    uint32_t cleanup_timeout;
};

static bc_status available(bc_ipmi_io_guard *guard, uint32_t *remaining) {
    *remaining = 0;
    if (guard->cleanup_timeout) {
        uint64_t now = guard->clock(guard->user);
        if (now < guard->cleanup_started) return BC_INVALID_ARGUMENT;
        uint64_t elapsed = now - guard->cleanup_started;
        if (elapsed >= guard->cleanup_timeout) return BC_TIMEOUT;
        *remaining = guard->cleanup_timeout - (uint32_t)elapsed;
        return BC_OK;
    }
    bc_status status = guard->check(guard->user, remaining);
    return status != BC_OK ? status : *remaining ? BC_OK : BC_TIMEOUT;
}
static bc_status send_guarded(void *user, const uint8_t *data, uint32_t length) {
    bc_ipmi_io_guard *guard = user;
    uint32_t remaining;
    bc_status status = available(guard, &remaining);
    if (status != BC_OK) return status;
    return guard->upstream->send(guard->upstream->userdata, data, length);
}
static bc_status receive_guarded(void *user, uint8_t *data, uint32_t capacity,
    uint32_t *length, uint32_t timeout) {
    if (!length || (!data && capacity)) return BC_INVALID_ARGUMENT;
    *length = 0;
    bc_ipmi_io_guard *guard = user;
    uint64_t started = guard->clock(guard->user), previous = started;
    for (;;) {
        uint32_t remaining;
        bc_status status = available(guard, &remaining);
        if (status != BC_OK) return status;
        uint64_t now = guard->clock(guard->user);
        if (now < previous) return BC_INVALID_ARGUMENT;
        previous = now;
        uint64_t elapsed = now - started;
        if (timeout && elapsed >= timeout) return BC_TIMEOUT;
        uint32_t slice = timeout ? timeout - (uint32_t)elapsed : 0;
        if (slice > 25) slice = 25;
        if (slice > remaining) slice = remaining;
        status = guard->upstream->receive(guard->upstream->userdata, data, capacity, length, slice);
        if (status != BC_TIMEOUT || !timeout) return status;
        *length = 0;
    }
}

bc_status bc_ipmi_io_guard_create(const bc_ipmi_io *upstream, bc_ipmi_io_clock clock,
    bc_ipmi_io_check check, void *user, bc_ipmi_io_guard **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!upstream || upstream->struct_size != sizeof(*upstream) || upstream->abi_version != BC_ABI_VERSION ||
        !upstream->send || !upstream->receive || !clock || !check) return BC_INVALID_ARGUMENT;
    bc_ipmi_io_guard *guard = calloc(1, sizeof(*guard));
    if (!guard) return BC_NO_MEMORY;
    guard->upstream = upstream; guard->clock = clock; guard->check = check; guard->user = user;
    guard->io = (bc_ipmi_io){sizeof(bc_ipmi_io), BC_ABI_VERSION, guard, send_guarded, receive_guarded};
    *out = guard; return BC_OK;
}
const bc_ipmi_io *bc_ipmi_io_guard_get(const bc_ipmi_io_guard *guard) { return guard ? &guard->io : NULL; }
bc_status bc_ipmi_io_guard_begin_cleanup(bc_ipmi_io_guard *guard, uint32_t timeout) {
    if (!guard || !timeout) return BC_INVALID_ARGUMENT;
    if (guard->cleanup_timeout) return BC_BUSY;
    guard->cleanup_started = guard->clock(guard->user);
    guard->cleanup_timeout = timeout;
    return BC_OK;
}
void bc_ipmi_io_guard_end_cleanup(bc_ipmi_io_guard *guard) {
    if (guard) guard->cleanup_timeout = 0;
}
void bc_ipmi_io_guard_destroy(bc_ipmi_io_guard *guard) { free(guard); }

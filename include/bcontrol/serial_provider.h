#ifndef BCONTROL_SERIAL_PROVIDER_H
#define BCONTROL_SERIAL_PROVIDER_H
#include "serial.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Adapter interface; no platform socket or thread types cross the ABI. */
typedef struct {
    uint32_t struct_size;
    bc_status (*read)(void *, uint64_t, uint32_t, uint8_t *, uint32_t, uint32_t *);
    bc_status (*write)(void *, bc_bytes, uint32_t *);
    bc_status (*control)(void *, uint32_t);
    bc_status (*info)(const void *, bc_serial_info *);
    bc_status (*close)(void *);
    void (*destroy)(void *);
} bc_serial_provider;
BC_API void bc_serial_own(bc_serial_stream *);
BC_API bc_status bc_serial_wrap(const bc_serial_provider *, void *, bc_serial_stream **);
#ifdef __cplusplus
}
#endif
#endif

#ifndef BCONTROL_DECODE_PROVIDER_H
#define BCONTROL_DECODE_PROVIDER_H
#include "decode_job.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Copies compressed bytes. Context ownership transfers only on success. */
BC_API bc_status bc_decode_job_create(const uint8_t *, uint32_t,
    bc_status (*execute)(void *, const uint8_t *, uint32_t),
    void (*destroy)(void *), void *, bc_decode_job **);
#ifdef __cplusplus
}
#endif
#endif

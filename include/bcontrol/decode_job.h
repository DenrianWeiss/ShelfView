#ifndef BCONTROL_DECODE_JOB_H
#define BCONTROL_DECODE_JOB_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_decode_job bc_decode_job;
/* Success transfers the job to the scheduler. On failure the producer retains
 * ownership. Preserve order and drain/release queued jobs before the session.
 * Execute and destroy are serialized by the platform's decode lane. */
typedef bc_status (*bc_decode_submit)(void *, bc_decode_job *);
BC_API uint32_t bc_decode_job_size(const bc_decode_job *);
BC_API bc_status bc_decode_job_execute(bc_decode_job *);
BC_API void bc_decode_job_destroy(bc_decode_job *);
#ifdef __cplusplus
}
#endif
#endif

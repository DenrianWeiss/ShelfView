#include "bcontrol/decode_provider.h"
#include <stdlib.h>
#include <string.h>
struct bc_decode_job {
    uint8_t *bytes;
    uint32_t length;
    int executed;
    bc_status (*execute)(void *, const uint8_t *, uint32_t);
    void (*destroy)(void *);
    void *user;
};
bc_status bc_decode_job_create(const uint8_t *bytes, uint32_t length,
    bc_status (*execute)(void *, const uint8_t *, uint32_t),
    void (*destroy)(void *), void *user, bc_decode_job **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!bytes || !length || !execute || !destroy) return BC_INVALID_ARGUMENT;
    bc_decode_job *job = calloc(1, sizeof(*job));
    if (!job) return BC_NO_MEMORY;
    job->bytes = malloc(length);
    if (!job->bytes) { free(job); return BC_NO_MEMORY; }
    memcpy(job->bytes, bytes, length);
    job->length = length; job->execute = execute; job->destroy = destroy; job->user = user;
    *out = job;
    return BC_OK;
}
uint32_t bc_decode_job_size(const bc_decode_job *job) { return job ? job->length : 0; }
bc_status bc_decode_job_execute(bc_decode_job *job) {
    if (!job) return BC_INVALID_ARGUMENT;
    if (job->executed) return BC_BUSY;
    job->executed = 1;
    return job->execute(job->user, job->bytes, job->length);
}
void bc_decode_job_destroy(bc_decode_job *job) {
    if (!job) return;
    job->destroy(job->user);
    free(job->bytes);
    free(job);
}

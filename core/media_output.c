#include "bcontrol/media_output_provider.h"
#include <stdlib.h>
#include <string.h>
#define OUTPUT_LIMIT (17u * 1024u * 1024u)
#define OUTPUT_MESSAGES 16u
typedef struct message { struct message *next; uint32_t size; uint8_t bytes[]; } message;
struct bc_media_output { message *head, *tail; uint32_t bytes, count; };
bc_status bc_media_output_create(bc_media_output **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = calloc(1, sizeof(**out));
    return *out ? BC_OK : BC_NO_MEMORY;
}
bc_status bc_media_output_emit(void *user, const uint8_t *bytes, uint32_t size) {
    bc_media_output *out = user;
    if (!out || (size && !bytes)) return BC_INVALID_ARGUMENT;
    if (out->count == OUTPUT_MESSAGES || size > OUTPUT_LIMIT-out->bytes) return BC_LIMIT_EXCEEDED;
    message *m = malloc(sizeof(*m)+(size_t)size);
    if (!m) return BC_NO_MEMORY;
    m->next = NULL; m->size = size;
    if (size) memcpy(m->bytes, bytes, size);
    if (out->tail) out->tail->next = m; else out->head = m;
    out->tail = m; out->bytes += size; ++out->count;
    return BC_OK;
}
static void release(message *m) {
    volatile uint8_t *wipe = m->bytes;
    for (uint32_t i = 0; i < m->size; ++i) wipe[i] = 0;
    free(m);
}
bc_status bc_media_output_take(bc_media_output *out, uint8_t *bytes, uint32_t capacity, uint32_t *written) {
    if (!written || !out || (capacity && !bytes)) return BC_INVALID_ARGUMENT;
    *written = 0;
    message *m = out->head;
    if (!m) return BC_BUSY;
    *written = m->size;
    if (capacity < m->size) return BC_LIMIT_EXCEEDED;
    if (m->size) memcpy(bytes, m->bytes, m->size);
    out->head = m->next;
    if (!out->head) out->tail = NULL;
    out->bytes -= m->size; --out->count;
    release(m);
    return BC_OK;
}
void bc_media_output_destroy(bc_media_output *out) {
    if (!out) return;
    while (out->head) { message *m = out->head; out->head = m->next; release(m); }
    free(out);
}

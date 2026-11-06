#ifndef BC_AGENT_MEDIA_PULL_H
#define BC_AGENT_MEDIA_PULL_H
#include <stddef.h>
#include <stdint.h>
#include "bcontrol/media_session.h"
typedef struct bc_media_pull bc_media_pull;
bc_media_pull *bc_media_pull_create(const char *listen, const char *advertise);
int bc_media_pull_add(bc_media_pull *, const char *path, char token[65], char *url, size_t capacity, uint64_t *size_out);
/* Takes source.userdata ownership only on success. */
int bc_media_pull_add_source(bc_media_pull *, const bc_media_source *, void (*release)(void *), char token[65], char *url, size_t capacity);
void bc_media_pull_remove(bc_media_pull *, const char *token);
void bc_media_pull_destroy(bc_media_pull *);
#endif

#ifndef BC_AGENT_MEDIA_SERVICE_H
#define BC_AGENT_MEDIA_SERVICE_H
#include "civetweb.h"
#include "yyjson.h"
#include "bcontrol/media_session.h"
typedef struct bc_media_service bc_media_service;
typedef struct {
    void *userdata;
    int (*allowed)(const struct mg_connection *, void *);
    int (*authorize)(struct mg_connection *, void *, char client_id[33]);
    int (*client_active_locked)(void *, const char *client_id);
    int (*json)(struct mg_connection *, void *, int, yyjson_mut_doc *);
    int (*error)(struct mg_connection *, void *, int, const char *);
    int (*bytes)(struct mg_connection *, void *, const void *, size_t);
} bc_media_hooks;
bc_media_service *bc_media_service_create(struct mg_context *, const bc_media_hooks *);
int bc_media_service_http(bc_media_service *, struct mg_connection *, const char *path, const char *method);
void bc_media_service_tick(bc_media_service *);
void bc_media_service_shutdown(bc_media_service *);
void bc_media_service_destroy(bc_media_service *);
/* Successful acquisition owns source.userdata until source_release. */
bc_status bc_media_service_source_acquire(bc_media_service *, const char *owner, const char *id, bc_media_source *);
void bc_media_service_source_release(void *userdata);
/* Caller holds the shared Agent HTTP context lock. */
int bc_media_service_source_active_locked(bc_media_service *, const char *owner, const char *id);
#endif

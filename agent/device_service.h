#ifndef BC_AGENT_DEVICE_SERVICE_H
#define BC_AGENT_DEVICE_SERVICE_H
#include "bcontrol/bcontrol.h"
#include <stddef.h>
#include "civetweb.h"
#include "yyjson.h"
typedef struct bc_device_service bc_device_service;
typedef struct {
    void *userdata;
    int (*authorize)(struct mg_connection *, void *, char owner[33]);
    int (*client_active_locked)(void *, const char *owner);
    int (*json)(struct mg_connection *, void *, int, yyjson_mut_doc *);
    int (*error)(struct mg_connection *, void *, int, const char *);
    int (*media_add)(void *, const char *path, char token[65], char *url, size_t capacity, uint64_t *size);
    void (*media_remove)(void *, const char *token);
    int (*media_add_source)(void *, const char *owner, const char *source_id, char token[65], char *url, size_t capacity, uint64_t *size);
    int (*media_source_available)(void *);
    int (*media_source_active_locked)(void *, const char *owner, const char *id);
} bc_device_hooks;
bc_device_service *bc_device_service_create(struct mg_context *, const bc_endpoint_options *, const bc_device_hooks *);
int bc_device_service_http(bc_device_service *, struct mg_connection *, const char *, const char *);
void bc_device_service_tick(bc_device_service *);
void bc_device_service_shutdown(bc_device_service *);
void bc_device_service_destroy(bc_device_service *);
#endif

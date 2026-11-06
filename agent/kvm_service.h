#ifndef BC_AGENT_KVM_SERVICE_H
#define BC_AGENT_KVM_SERVICE_H
#include "bcontrol/bcontrol.h"
#include "civetweb.h"
#include "yyjson.h"
typedef struct bc_kvm_service bc_kvm_service;
typedef struct {
    void *userdata;
    int (*allowed)(const struct mg_connection *, void *);
    int (*authorize)(struct mg_connection *, void *, char client_id[33]);
    int (*client_active_locked)(void *, const char *client_id);
    int (*json)(struct mg_connection *, void *, int, yyjson_mut_doc *);
    int (*error)(struct mg_connection *, void *, int, const char *);
} bc_kvm_hooks;
typedef struct {
    const char *url;
    const char *management_device_id;
    const char *ca_file;
    const bc_string *headers;
    uint32_t header_count;
    uint32_t cert_policy;
    uint32_t tls_min, tls_max;
    uint32_t flags;
    uint32_t timeout_ms;
} bc_agent_kvm_options;
bc_kvm_service *bc_kvm_service_create(struct mg_context *, const bc_kvm_hooks *, const bc_agent_kvm_options *);
int bc_kvm_service_http(bc_kvm_service *, struct mg_connection *, const char *path, const char *method);
void bc_kvm_service_tick(bc_kvm_service *);
void bc_kvm_service_shutdown(bc_kvm_service *);
/* Stop/join the HTTP workers after shutdown and before destroy. */
void bc_kvm_service_destroy(bc_kvm_service *);
#endif

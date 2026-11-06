#include "device_service.h"
#include "server.h"
#include "redfish_json.h"
#include "bcontrol/redfish_auth.h"
#include "bcontrol/transport.h"
#include "bcontrol/remote_media.h"
#include <openssl/rand.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONNECTION_LIMIT 8
#define CONNECT 0u
#define READ 1u
#define CLOSE 2u
#define QUERY 3u
#define RESET 4u
#define MEDIA_MAP 5u
#define MEDIA_UNMAP 6u
#define BOOT_ONCE 7u
typedef struct {
    uint32_t kind, mode, selection, method;
    char *path;
    char *file;
    char *transfer_method;
    char *transfer_protocol;
    char *body;
    uint32_t body_length;
    uint32_t write_protected;
    int direct_media;
    int browser_source;
    char token[65];
    char url[1024];
    int started, ready, done, internal, http, fatal, close_after_media, verify_media;
    int submit_manual_eject;
    uint64_t media_deadline;
    bc_status status, media_cleanup_status;
    yyjson_mut_doc *doc;
} job;
typedef struct {
    int used;
    uint32_t state;
    char id[33], owner[33];
    char media_token[65];
    char media_source_id[33];
    char *media_uri;
    int remote_media;
    struct bc_device_service *service;
    job *pending;
    job cleanup;
    bc_transport *transport;
    bc_context *context;
    bc_endpoint *base;
    bc_redfish_connection *connection;
    bc_redfish_auth_operation *auth;
    bc_request *request;
    bc_redfish_operation *typed;
} device_slot;
struct bc_device_service {
    struct mg_context *http;
    bc_endpoint_options endpoint;
    bc_device_hooks hooks;
    device_slot slots[CONNECTION_LIMIT];
    bc_remote_media_registry *remote_media;
    int stopping;
};
static bc_string text(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
static int random_id(char out[33]) {
    unsigned char bytes[16]; const char *hex = "0123456789abcdef";
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) return 0;
    for (unsigned i = 0; i < sizeof(bytes); ++i) { out[2*i] = hex[bytes[i] >> 4]; out[2*i+1] = hex[bytes[i] & 15]; }
    out[32] = 0; return 1;
}
static job *new_job(uint32_t kind) {
    job *j = calloc(1, sizeof(*j));
    if (!j) return NULL;
    j->kind = kind; j->http = 200; j->doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = j->doc ? yyjson_mut_obj(j->doc) : NULL;
    if (!root) { yyjson_mut_doc_free(j->doc); free(j); return NULL; }
    yyjson_mut_doc_set_root(j->doc, root); return j;
}
static void free_job(job *j) { if (j) { yyjson_mut_doc_free(j->doc); free(j->path); free(j->file); free(j->transfer_method); free(j->transfer_protocol); free(j->body); free(j); } }
static void auth_done(bc_redfish_auth_operation *operation, const bc_redfish_auth_result *r, void *userdata) {
    (void)operation; device_slot *slot = userdata; job *j = slot->pending;
    j->status = r->status; j->ready = 1;
    if (j->internal) return;
    yyjson_mut_val *out = yyjson_mut_doc_get_root(j->doc);
    yyjson_mut_obj_add_uint(j->doc, out, "http_status", r->http_status);
    yyjson_mut_obj_add_uint(j->doc, out, "flags", r->flags);
    if (j->kind == CONNECT && r->status == BC_OK) {
        slot->connection = r->connection; bc_redfish_connection_retain(slot->connection);
        const bc_redfish_connection_info *info = bc_redfish_connection_info_get(slot->connection);
        char revision[32]; snprintf(revision, sizeof(revision), "%" PRIu64, info->endpoint_revision);
        yyjson_mut_obj_add_strcpy(j->doc, out, "endpoint_revision", revision);
        yyjson_mut_obj_add_str(j->doc, out, "authentication", r->auth_mode == BC_REDFISH_LOGIN_SESSION ? "session" : "basic");
        j->http = 201;
        bc_string retained = {0};
        bc_status bound = bc_remote_media_registry_bind(slot->service->remote_media, text(slot->owner), text(slot->id), &retained);
        if (bound == BC_OK) {
            slot->media_uri = malloc((size_t)retained.length + 1);
            if (slot->media_uri) {
                memcpy(slot->media_uri, retained.data, (size_t)retained.length); slot->media_uri[retained.length] = 0;
                slot->remote_media = 1;
            } else { bc_remote_media_registry_release(slot->service->remote_media, text(slot->id)); j->status = BC_NO_MEMORY; }
        }
    }
}
static void read_done(bc_request *request, const bc_response *r, void *userdata) {
    (void)request; device_slot *slot = userdata; job *j = slot->pending;
    j->status = r->status; j->ready = 1;
    yyjson_mut_val *out = yyjson_mut_doc_get_root(j->doc);
    yyjson_mut_obj_add_uint(j->doc, out, "http_status", r->http_status);
    yyjson_mut_obj_add_uint(j->doc, out, "cert_policy", r->cert_policy);
    yyjson_mut_obj_add_bool(j->doc, out, "peer_verified", r->peer_verified != 0);
    yyjson_mut_obj_add_strncpy(j->doc, out, "tls_version", r->tls_version.data ? r->tls_version.data : "", (size_t)r->tls_version.length);
    if (r->body.length) {
        yyjson_doc *body = yyjson_read((const char *)r->body.data, (size_t)r->body.length, 0);
        if (body) {
            yyjson_mut_obj_add_val(j->doc, out, "body", yyjson_val_mut_copy(j->doc, yyjson_doc_get_root(body)));
            yyjson_doc_free(body);
        } else yyjson_mut_obj_add_str(j->doc, out, "body_format", "non_json");
    }
}
static void media_done(bc_redfish_operation *operation, const bc_redfish_result *r, void *userdata) {
    (void)operation; device_slot *slot = userdata; job *j = slot->pending;
    j->status = r->status; j->ready = 1;
    yyjson_mut_val *out = yyjson_mut_doc_get_root(j->doc);
    yyjson_mut_obj_add_uint(j->doc, out, "http_status", r->http_status);
    yyjson_mut_obj_add_uint(j->doc, out, "flags", r->flags);
    if (j->kind == MEDIA_MAP) {
        if (r->status == BC_OK || r->status == BC_OUTCOME_UNKNOWN || (r->flags & BC_REDFISH_COMMAND_UNCONFIRMED)) {
            if (!j->direct_media) memcpy(slot->media_token, j->token, sizeof(slot->media_token));
            if (j->browser_source) memcpy(slot->media_source_id, j->file, sizeof(slot->media_source_id));
            slot->media_uri = j->path;
            j->path = NULL;
            yyjson_mut_obj_add_strcpy(j->doc, out, "url", j->direct_media ? j->file : j->url);
        } else if (j->direct_media) {
            bc_remote_media_registry_clear(slot->service->remote_media, text(slot->id)); slot->remote_media = 0;
        }
    } else if (j->kind == MEDIA_UNMAP && r->status == BC_OK) {
        j->verify_media = 1;
    }
}
static void clear_media(device_slot *slot) {
    if (slot->remote_media) bc_remote_media_registry_clear(slot->service->remote_media, text(slot->id));
    if (slot->media_token[0] && slot->service->hooks.media_remove)
        slot->service->hooks.media_remove(slot->service->hooks.userdata, slot->media_token);
    OPENSSL_cleanse(slot->media_token, sizeof(slot->media_token));
    slot->media_source_id[0] = 0; slot->remote_media = 0;
    free(slot->media_uri); slot->media_uri = NULL;
}
static void typed_done(bc_redfish_operation *operation, const bc_redfish_result *r, void *userdata) {
    device_slot *slot = userdata; job *j = slot->pending;
    j->status = r->status; j->ready = 1;
    bc_agent_redfish_json(j->doc, operation, r);
    const bc_redfish_virtual_media_info *media = bc_redfish_virtual_media_info_get(operation);
    if (r->status == BC_OK && slot->media_uri && j->path && !strcmp(slot->media_uri, j->path) &&
        media && (media->flags & BC_REDFISH_VM_INSERTED_PRESENT) && !media->inserted && !media->image.length) {
        clear_media(slot);
    }
}
static bc_status typed_start(device_slot *slot, job *j) {
    bc_endpoint *endpoint = bc_redfish_connection_endpoint(slot->connection);
    bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, 5000, 256};
    bc_redfish_collection_options collections = {sizeof(collections), BC_ABI_VERSION, 5000, 256};
    bc_string uri = text(j->path);
    if (j->kind == BOOT_ONCE) return bc_redfish_boot_set_once(endpoint, uri, j->selection, j->mode, &options, typed_done, slot, &slot->typed);
    if (j->kind == RESET) return bc_redfish_reset(endpoint, uri, j->selection, &options, typed_done, slot, &slot->typed);
    switch (j->selection) {
    case BC_REDFISH_DISCOVERY: return bc_redfish_discover(endpoint, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_TASK_DISCOVERY: return bc_redfish_discover_tasks(endpoint, &collections, typed_done, slot, &slot->typed);
    case BC_REDFISH_CHASSIS_DISCOVERY: return bc_redfish_discover_chassis(endpoint, &collections, typed_done, slot, &slot->typed);
    case BC_REDFISH_BOOT: return bc_redfish_get_boot(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_SYSTEM: return bc_redfish_get_system(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_RESET_CAPABILITIES: return bc_redfish_get_reset_capabilities(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_SENSOR_DISCOVERY: return bc_redfish_discover_sensors(endpoint, uri, &collections, typed_done, slot, &slot->typed);
    case BC_REDFISH_SENSOR: return bc_redfish_get_sensor(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_SENSOR_DETAILS: return bc_redfish_get_sensor_details(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_TASK: return bc_redfish_get_task(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_TASK_MONITOR: return bc_redfish_get_task_monitor(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_PROBE: return bc_redfish_probe(endpoint, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_VIRTUAL_MEDIA: return bc_redfish_get_virtual_media(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_VIRTUAL_MEDIA_DISCOVERY: return bc_redfish_discover_virtual_media(endpoint, uri, &collections, typed_done, slot, &slot->typed);
    case BC_REDFISH_GRAPHICAL_CONSOLE: return bc_redfish_get_graphical_console(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_MANAGER_DISCOVERY: return bc_redfish_discover_managers(endpoint, &collections, typed_done, slot, &slot->typed);
    case BC_REDFISH_NETWORK_PROTOCOL: return bc_redfish_get_network_protocol(endpoint, uri, &options, typed_done, slot, &slot->typed);
    case BC_REDFISH_ETHERNET_DISCOVERY: return bc_redfish_discover_ethernet(endpoint, uri, &collections, typed_done, slot, &slot->typed);
    case BC_REDFISH_ETHERNET_INTERFACE: return bc_redfish_get_ethernet_interface(endpoint, uri, &options, typed_done, slot, &slot->typed);
    default: return BC_UNSUPPORTED;
    }
}
static void media_removed_done(bc_redfish_operation *operation, const bc_redfish_result *result, void *userdata) {
    device_slot *slot = userdata; job *j = slot->pending;
    const bc_redfish_virtual_media_info *info = bc_redfish_virtual_media_info_get(operation);
    bc_status status = result->status;
    if (status == BC_OK && (!info || !(info->flags & BC_REDFISH_VM_INSERTED_PRESENT) || info->inserted || info->image.length))
        status = BC_OUTCOME_UNKNOWN;
    if (status == BC_OK) {
        clear_media(slot);
    }
    if (j->kind == CLOSE) j->media_cleanup_status = status;
    j->status = status; j->ready = 1;
}
static void close_media_done(bc_redfish_operation *operation, const bc_redfish_result *result, void *userdata) {
    (void)operation; device_slot *slot = userdata; job *j = slot->pending;
    j->media_cleanup_status = result->status;
    j->verify_media = result->status == BC_OK;
    j->status = result->status; j->ready = 1;
}
static uint32_t media_remaining(const job *j) {
    uint64_t now = bc_agent_now_ms();
    return j->media_deadline > now ? (uint32_t)(j->media_deadline - now) : 0;
}
static void manual_eject_read_done(bc_redfish_operation *operation, const bc_redfish_result *result, void *userdata) {
    device_slot *slot = userdata; job *j = slot->pending;
    j->status = result->status; j->ready = 1;
    if (result->status != BC_OK) return;
    const bc_redfish_virtual_media_info *info = bc_redfish_virtual_media_info_get(operation);
    if (info && (info->flags & BC_REDFISH_VM_INSERTED_PRESENT) && !info->inserted && !info->image.length) clear_media(slot);
    else j->submit_manual_eject = 1;
}
static bc_status start(bc_device_service *s, device_slot *slot, job *j) {
    j->started = 1;
    if (j->kind == CONNECT) {
        bc_status status = bc_curl_transport_create(&slot->transport);
        bc_context_options options = {sizeof(options), BC_ABI_VERSION, slot->transport, 1024u * 1024u, 1, 0};
        if (status == BC_OK) status = bc_context_create(&options, &slot->context);
        if (status == BC_OK) status = bc_endpoint_create(slot->context, &s->endpoint, &slot->base);
        bc_redfish_login_options login = {sizeof(login), BC_ABI_VERSION, j->mode, 5000, s->endpoint.username, s->endpoint.password};
        if (status == BC_OK) status = bc_redfish_login(slot->base, &login, auth_done, slot, &slot->auth);
        return status;
    }
    if (j->kind == CLOSE) {
        if (!slot->connection) { j->ready = 1; return BC_OK; }
        if (slot->media_uri && !slot->remote_media) {
            bc_redfish_options media_options = {sizeof(media_options), BC_ABI_VERSION, 5000, 0};
            bc_status status = bc_redfish_virtual_media_eject(bc_redfish_connection_endpoint(slot->connection),
                text(slot->media_uri), &media_options, close_media_done, slot, &slot->typed);
            if (status == BC_OK) { j->close_after_media = 1; return BC_OK; }
            j->media_cleanup_status = status;
        }
        if (bc_redfish_connection_info_get(slot->connection)->mode == BC_REDFISH_LOGIN_BASIC) { j->ready = 1; return BC_OK; }
        return bc_redfish_logout(slot->connection, 5000, auth_done, slot, &slot->auth);
    }
    if (j->kind == MEDIA_MAP) {
        if (!slot->connection || (!j->direct_media && !(j->browser_source ? s->hooks.media_add_source != NULL : s->hooks.media_add != NULL))) return BC_UNSUPPORTED;
        if (!j->direct_media && bc_remote_media_registry_can_mount(s->remote_media, text(j->path)) != BC_OK) return BC_BUSY;
        if (j->direct_media) {
            bc_status held = bc_remote_media_registry_begin(s->remote_media, text(slot->owner), text(slot->id), text(j->path));
            if (held != BC_OK) return held;
            slot->remote_media = 1;
        }
        if (!j->direct_media) {
            uint64_t size = 0;
            int added = j->browser_source ? s->hooks.media_add_source(s->hooks.userdata, slot->owner, j->file, j->token, j->url, sizeof(j->url), &size) :
                s->hooks.media_add(s->hooks.userdata, j->file, j->token, j->url, sizeof(j->url), &size);
            if (!added) return BC_UNSUPPORTED;
            memcpy(slot->media_token, j->token, sizeof(slot->media_token));
        }
        bc_redfish_virtual_media_insert_options insert = {0};
        insert.struct_size = sizeof(insert);
        insert.image = text(j->direct_media ? j->file : j->url);
        if (j->transfer_method) insert.transfer_method = text(j->transfer_method);
        if (j->transfer_protocol) insert.transfer_protocol_type = text(j->transfer_protocol);
        if (j->write_protected) { insert.flags = BC_REDFISH_VM_WRITE_PROTECTED_SET; insert.write_protected = 1; }
        bc_redfish_options media_options = {sizeof(media_options), BC_ABI_VERSION, 5000, 0};
        bc_status status = bc_redfish_virtual_media_insert(bc_redfish_connection_endpoint(slot->connection),
            text(j->path), &insert, &media_options, media_done, slot, &slot->typed);
        if (status != BC_OK && j->direct_media) {
            bc_remote_media_registry_clear(s->remote_media, text(slot->id)); slot->remote_media = 0;
        }
        if (status != BC_OK && s->hooks.media_remove) s->hooks.media_remove(s->hooks.userdata, slot->media_token);
        return status;
    }
    if (j->kind == MEDIA_UNMAP) {
        j->media_deadline = bc_agent_now_ms() + 5000;
        if (!slot->connection) return BC_UNSUPPORTED;
        if (j->path && slot->media_uri && strcmp(j->path, slot->media_uri)) return BC_BUSY;
        if (!slot->media_uri && j->path) {
            int occupied = 0;
            mg_lock_context(s->http);
            for (unsigned i = 0; i < CONNECTION_LIMIT; ++i) {
                device_slot *other = &s->slots[i];
                if (other == slot || !other->used) continue;
                const char *uri = other->media_uri;
                if (!uri && other->pending && other->pending->kind == MEDIA_MAP) uri = other->pending->path;
                if (uri && !strcmp(uri, j->path)) { occupied = 1; break; }
            }
            mg_unlock_context(s->http);
            if (occupied) return BC_BUSY;
            char *uri = malloc(strlen(j->path) + 1);
            if (!uri) return BC_NO_MEMORY;
            strcpy(uri, j->path);
            bc_status claimed = bc_remote_media_registry_claim_eject(s->remote_media, text(slot->owner), text(slot->id), text(uri));
            if (claimed != BC_OK) { free(uri); return claimed; }
            slot->media_uri = uri; slot->remote_media = 1;
            bc_redfish_options read_options = {sizeof(read_options), BC_ABI_VERSION, media_remaining(j), 0};
            return bc_redfish_get_virtual_media(bc_redfish_connection_endpoint(slot->connection),
                text(slot->media_uri), &read_options, manual_eject_read_done, slot, &slot->typed);
        }
        if (!slot->media_uri) return BC_UNSUPPORTED;
        bc_redfish_options media_options = {sizeof(media_options), BC_ABI_VERSION, 5000, 0};
        return bc_redfish_virtual_media_eject(bc_redfish_connection_endpoint(slot->connection),
            text(slot->media_uri), &media_options, media_done, slot, &slot->typed);
    }
    if (j->kind == QUERY || j->kind == RESET || j->kind == BOOT_ONCE) return typed_start(slot, j);
    bc_http_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = text(j->path); options.timeout_ms = 5000;
    options.method = j->method;
    options.body = (bc_bytes){(const unsigned char *)j->body, j->body_length};
    return bc_http_submit(bc_redfish_connection_endpoint(slot->connection), &options, read_done, slot, &slot->request);
}
static void dispose(bc_device_service *s, device_slot *slot) {
    bc_remote_media_registry_release(s->remote_media, text(slot->id));
    if (slot->media_token[0]) {
        if (s->hooks.media_remove) s->hooks.media_remove(s->hooks.userdata, slot->media_token);
        OPENSSL_cleanse(slot->media_token, sizeof(slot->media_token));
    }
    free(slot->media_uri); slot->media_uri = NULL;
    if (slot->context) { bc_context_shutdown(slot->context); bc_context_poll(slot->context, 0); }
    bc_request_release(slot->request); slot->request = NULL;
    bc_redfish_release(slot->typed); slot->typed = NULL;
    bc_redfish_auth_release(slot->auth); slot->auth = NULL;
    bc_redfish_connection_release(slot->connection); slot->connection = NULL;
    bc_endpoint_release(slot->base); slot->base = NULL;
    if (slot->context) bc_context_destroy(slot->context);
    if (slot->transport) bc_curl_transport_destroy(slot->transport);
    slot->context = NULL; slot->transport = NULL;
}
bc_device_service *bc_device_service_create(struct mg_context *http, const bc_endpoint_options *endpoint, const bc_device_hooks *hooks) {
    bc_device_service *s = calloc(1, sizeof(*s));
    if (s) {
        s->http = http; s->endpoint = *endpoint; s->hooks = *hooks;
        if (bc_remote_media_registry_create(CONNECTION_LIMIT, &s->remote_media) != BC_OK) { free(s); return NULL; }
    }
    return s;
}
void bc_device_service_tick(bc_device_service *s) {
    for (unsigned i = 0; i < CONNECTION_LIMIT; ++i) {
        device_slot *slot = &s->slots[i];
        mg_lock_context(s->http);
        int active = slot->used && !s->stopping && s->hooks.client_active_locked(s->hooks.userdata, slot->owner);
        if (active && slot->media_source_id[0] && s->hooks.media_source_active_locked &&
            !s->hooks.media_source_active_locked(s->hooks.userdata, slot->owner, slot->media_source_id)) active = 0;
        if (slot->used && !slot->pending && !active) {
            slot->cleanup = (job){0}; slot->cleanup.kind = CLOSE; slot->cleanup.internal = 1;
            slot->pending = &slot->cleanup; slot->state = BC_REDFISH_CONNECTION_CLOSING;
        }
        job *j = slot->pending;
        mg_unlock_context(s->http);
        if (!j) continue;
        if (!j->started) {
            if (!active && !j->internal && j->kind != CLOSE) { j->status = BC_CANCELLED; j->ready = 1; }
            else { j->status = start(s, slot, j); if (j->status != BC_OK) j->ready = 1; }
        }
        if (slot->context && !j->ready) {
            if (!active && j->kind != CLOSE) {
                if (slot->request) bc_request_cancel(slot->request);
                if (slot->typed) bc_redfish_cancel(slot->typed);
            }
            bc_status status = bc_context_poll(slot->context, 0);
            if (status != BC_OK) { bc_context_shutdown(slot->context); bc_context_poll(slot->context, 0); j->status = status; j->ready = 1; j->fatal = 1; }
        }
        if (!j->ready) continue;
        if (j->kind == MEDIA_MAP && j->status != BC_OK && !slot->media_uri && slot->media_token[0]) {
            if (s->hooks.media_remove) s->hooks.media_remove(s->hooks.userdata, slot->media_token);
            OPENSSL_cleanse(slot->media_token, sizeof(slot->media_token));
        }
        bc_request_release(slot->request); slot->request = NULL;
        bc_redfish_release(slot->typed); slot->typed = NULL;
        bc_redfish_auth_release(slot->auth); slot->auth = NULL;
        if (j->submit_manual_eject) {
            j->submit_manual_eject = 0; j->ready = 0;
            uint32_t remaining = media_remaining(j);
            bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, remaining, 0};
            bc_status status = !active ? BC_CANCELLED : remaining ? bc_redfish_virtual_media_eject(bc_redfish_connection_endpoint(slot->connection),
                text(slot->media_uri), &options, media_done, slot, &slot->typed) : BC_TIMEOUT;
            if (status == BC_OK) continue;
            j->status = status; j->ready = 1;
        }
        if (j->verify_media) {
            j->verify_media = 0; j->ready = 0;
            uint32_t remaining = j->kind == MEDIA_UNMAP ? media_remaining(j) : 5000;
            bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, remaining, 0};
            bc_status status = remaining ? bc_redfish_get_virtual_media(bc_redfish_connection_endpoint(slot->connection),
                text(slot->media_uri), &options, media_removed_done, slot, &slot->typed) : BC_TIMEOUT;
            if (status == BC_OK) continue;
            j->status = status; j->ready = 1;
            if (j->kind == CLOSE) j->media_cleanup_status = status;
        }
        if (j->kind == CLOSE && j->close_after_media) {
            j->close_after_media = 0; j->ready = 0;
            if (slot->connection && bc_redfish_connection_info_get(slot->connection)->mode != BC_REDFISH_LOGIN_BASIC) {
                bc_status logout = bc_redfish_logout(slot->connection, 5000, auth_done, slot, &slot->auth);
                if (logout == BC_OK) continue;
                j->status = logout;
            }
            j->ready = 1;
        }
        if (j->kind == CLOSE && j->media_cleanup_status != BC_OK) {
            if (!j->internal) yyjson_mut_obj_add_str(j->doc, yyjson_mut_doc_get_root(j->doc),
                "media_cleanup_status", bc_status_string(j->media_cleanup_status));
            if (j->status == BC_OK) j->status = j->media_cleanup_status;
        }
        if (!j->internal) {
            yyjson_mut_val *out = yyjson_mut_doc_get_root(j->doc);
            yyjson_mut_obj_add_str(j->doc, out, "status", bc_status_string(j->status));
            yyjson_mut_obj_add_strcpy(j->doc, out, "connection_id", slot->id);
            yyjson_mut_obj_add_strncpy(j->doc, out, "device_id", s->endpoint.device_id.data,
                                      (size_t)s->endpoint.device_id.length);
            if (slot->media_uri) yyjson_mut_obj_add_strcpy(j->doc, out, "managed_media_uri", slot->media_uri);
            else yyjson_mut_obj_add_null(j->doc, out, "managed_media_uri");
            yyjson_mut_obj_add_bool(j->doc, out, "remote_media_retained", slot->remote_media != 0);
            yyjson_mut_obj_add_bool(j->doc, out, "browser_media_available", s->hooks.media_source_available && s->hooks.media_source_available(s->hooks.userdata));
            if (slot->media_source_id[0]) yyjson_mut_obj_add_strcpy(j->doc, out, "media_source_id", slot->media_source_id);
        }
        int keep = slot->connection && j->kind != CLOSE && !j->fatal;
        if (!keep) dispose(s, slot);
        int internal = j->internal;
        mg_lock_context(s->http);
        slot->pending = NULL;
        if (!keep) memset(slot, 0, sizeof(*slot));
        else slot->state = BC_REDFISH_CONNECTION_OPEN;
        if (!internal) j->done = 1;
        mg_unlock_context(s->http);
    }
}
static int media_fields(yyjson_val *root) {
    if (!yyjson_is_obj(root)) return 0;
    unsigned seen = 0;
    size_t i, maximum; yyjson_val *key, *value;
    yyjson_obj_foreach(root, i, maximum, key, value) {
        (void)value;
        const char *name = yyjson_get_str(key);
        if (!name || strlen(name) != yyjson_get_len(key)) return 0;
        unsigned flag = !strcmp(name, "media_uri") ? 1u : !strcmp(name, "file") ? 2u :
            !strcmp(name, "image_url") ? 8u : !strcmp(name, "write_protected") ? 4u :
            !strcmp(name, "transfer_method") ? 16u : !strcmp(name, "transfer_protocol_type") ? 32u : !strcmp(name, "source_id") ? 64u : 0u;
        if (!flag || (seen & flag)) return 0;
        seen |= flag;
    }
    return (seen & 1u) && (seen & (2u | 8u | 64u));
}
static int request_fields(yyjson_val *root) {
    if (!yyjson_is_obj(root)) return 0;
    unsigned seen = 0;
    size_t i, maximum; yyjson_val *key, *value;
    yyjson_obj_foreach(root, i, maximum, key, value) {
        (void)value;
        const char *name = yyjson_get_str(key);
        if (!name || strlen(name) != yyjson_get_len(key)) return 0;
        unsigned flag = !strcmp(name, "path") ? 1u : !strcmp(name, "method") ? 2u : !strcmp(name, "body") ? 4u : 0u;
        if (!flag || (seen & flag)) return 0;
        seen |= flag;
    }
    return (seen & 1u) != 0;
}

static int error(struct mg_connection *c, bc_device_service *s, int status, const char *code) {
    return s->hooks.error(c, s->hooks.userdata, status, code);
}
static int wait_job(struct mg_connection *c, bc_device_service *s, job *j, const char *owner) {
    for (;;) {
        mg_lock_context(s->http); int done = j->done; mg_unlock_context(s->http);
        if (done) break;
        bc_agent_sleep(5);
    }
    char current[33]; int authorized = s->hooks.authorize(c, s->hooks.userdata, current) && !strcmp(current, owner);
    if (!authorized) { free_job(j); return error(c, s, 401, "client_revoked"); }
    yyjson_mut_doc *doc = j->doc; int http = j->http; j->doc = NULL; free_job(j);
    return s->hooks.json(c, s->hooks.userdata, http, doc);
}
static int parse_boot(yyjson_val *root, job *j) {
    if (!yyjson_is_obj(root)) return 0;
    size_t i, count; yyjson_val *key, *item;
    yyjson_obj_foreach(root, i, count, key, item) {
        const char *name = yyjson_get_str(key); (void)item;
        if (strcmp(name, "uri") && strcmp(name, "target") && strcmp(name, "mode")) return 0;
    }
    const char *uri = bc_agent_json_field(root, "uri", 8192), *target = bc_agent_json_field(root, "target", 32);
    const char *mode = bc_agent_json_field(root, "mode", 16);
    if (!uri || !bc_redfish_uri_supported(text(uri)) || !target || (yyjson_obj_get(root, "mode") && !mode)) return 0;
    const char *const names[] = {"none", "pxe", "disk", "cd", "setup", "usb", "uefi-shell"};
    j->selection = BC_BOOT_UNKNOWN;
    for (uint32_t n = 0; n < sizeof(names) / sizeof(names[0]); ++n) if (!strcmp(target, names[n])) j->selection = n;
    if (j->selection == BC_BOOT_UNKNOWN) return 0;
    if (!mode || !strcmp(mode, "preserve")) j->mode = BC_BOOT_MODE_PRESERVE;
    else if (!strcmp(mode, "legacy")) j->mode = BC_BOOT_MODE_LEGACY;
    else if (!strcmp(mode, "uefi")) j->mode = BC_BOOT_MODE_UEFI;
    else return 0;
    j->path = malloc(strlen(uri) + 1); if (!j->path) return 0;
    strcpy(j->path, uri); return 1;
}
static int parse_typed(yyjson_val *root, job *j) {
    const char *field = j->kind == RESET ? "action" : "operation";
    const char *value = bc_agent_json_field(root, field, 32);
    if (!value || !bc_agent_json_fields(root, field, "uri")) return 0;
    int found = 0, needs_uri = 1;
    if (j->kind == RESET) {
        for (uint32_t i = 0; bc_agent_reset_name(i); ++i)
            if (!strcmp(value, bc_agent_reset_name(i))) { j->selection = i; found = 1; break; }
    } else {
        static const struct { const char *name; uint32_t kind; } queries[] = {
            {"systems", BC_REDFISH_DISCOVERY}, {"system", BC_REDFISH_SYSTEM},
            {"boot", BC_REDFISH_BOOT}, {"reset-capabilities", BC_REDFISH_RESET_CAPABILITIES}, {"chassis", BC_REDFISH_CHASSIS_DISCOVERY},
            {"sensors", BC_REDFISH_SENSOR_DISCOVERY}, {"sensor", BC_REDFISH_SENSOR},
            {"sensor-details", BC_REDFISH_SENSOR_DETAILS},
            {"tasks", BC_REDFISH_TASK_DISCOVERY}, {"task", BC_REDFISH_TASK}, {"task-monitor", BC_REDFISH_TASK_MONITOR}, {"probe", BC_REDFISH_PROBE},
            {"virtual-media", BC_REDFISH_VIRTUAL_MEDIA_DISCOVERY}, {"virtual-media-info", BC_REDFISH_VIRTUAL_MEDIA}, {"graphical-console", BC_REDFISH_GRAPHICAL_CONSOLE},
            {"managers", BC_REDFISH_MANAGER_DISCOVERY}, {"network-protocol", BC_REDFISH_NETWORK_PROTOCOL},
            {"ethernet-interfaces", BC_REDFISH_ETHERNET_DISCOVERY}, {"ethernet-interface", BC_REDFISH_ETHERNET_INTERFACE}
        };
        for (size_t i = 0; i < sizeof(queries) / sizeof(queries[0]); ++i)
            if (!strcmp(value, queries[i].name)) { j->selection = queries[i].kind; found = 1; break; }
        needs_uri = j->selection != BC_REDFISH_DISCOVERY && j->selection != BC_REDFISH_CHASSIS_DISCOVERY &&
            j->selection != BC_REDFISH_PROBE && j->selection != BC_REDFISH_TASK_DISCOVERY &&
            j->selection != BC_REDFISH_MANAGER_DISCOVERY;
    }
    if (!found) return 0;
    if (!needs_uri) return !yyjson_obj_get(root, "uri");
    const char *uri = bc_agent_json_field(root, "uri", 8192);
    if (!uri || !bc_redfish_uri_supported(text(uri))) return 0;
    j->path = malloc(strlen(uri) + 1);
    if (!j->path) return 0;
    strcpy(j->path, uri); return 1;
}
int bc_device_service_http(bc_device_service *s, struct mg_connection *c, const char *path, const char *method) {
    const char prefix[] = "/v1/connections";
    if (strncmp(path, prefix, sizeof(prefix) - 1) || (path[sizeof(prefix) - 1] && path[sizeof(prefix) - 1] != '/')) return 0;
    char owner[33];
    if (!s->hooks.authorize(c, s->hooks.userdata, owner)) return error(c, s, 401, "client_revoked");
    const char *suffix = path + sizeof(prefix) - 1;
    int create = !*suffix && !strcmp(method, "POST");
    if (!*suffix && !strcmp(method, "GET")) {
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *rows = yyjson_mut_arr(doc); yyjson_mut_doc_set_root(doc, rows);
        const char *states[] = {"open", "closing", "closed", "opening"};
        mg_lock_context(s->http);
        int authorized = s->hooks.client_active_locked(s->hooks.userdata, owner);
        if (authorized) for (unsigned i = 0; i < CONNECTION_LIMIT; ++i) {
            device_slot *slot = &s->slots[i];
            if (!slot->used || strcmp(slot->owner, owner)) continue;
            yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_add_val(rows, row);
            yyjson_mut_obj_add_strcpy(doc, row, "connection_id", slot->id);
            yyjson_mut_obj_add_str(doc, row, "state", states[slot->state]);
            yyjson_mut_obj_add_bool(doc, row, "busy", slot->pending != NULL);
        }
        mg_unlock_context(s->http);
        if (!authorized) { yyjson_mut_doc_free(doc); return error(c, s, 401, "client_revoked"); }
        return s->hooks.json(c, s->hooks.userdata, 200, doc);
    }
    uint32_t kind = create ? CONNECT : CLOSE;
    char id[33] = {0};
    if (!create) {
        if (*suffix != '/' || strlen(suffix + 1) < 32) return error(c, s, 404, "not_found");
        memcpy(id, suffix + 1, 32); suffix += 33;
        if (!strcmp(suffix, "/request") && !strcmp(method, "POST")) kind = READ;
        else if (!strcmp(suffix, "/query") && !strcmp(method, "POST")) kind = QUERY;
        else if (!strcmp(suffix, "/boot") && !strcmp(method, "POST")) kind = BOOT_ONCE;
        else if (!strcmp(suffix, "/power") && !strcmp(method, "POST")) kind = RESET;
        else if (!strcmp(suffix, "/media") && !strcmp(method, "POST")) kind = MEDIA_MAP;
        else if (!strcmp(suffix, "/media") && !strcmp(method, "DELETE")) kind = MEDIA_UNMAP;
        else if (*suffix || strcmp(method, "DELETE")) return error(c, s, 404, "not_found");
    }
    job *j = new_job(kind);
    if (!j) return error(c, s, 500, "no_memory");
    if (kind == MEDIA_MAP) {
        yyjson_doc *doc = bc_agent_read_json(c); yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
        const char *uri = bc_agent_json_field(root, "media_uri", 8192);
        const char *file = bc_agent_json_field(root, "file", 4096);
        const char *image_url = bc_agent_json_field(root, "image_url", 8192);
        const char *source_id = bc_agent_json_field(root, "source_id", 32);
        const char *transfer_method = bc_agent_json_field(root, "transfer_method", 64);
        const char *transfer_protocol = bc_agent_json_field(root, "transfer_protocol_type", 64);
        int direct = image_url && *image_url;
        yyjson_val *protected_value = yyjson_obj_get(root, "write_protected");
        int valid = media_fields(root) && uri && bc_redfish_uri_supported(text(uri)) &&
            (unsigned)(yyjson_obj_get(root, "file") != NULL) + (unsigned)(yyjson_obj_get(root, "image_url") != NULL) + (unsigned)(yyjson_obj_get(root, "source_id") != NULL) == 1;
        if (valid && ((yyjson_obj_get(root, "file") && !file) || (yyjson_obj_get(root, "image_url") && !image_url) ||
                      (yyjson_obj_get(root, "source_id") && !source_id))) valid = 0;
        if (valid && image_url && !direct) valid = 0;
        if (valid && source_id) {
            if (strlen(source_id) != 32) valid = 0;
            else for (const char *p = source_id; *p; ++p) if (!(*p >= '0' && *p <= '9') && !(*p >= 'a' && *p <= 'f')) valid = 0;
        }
        if (valid && direct && !(strlen(image_url) > 8 &&
            (!strncmp(image_url, "http://", 7) || !strncmp(image_url, "https://", 8) ||
             !strncmp(image_url, "nfs://", 6) || !strncmp(image_url, "cifs://", 7) || !strncmp(image_url, "smb://", 6)))) valid = 0;
        if (valid && file && !*file) valid = 0;
        if (valid && ((transfer_method && !*transfer_method) || (transfer_protocol && !*transfer_protocol))) valid = 0;
        if (valid && protected_value && !yyjson_is_bool(protected_value)) valid = 0;
        if (valid) {
            const char *source = source_id ? source_id : direct ? image_url : file;
            j->path = malloc(strlen(uri) + 1); j->file = malloc(strlen(source) + 1);
            if (!j->path || !j->file) valid = 0;
            else { strcpy(j->path, uri); strcpy(j->file, source); }
            if (valid && transfer_method) {
                j->transfer_method = malloc(strlen(transfer_method) + 1);
                if (j->transfer_method) strcpy(j->transfer_method, transfer_method); else valid = 0;
            }
            if (valid && transfer_protocol) {
                j->transfer_protocol = malloc(strlen(transfer_protocol) + 1);
                if (j->transfer_protocol) strcpy(j->transfer_protocol, transfer_protocol); else valid = 0;
            }
            j->direct_media = direct;
            j->browser_source = source_id != NULL;
            j->write_protected = protected_value && yyjson_is_true(protected_value);
        }
        yyjson_doc_free(doc);
        if (!valid) { free_job(j); return error(c, s, 400, "invalid_media_request"); }
    } else if (kind == MEDIA_UNMAP && mg_get_request_info(c)->content_length > 0) {
        yyjson_doc *doc = bc_agent_read_json(c); yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
        const char *uri = bc_agent_json_field(root, "media_uri", 8192);
        int valid = bc_agent_json_fields(root, "media_uri", NULL) && uri && bc_redfish_uri_supported(text(uri));
        if (valid) {
            j->path = malloc(strlen(uri) + 1);
            if (j->path) strcpy(j->path, uri); else valid = 0;
        }
        yyjson_doc_free(doc);
        if (!valid) { free_job(j); return error(c, s, 400, "invalid_media_request"); }
    } else if (kind != CLOSE && kind != MEDIA_UNMAP) {
        yyjson_doc *doc = bc_agent_read_json(c); yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
        const char *key = create ? "mode" : "path";
        const char *value = bc_agent_json_field(root, key, create ? 16 : 8192);
        int valid = 0;
        if (kind == BOOT_ONCE) valid = parse_boot(root, j);
        else if (kind == QUERY || kind == RESET) valid = parse_typed(root, j);
        else valid = value && (kind == READ ? request_fields(root) : bc_agent_json_fields(root, key, "device_id"));
        if (valid && create) {
            yyjson_val *device_value = yyjson_obj_get(root, "device_id");
            const char *device = bc_agent_json_field(root, "device_id", 64);
            if (device_value && (!device || strlen(device) != s->endpoint.device_id.length ||
                memcmp(device, s->endpoint.device_id.data, (size_t)s->endpoint.device_id.length))) {
                yyjson_doc_free(doc); free_job(j);
                return error(c, s, 409, "device_association_mismatch");
            }
            if (!strcmp(value, "basic")) j->mode = BC_REDFISH_LOGIN_BASIC;
            else if (!strcmp(value, "session")) j->mode = BC_REDFISH_LOGIN_SESSION;
            else if (strcmp(value, "auto")) valid = 0;
        } else if (valid && kind == READ) {
            if (!bc_redfish_uri_supported(text(value))) valid = 0;
            else { j->path = malloc(strlen(value) + 1); if (j->path) strcpy(j->path, value); else valid = 0; }
            const char *method = bc_agent_json_field(root, "method", 16);
            if (valid && method) {
                if (!strcmp(method, "GET")) j->method = BC_HTTP_GET;
                else if (!strcmp(method, "POST")) j->method = BC_HTTP_POST;
                else if (!strcmp(method, "PATCH")) j->method = BC_HTTP_PATCH;
                else if (!strcmp(method, "DELETE")) j->method = BC_HTTP_DELETE;
                else valid = 0;
                size_t length = 0;
                char *body = NULL;
                yyjson_val *json_body = yyjson_obj_get(root, "body");
                if (valid && json_body) body = yyjson_val_write(json_body, 0, &length);
                if (valid && length > BC_REDFISH_MAX_BODY) valid = 0;
                if (valid && json_body && !body) valid = 0;
                if (valid) { j->body = body; j->body_length = (uint32_t)length; }
                else free(body);
                if (valid && j->method == BC_HTTP_GET && j->body_length) valid = 0;
                if (valid && j->method == BC_HTTP_PATCH && !j->body_length) valid = 0;
            }
        }
        yyjson_doc_free(doc);
        if (!valid) { free_job(j); return error(c, s, 400, "invalid_connection_request"); }
    }
    if (create && !s->endpoint.origin.length) { free_job(j); return error(c, s, 409, "no_device_configured"); }
    if (create && !random_id(id)) { free_job(j); return error(c, s, 500, "random_source_failed"); }
    int result = create ? 409 : 404;
    mg_lock_context(s->http);
    if (s->stopping) result = 503;
    else if (!s->hooks.client_active_locked(s->hooks.userdata, owner)) result = 401;
    else for (unsigned i = 0; i < CONNECTION_LIMIT; ++i) {
        device_slot *slot = &s->slots[i];
        if (create ? slot->used : !slot->used || strcmp(slot->id, id) || strcmp(slot->owner, owner)) continue;
        if (slot->pending || (kind == MEDIA_MAP && slot->media_uri)) { result = 409; break; }
        if (kind == MEDIA_UNMAP && !slot->media_uri && !j->path) { result = 404; break; }
        if (create) { slot->used = 1; slot->state = 3; memcpy(slot->id, id, 33); memcpy(slot->owner, owner, 33); slot->service = s; }
        else if (kind == CLOSE) slot->state = BC_REDFISH_CONNECTION_CLOSING;
        slot->pending = j; result = 0; break;
    }
    mg_unlock_context(s->http);
    if (result) { free_job(j); return error(c, s, result, result == 401 ? "client_revoked" : result == 503 ? "shutting_down" : result == 404 ? "not_found" : "connection_busy_or_limit"); }
    return wait_job(c, s, j, owner);
}
void bc_device_service_shutdown(bc_device_service *s) {
    if (!s) return;
    mg_lock_context(s->http); s->stopping = 1; mg_unlock_context(s->http);
    for (;;) {
        bc_device_service_tick(s);
        int remaining = 0;
        mg_lock_context(s->http);
        for (unsigned i = 0; i < CONNECTION_LIMIT; ++i) remaining += s->slots[i].used;
        mg_unlock_context(s->http);
        if (!remaining) break;
        bc_agent_sleep(5);
    }
}
void bc_device_service_destroy(bc_device_service *s) {
    if (s) bc_remote_media_registry_destroy(s->remote_media);
    free(s);
}

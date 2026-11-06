#include "server.h"
#include "media_service.h"
#include "media_pull.h"
#include "kvm_service.h"
#include "bcontrol/kvm_transport.h"
#include "device_service.h"
#include "bcontrol/bcontrol.h"
#include "bcontrol/transport.h"
#include "bcontrol/redfish.h"
#include "civetweb.h"
#include "yyjson.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define CLIENT_LIMIT 32
#define BODY_LIMIT 32768
#define PAIR_TTL_MS UINT64_C(300000)
typedef struct { int active; char id[33], name[121]; unsigned char digest[32]; } client;
typedef struct {
    struct mg_context *http;
    client clients[CLIENT_LIMIT];
    unsigned char pairing_digest[32];
    char pairing_owner[33];
    uint64_t pairing_expires;
    int pairing_active;
    const char *origin, *pairing_file;
    bc_endpoint_options endpoint;
    bc_media_service *media;
    bc_device_service *devices;
    bc_media_pull *pull;
    bc_kvm_service *kvm;
} server;
static volatile sig_atomic_t stopped;
static void stop_signal(int number) { (void)number; stopped = 1; }
static bc_string text(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
static int digest(const char *value, unsigned char out[32]) {
    unsigned length = 0;
    return EVP_Digest(value, strlen(value), out, &length, EVP_sha256(), NULL) && length == 32;
}
static int random_hex(char *out, size_t bytes) {
    unsigned char data[32]; const char *hex = "0123456789abcdef";
    if (bytes > sizeof(data) || RAND_bytes(data, (int)bytes) != 1) return 0;
    for (size_t i = 0; i < bytes; ++i) { out[2*i] = hex[data[i] >> 4]; out[2*i+1] = hex[data[i] & 15]; }
    out[2*bytes] = 0; OPENSSL_cleanse(data, sizeof(data)); return 1;
}
static int quiet_log(const struct mg_connection *c, const char *message) { (void)c; (void)message; return 1; }
static int origin_allowed(const struct mg_connection *c, const server *s) {
    const char *origin = mg_get_header(c, "Origin");
    return !origin || (s->origin && !strcmp(origin, s->origin));
}
static int send_json(struct mg_connection *c, const server *s, int status, yyjson_mut_doc *doc) {
    size_t length = 0;
    char *json = doc ? yyjson_mut_write(doc, 0, &length) : NULL;
    if (!json) { status = 500; json = NULL; length = 2; }
    const char *origin = mg_get_header(c, "Origin");
    mg_printf(c, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %" PRIu64 "\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n", status, mg_get_response_code_text(c, status), (uint64_t)length);
    if (origin && s->origin && !strcmp(origin, s->origin))
        mg_printf(c, "Access-Control-Allow-Origin: %s\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n", origin);
    mg_printf(c, "\r\n"); mg_write(c, json ? json : "{}", length); free(json);
    if (doc) yyjson_mut_doc_free(doc);
    return status;
}
static int error_json(struct mg_connection *c, server *s, int status, const char *code) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "error", code);
    return send_json(c, s, status, doc);
}
yyjson_doc *bc_agent_read_json(struct mg_connection *c) {
    const struct mg_request_info *ri = mg_get_request_info(c);
    const char *type = mg_get_header(c, "Content-Type");
    if (!type || (strcmp(type, "application/json") && strncmp(type, "application/json;", 17)) ||
        mg_get_header(c, "Transfer-Encoding") || ri->content_length <= 0 || ri->content_length > BODY_LIMIT) return NULL;
    size_t size = (size_t)ri->content_length, received = 0;
    char *body = malloc(size);
    if (!body) return NULL;
    while (received < size) {
        int n = mg_read(c, body + received, size - received);
        if (n <= 0) { free(body); return NULL; }
        received += (size_t)n;
    }
    yyjson_doc *doc = yyjson_read(body, size, 0);
    OPENSSL_cleanse(body, size); free(body);
    if (doc && !yyjson_is_obj(yyjson_doc_get_root(doc))) { yyjson_doc_free(doc); return NULL; }
    return doc;
}
const char *bc_agent_json_field(yyjson_val *root, const char *name, size_t maximum) {
    yyjson_val *v = yyjson_obj_get(root, name);
    const char *value = yyjson_get_str(v);
    return value && yyjson_get_len(v) <= maximum && strlen(value) == yyjson_get_len(v) ? value : NULL;
}
int bc_agent_json_fields(yyjson_val *root, const char *one, const char *two) {
    size_t i, maximum; yyjson_val *key, *value; unsigned seen = 0;
    yyjson_obj_foreach(root, i, maximum, key, value) {
        (void)value;
        const char *k = yyjson_get_str(key);
        if (strlen(k) != yyjson_get_len(key)) return 0;
        unsigned flag = !strcmp(k, one) ? 1 : two && !strcmp(k, two) ? 2 : 0;
        if (!flag || (seen & flag)) return 0;
        seen |= flag;
    }
    return (seen & 1) != 0;
}
static int find_client_locked(server *s, const char *token) {
    if (!token || strlen(token) != 64) return -1;
    unsigned char hash[32];
    if (!digest(token, hash)) return -1;
    int found = -1;
    for (int i = 0; i < CLIENT_LIMIT; ++i)
        if (!CRYPTO_memcmp(hash, s->clients[i].digest, 32) && s->clients[i].active) found = i;
    OPENSSL_cleanse(hash, sizeof(hash)); return found;
}
static int authenticate(struct mg_connection *c, server *s) {
    const char *header = mg_get_header(c, "Authorization");
    if (!header || strncmp(header, "Bearer ", 7)) return -1;
    mg_lock_context(mg_get_context(c)); int id = find_client_locked(s, header + 7); mg_unlock_context(mg_get_context(c));
    return id;
}
static int issue_pairing(server *s, char secret[65], const char *owner) {
    if (!random_hex(secret, 32) || !digest(secret, s->pairing_digest)) return 0;
    if (owner) memcpy(s->pairing_owner, owner, 33); else memset(s->pairing_owner, 0, 33);
    s->pairing_active = 1; s->pairing_expires = bc_agent_now_ms() + PAIR_TTL_MS; return 1;
}
static int pair(struct mg_connection *c, server *s, yyjson_val *root) {
    const char *secret = bc_agent_json_field(root, "secret", 64), *name = bc_agent_json_field(root, "name", 120);
    if (!bc_agent_json_fields(root, "secret", "name") || !secret || strlen(secret) != 64 || !name || !*name)
        return error_json(c, s, 400, "invalid_pairing_request");
    char token[65] = {0}, id[33] = {0}; unsigned char hash[32];
    if (!digest(secret, hash) || !random_hex(token, 32) || !random_hex(id, 16)) return error_json(c, s, 500, "random_source_failed");
    int slot = -1, accepted = 0;
    mg_lock_context(mg_get_context(c));
    int issuer_active = !s->pairing_owner[0];
    for (int i = 0; i < CLIENT_LIMIT; ++i) if (s->clients[i].active && !strcmp(s->clients[i].id, s->pairing_owner)) issuer_active = 1;
    if (issuer_active && s->pairing_active && bc_agent_now_ms() < s->pairing_expires && !CRYPTO_memcmp(hash, s->pairing_digest, 32)) {
        accepted = 1;
        for (int i = 0; i < CLIENT_LIMIT; ++i) if (!s->clients[i].active) { slot = i; break; }
        if (slot >= 0) {
            client *cl = &s->clients[slot];
            if (!digest(token, cl->digest)) slot = -1;
            else {
                memcpy(cl->id, id, sizeof(id)); snprintf(cl->name, sizeof(cl->name), "%s", name); cl->active = 1;
                s->pairing_active = 0; OPENSSL_cleanse(s->pairing_digest, 32);
            }
        }
    }
    mg_unlock_context(mg_get_context(c)); OPENSSL_cleanse(hash, sizeof(hash));
    if (slot < 0) { OPENSSL_cleanse(token, sizeof(token)); return error_json(c, s, accepted ? 409 : 401, accepted ? "client_limit" : "pairing_rejected"); }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *out = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, out);
    yyjson_mut_obj_add_strcpy(doc, out, "client_id", id); yyjson_mut_obj_add_strcpy(doc, out, "token", token);
    OPENSSL_cleanse(token, sizeof(token)); return send_json(c, s, 201, doc);
}
typedef struct { int done; bc_response response; yyjson_mut_doc *doc; yyjson_mut_val *out; } device_result;
static void device_done(bc_request *request, const bc_response *r, void *userdata) {
    (void)request; device_result *result = userdata; result->done = 1; result->response = *r;
    yyjson_mut_doc *doc = result->doc; yyjson_mut_val *out = result->out;
    yyjson_mut_obj_add_str(doc, out, "status", bc_status_string(r->status));
    yyjson_mut_obj_add_uint(doc, out, "http_status", r->http_status);
    yyjson_mut_obj_add_uint(doc, out, "cert_policy", r->cert_policy);
    yyjson_mut_obj_add_bool(doc, out, "peer_verified", r->peer_verified != 0);
    yyjson_mut_obj_add_strncpy(doc, out, "tls_version", r->tls_version.data ? r->tls_version.data : "", (size_t)r->tls_version.length);
    if (r->body.length) {
        yyjson_doc *body = yyjson_read((const char *)r->body.data, (size_t)r->body.length, 0);
        if (body) { yyjson_mut_obj_add_val(doc, out, "body", yyjson_val_mut_copy(doc, yyjson_doc_get_root(body))); yyjson_doc_free(body); }
        else yyjson_mut_obj_add_str(doc, out, "body_format", "non_json");
    }
}
static int device_get(struct mg_connection *c, server *s, yyjson_val *root) {
    const char *path = bc_agent_json_field(root, "path", 8192);
    if (!bc_agent_json_fields(root, "path", NULL) || !path || !bc_redfish_uri_supported(text(path))) return error_json(c, s, 400, "invalid_resource_path");
    if (!s->endpoint.origin.length) return error_json(c, s, 409, "no_device_configured");
    bc_transport *t = NULL; bc_context *context = NULL; bc_endpoint *endpoint = NULL; bc_request *r = NULL;
    bc_status status = bc_curl_transport_create(&t);
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, t, 1024u * 1024u, 1, 0};
    if (status == BC_OK) status = bc_context_create(&co, &context);
    if (status == BC_OK) status = bc_endpoint_create(context, &s->endpoint, &endpoint);
    device_result result = {0}; result.doc = yyjson_mut_doc_new(NULL); result.out = yyjson_mut_obj(result.doc); yyjson_mut_doc_set_root(result.doc, result.out);
    bc_http_options request = {0}; request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION; request.path = text(path); request.timeout_ms = 5000;
    if (status == BC_OK) status = bc_http_submit(endpoint, &request, device_done, &result, &r);
    while (status == BC_OK && !result.done) status = bc_context_poll(context, 50);
    if (status != BC_OK && context) { bc_context_shutdown(context); bc_context_poll(context, 0); }
    if (r) bc_request_release(r);
    if (endpoint) bc_endpoint_release(endpoint);
    if (context) bc_context_destroy(context);
    if (t) bc_curl_transport_destroy(t);
    if (status != BC_OK) { yyjson_mut_doc_free(result.doc); return error_json(c, s, 502, bc_status_string(status)); }
    if (authenticate(c, s) < 0) { yyjson_mut_doc_free(result.doc); return error_json(c, s, 401, "client_revoked"); }
    return send_json(c, s, 200, result.doc);
}
static int headers_valid(const struct mg_request_info *ri) {
    const char *names[] = {"Authorization", "Origin", "Host", "Content-Length", "Content-Type"};
    for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); ++n) {
        int count = 0;
        for (int i = 0; i < ri->num_headers; ++i) if (!mg_strcasecmp(ri->http_headers[i].name, names[n])) ++count;
        if (count > 1) return 0;
    }
    return 1;
}
static int envelope_valid(const struct mg_connection *c) {
    const struct mg_request_info *ri = mg_get_request_info(c);
    char ip[64], name[64];
    snprintf(ip, sizeof(ip), "127.0.0.1:%d", ri->server_port);
    snprintf(name, sizeof(name), "localhost:%d", ri->server_port);
    const char *host = mg_get_header(c, "Host");
    int default_port = ri->server_port == (ri->is_ssl ? 443 : 80);
    return headers_valid(ri) && host && (!mg_strcasecmp(host, ip) || !mg_strcasecmp(host, name) ||
        (default_port && (!mg_strcasecmp(host, "localhost") || !strcmp(host, "127.0.0.1")))) && !ri->query_string &&
        ri->local_uri && !mg_get_header(c, "Transfer-Encoding");
}
static int media_allowed(const struct mg_connection *c, void *userdata) {
    return envelope_valid(c) && origin_allowed(c, userdata);
}
static int media_authorize(struct mg_connection *c, void *userdata, char id[33]) {
    server *s = userdata; const char *header = mg_get_header(c, "Authorization");
    if (!header || strncmp(header, "Bearer ", 7)) return 0;
    mg_lock_context(mg_get_context(c)); int slot = find_client_locked(s, header + 7);
    if (slot >= 0) memcpy(id, s->clients[slot].id, 33);
    mg_unlock_context(mg_get_context(c)); return slot >= 0;
}
static int media_client_active(void *userdata, const char *id) {
    server *s = userdata;
    for (int i = 0; i < CLIENT_LIMIT; ++i) if (s->clients[i].active && !strcmp(s->clients[i].id, id)) return 1;
    return 0;
}
static int media_json(struct mg_connection *c, void *s, int status, yyjson_mut_doc *doc) { return send_json(c, s, status, doc); }
static int media_error(struct mg_connection *c, void *s, int status, const char *code) { return error_json(c, s, status, code); }
static int pull_add(void *userdata, const char *path, char token[65], char *url, size_t capacity, uint64_t *size) {
    server *s = userdata;
    return s->pull ? bc_media_pull_add(s->pull, path, token, url, capacity, size) : 0;
}
static void pull_remove(void *userdata, const char *token) {
    server *s = userdata;
    if (s->pull) bc_media_pull_remove(s->pull, token);
}
static int pull_add_source(void *userdata, const char *owner, const char *id, char token[65], char *url, size_t capacity, uint64_t *size) {
    server *s = userdata;
    if (!s->pull) return 0;
    bc_media_source source = {0};
    if (bc_media_service_source_acquire(s->media, owner, id, &source) != BC_OK) return 0;
    if (!bc_media_pull_add_source(s->pull, &source, bc_media_service_source_release, token, url, capacity)) {
        bc_media_service_source_release(source.userdata); return 0;
    }
    if (size) *size = source.size;
    return 1;
}
static int pull_source_available(void *userdata) { return ((server *)userdata)->pull != NULL; }
static int pull_source_active_locked(void *userdata, const char *owner, const char *id) {
    return bc_media_service_source_active_locked(((server *)userdata)->media, owner, id);
}
static int media_bytes(struct mg_connection *c, void *userdata, const void *bytes, size_t size) {
    server *s = userdata; const char *origin = mg_get_header(c, "Origin");
    mg_printf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %" PRIu64 "\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n", (uint64_t)size);
    if (origin && s->origin && !strcmp(origin, s->origin)) mg_printf(c, "Access-Control-Allow-Origin: %s\r\nVary: Origin\r\n", origin);
    mg_printf(c, "\r\n"); mg_write(c, bytes, size); return 200;
}
static int handle(struct mg_connection *c, void *userdata) {
    server *s = userdata; const struct mg_request_info *ri = mg_get_request_info(c);
    const char *path = ri->local_uri, *method = ri->request_method;
    if (!envelope_valid(c))
        return error_json(c, s, 400, "invalid_request");
    if (!origin_allowed(c, s)) return error_json(c, s, 403, "origin_rejected");
    if (!strcmp(method, "OPTIONS")) return error_json(c, s, 200, "preflight");
    if (!strcmp(path, "/v1/health") && !strcmp(method, "GET")) {
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *out = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, out);
        yyjson_mut_obj_add_uint(doc, out, "api_version", 1); yyjson_mut_obj_add_str(doc, out, "mode", "personal");
        return send_json(c, s, 200, doc);
    }
    if (!strcmp(path, "/v1/pair") && !strcmp(method, "POST")) {
        yyjson_doc *doc = bc_agent_read_json(c);
        if (!doc) return error_json(c, s, 400, "invalid_json");
        int status = pair(c, s, yyjson_doc_get_root(doc)); yyjson_doc_free(doc); return status;
    }
    if (authenticate(c, s) < 0) return error_json(c, s, 401, "authentication_required");
    int device_status = bc_device_service_http(s->devices, c, path, method);
    if (device_status) return device_status;
    int media_status = bc_media_service_http(s->media, c, path, method);
    if (media_status) return media_status;
    int kvm_status = bc_kvm_service_http(s->kvm, c, path, method);
    if (kvm_status) return kvm_status;
    if (!strcmp(path, "/v1/pairing") && !strcmp(method, "POST")) {
        char secret[65]; mg_lock_context(mg_get_context(c));
        int caller = find_client_locked(s, mg_get_header(c, "Authorization") + 7);
        int ok = caller >= 0 && issue_pairing(s, secret, s->clients[caller].id);
        mg_unlock_context(mg_get_context(c));
        if (caller < 0) return error_json(c, s, 401, "client_revoked");
        if (!ok) return error_json(c, s, 500, "random_source_failed");
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *out = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, out);
        yyjson_mut_obj_add_strcpy(doc, out, "secret", secret); yyjson_mut_obj_add_uint(doc, out, "expires_in_ms", PAIR_TTL_MS);
        OPENSSL_cleanse(secret, sizeof(secret)); return send_json(c, s, 201, doc);
    }
    if (!strcmp(path, "/v1/clients") && !strcmp(method, "GET")) {
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *out = yyjson_mut_arr(doc); yyjson_mut_doc_set_root(doc, out);
        mg_lock_context(mg_get_context(c));
        if (find_client_locked(s, mg_get_header(c, "Authorization") + 7) < 0) {
            mg_unlock_context(mg_get_context(c)); yyjson_mut_doc_free(doc); return error_json(c, s, 401, "client_revoked");
        }
        for (int i = 0; i < CLIENT_LIMIT; ++i) if (s->clients[i].active) {
            yyjson_mut_val *row = yyjson_mut_obj(doc); yyjson_mut_arr_append(out, row);
            yyjson_mut_obj_add_strcpy(doc, row, "id", s->clients[i].id); yyjson_mut_obj_add_strcpy(doc, row, "name", s->clients[i].name);
        }
        mg_unlock_context(mg_get_context(c)); return send_json(c, s, 200, doc);
    }
    if (!strncmp(path, "/v1/clients/", 12) && strlen(path + 12) == 32 && !strcmp(method, "DELETE")) {
        int found = 0; mg_lock_context(mg_get_context(c));
        if (find_client_locked(s, mg_get_header(c, "Authorization") + 7) < 0) {
            mg_unlock_context(mg_get_context(c)); return error_json(c, s, 401, "client_revoked");
        }
        for (int i = 0; i < CLIENT_LIMIT; ++i) if (s->clients[i].active && !strcmp(s->clients[i].id, path + 12)) {
            OPENSSL_cleanse(&s->clients[i], sizeof(client)); found = 1;
        }
        mg_unlock_context(mg_get_context(c)); return error_json(c, s, found ? 200 : 404, found ? "revoked" : "not_found");
    }
    if (!strcmp(path, "/v1/request") && !strcmp(method, "POST")) {
        yyjson_doc *doc = bc_agent_read_json(c);
        if (!doc) return error_json(c, s, 400, "invalid_json");
        int status = device_get(c, s, yyjson_doc_get_root(doc)); yyjson_doc_free(doc); return status;
    }
    return error_json(c, s, 404, "not_found");
}
static int parse_version(const char *value, uint32_t *out) {
    if (strlen(value) != 3 || value[0] != '1' || value[1] != '.' || value[2] < '0' || value[2] > '3') return 0;
    *out = (uint32_t)(10 + value[2] - '0'); return 1;
}
int bc_agent_serve(int argc, char **argv) {
    server state = {0}; const char *pem = NULL, *media_listen = NULL, *media_advertise = NULL; unsigned long port = 8445;
    const char *device_id = NULL, *kvm_device_id = NULL;
    bc_string kvm_headers[8]; uint32_t kvm_header_count = 0;
    bc_agent_kvm_options kvm_options = {0}; kvm_options.cert_policy = BC_CERT_STRICT;
    state.endpoint.struct_size = sizeof(state.endpoint); state.endpoint.abi_version = BC_ABI_VERSION;
    state.endpoint.device_id = text("default"); state.endpoint.endpoint_id = text("redfish");
    state.endpoint.username = text(getenv("BC_BMC_USERNAME")); state.endpoint.password = text(getenv("BC_BMC_PASSWORD"));
    for (int i = 1; i < argc; ++i) {
        if (i + 1 >= argc) goto usage;
        const char *option = argv[i], *value = argv[++i];
        if (!strcmp(option, "--port")) { char *end; port = strtoul(value, &end, 10); if (!*value || *end || port < 1 || port > 65535) goto usage; }
        else if (!strcmp(option, "--pairing-file")) state.pairing_file = value;
        else if (!strcmp(option, "--origin")) state.origin = value;
        else if (!strcmp(option, "--tls-pem")) pem = value;
        else if (!strcmp(option, "--media-listen")) media_listen = value;
        else if (!strcmp(option, "--media-advertise")) media_advertise = value;
        else if (!strcmp(option, "--device-id")) device_id = value;
        else if (!strcmp(option, "--kvm-device-id")) kvm_device_id = value;
        else if (!strcmp(option, "--kvm-url")) kvm_options.url = value;
        else if (!strcmp(option, "--kvm-ca")) kvm_options.ca_file = value;
        else if (!strcmp(option, "--kvm-header")) {
            if (kvm_header_count >= 8 || strlen(value) > 2048) goto usage;
            kvm_headers[kvm_header_count++] = text(value);
        }
        else if (!strcmp(option, "--kvm-deflate")) kvm_options.flags |= BC_KVM_TRANSPORT_DEFLATE;
        else if (!strcmp(option, "--kvm-cert-policy")) {
            if (!strcmp(value, "strict")) kvm_options.cert_policy = BC_CERT_STRICT;
            else if (!strcmp(value, "skip-chain")) kvm_options.cert_policy = BC_CERT_SKIP_CHAIN;
            else if (!strcmp(value, "skip-all")) kvm_options.cert_policy = BC_CERT_SKIP_ALL;
            else goto usage;
        }
        else if (!strcmp(option, "--endpoint")) state.endpoint.origin = text(value);
        else if (!strcmp(option, "--ca")) state.endpoint.ca_file = text(value);
        else if (!strcmp(option, "--tls-min")) { if (!parse_version(value, &state.endpoint.tls_min)) goto usage; }
        else if (!strcmp(option, "--tls-max")) { if (!parse_version(value, &state.endpoint.tls_max)) goto usage; }
        else if (!strcmp(option, "--cert-policy")) {
            if (!strcmp(value, "strict")) state.endpoint.cert_policy = BC_CERT_STRICT;
            else if (!strcmp(value, "skip-chain")) state.endpoint.cert_policy = BC_CERT_SKIP_CHAIN;
            else if (!strcmp(value, "skip-all")) state.endpoint.cert_policy = BC_CERT_SKIP_ALL;
            else goto usage;
        } else goto usage;
    }
    if (device_id) {
        size_t length = strlen(device_id);
        if (!length || length > 64) goto usage;
        for (const char *p = device_id; *p; ++p)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.')) goto usage;
        state.endpoint.device_id = text(device_id);
    }
    if (kvm_device_id) {
        if (!device_id || strcmp(device_id, kvm_device_id) || !state.endpoint.origin.length ||
            !kvm_options.url || !*kvm_options.url) goto usage;
        kvm_options.management_device_id = device_id;
    }
    if (!state.pairing_file || !*state.pairing_file) goto usage;
    if (!!media_listen != !!media_advertise) goto usage;
    if (state.origin) {
        if (strncmp(state.origin, "https://", 8) && strncmp(state.origin, "http://", 7)) goto usage;
        for (const char *p = state.origin; *p; ++p) if ((unsigned char)*p <= 32 || (unsigned char)*p >= 127) goto usage;
    }
    char secret[65]; if (!issue_pairing(&state, secret, NULL)) return 1;
    if (!bc_agent_private_file(state.pairing_file, secret, 64)) {
        OPENSSL_cleanse(secret, sizeof(secret)); fputs("Cannot exclusively create private pairing file.\n", stderr); return 1;
    }
    OPENSSL_cleanse(secret, sizeof(secret));
    char listen[64]; snprintf(listen, sizeof(listen), "127.0.0.1:%lu%s", port, pem ? "s" : "");
    const char *options[] = {"listening_ports", listen, "num_threads", "16", "request_timeout_ms", "5000",
        "enable_keep_alive", "no", "decode_url", "no", "ssl_protocol_version", "4", NULL, NULL, NULL};
    if (pem) { options[12] = "ssl_certificate"; options[13] = pem; }
    struct mg_callbacks callbacks = {0}; callbacks.log_message = quiet_log;
    mg_init_library(MG_FEATURES_TLS);
    state.http = mg_start(&callbacks, &state, options);
    if (!state.http) { remove(state.pairing_file); mg_exit_library(); fputs("Agent listener failed.\n", stderr); return 1; }
    bc_media_hooks hooks = {&state, media_allowed, media_authorize, media_client_active, media_json, media_error, media_bytes};
    state.media = bc_media_service_create(state.http, &hooks);
    if (!state.media) { mg_stop(state.http); mg_exit_library(); remove(state.pairing_file); return 1; }
    bc_device_hooks device_hooks = {&state, media_authorize, media_client_active, media_json, media_error, pull_add, pull_remove, pull_add_source, pull_source_available, pull_source_active_locked};
    state.devices = bc_device_service_create(state.http, &state.endpoint, &device_hooks);
    if (!state.devices) { mg_stop(state.http); bc_media_service_destroy(state.media); mg_exit_library(); remove(state.pairing_file); return 1; }
    if (media_listen) {
        state.pull = bc_media_pull_create(media_listen, media_advertise);
        if (!state.pull) {
            mg_stop(state.http); bc_device_service_destroy(state.devices); bc_media_service_destroy(state.media);
            mg_exit_library(); remove(state.pairing_file); fputs("Media listener failed.\n", stderr); return 1;
        }
    }
    if (kvm_options.url) {
        bc_kvm_hooks kvm_hooks = {&state, media_allowed, media_authorize, media_client_active, media_json, media_error};
        kvm_options.headers = kvm_headers; kvm_options.header_count = kvm_header_count;
        kvm_options.timeout_ms = 5000;
        state.kvm = bc_kvm_service_create(state.http, &kvm_hooks, &kvm_options);
        if (!state.kvm) {
            if (state.pull) bc_media_pull_destroy(state.pull);
            mg_stop(state.http); bc_device_service_destroy(state.devices); bc_media_service_destroy(state.media);
            mg_exit_library(); remove(state.pairing_file); fputs("KVM proxy failed.\n", stderr); return 1;
        }
    }
    mg_set_request_handler(state.http, "/", handle, &state);
    signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal);
    printf("{\"port\":%lu,\"tls\":%s,\"mode\":\"personal\"}\n", port, pem ? "true" : "false"); fflush(stdout);
    while (!stopped) {
        bc_media_service_tick(state.media); bc_device_service_tick(state.devices);
        bc_kvm_service_tick(state.kvm);
        bc_agent_sleep(10);
    }
    bc_media_service_shutdown(state.media); bc_device_service_shutdown(state.devices);
    bc_kvm_service_shutdown(state.kvm);
    if (state.pull) bc_media_pull_destroy(state.pull);
    mg_stop(state.http);
    bc_kvm_service_destroy(state.kvm); bc_media_service_destroy(state.media); bc_device_service_destroy(state.devices);
    mg_exit_library(); remove(state.pairing_file); OPENSSL_cleanse(&state, sizeof(state)); return 0;
usage:
    fputs("bcontrol-agent serve --pairing-file NEW_FILE [--port 8445] [--origin WEB_ORIGIN] [--tls-pem PEM] "
        "[--endpoint BMC_ORIGIN] [--device-id ID] [--ca FILE] [--cert-policy MODE] [--tls-min VERSION] [--tls-max VERSION]"
        " [--media-listen ADDR:PORT --media-advertise http://HOST:PORT]"
        " [--kvm-url URL] [--kvm-device-id ID] [--kvm-header 'Name: Value'] [--kvm-ca FILE] [--kvm-cert-policy MODE] [--kvm-deflate]\n", stderr);
    return 2;
}

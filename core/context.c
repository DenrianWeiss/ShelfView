#include "bcontrol/bcontrol.h"
#include "bcontrol/transport.h"
#include "log_internal.h"
#include "endpoint_internal.h"
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct bc_context {
    bc_transport *transport;
    struct bc_request *requests;
    uint64_t max_response;
    uint64_t revision;
    uint32_t max_requests, active, endpoints, next_request;
    int shutdown, polling;
};
struct bc_endpoint {
    bc_context *context;
    bc_transport_endpoint_config config;
    bc_socks5_proxy proxy;
    void *backend;
    uint64_t revision;
    uint32_t refs, redfish_profile;
};
struct bc_request {
    bc_endpoint *endpoint;
    struct bc_request *next;
    bc_http_options options;
    bc_completion callback;
    void *userdata, *operation;
    bc_response response;
    bc_http_metadata metadata;
    bc_string auth_token;
    bc_string cookie_header;
    bc_string csrf_token;
    uint8_t *body;
    char error[256], tls[32], cipher[128];
    uint32_t refs, log_id;
    int done;
};

#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_ERROR
static const char *method_name(uint32_t method) {
    static const char *const names[] = {"GET", "POST", "PATCH", "DELETE"};
    return method < sizeof(names) / sizeof(names[0]) ? names[method] : "?";
}
#endif
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_ERROR
static const char *auth_name(const bc_endpoint *endpoint) {
    if (endpoint->config.auth_token.length) return "token";
    return endpoint->config.base.username.length ? "basic" : "none";
}
#endif

static int valid_string(bc_string s, uint64_t maximum, int required) {
    if (s.length > maximum || (s.length && !s.data) || (required && !s.length)) return 0;
    return !s.length || !memchr(s.data, 0, (size_t)s.length);
}
static bc_string copy_string(bc_string s) {
    char *p = malloc((size_t)s.length + 1);
    if (!p) return (bc_string){NULL, 0};
    if (s.length) memcpy(p, s.data, (size_t)s.length);
    p[s.length] = 0; return (bc_string){p, s.length};
}
static bc_status copy_token(bc_string token, bc_string *out) {
    if (!valid_string(token, 8192, 0)) return BC_PROTOCOL_ERROR;
    for (uint64_t i = 0; i < token.length; ++i)
        if ((unsigned char)token.data[i] < 33 || (unsigned char)token.data[i] > 126) return BC_PROTOCOL_ERROR;
    if (!token.length) return BC_OK;
    *out = copy_string(token);
    return out->data ? BC_OK : BC_NO_MEMORY;
}
static void erase(void *data, uint64_t length) {
    volatile uint8_t *p = data;
    for (uint64_t i = 0; i < length; ++i) p[i] = 0;
}
static void free_string(bc_string *s, int secret) {
    if (secret && s->data) erase((void *)s->data, s->length);
    free((void *)s->data); s->data = NULL; s->length = 0;
}
static void endpoint_free(bc_endpoint *e) {
    if (e->revision) BC_LOG_TRACE(BC_LOG_CATEGORY_LIFECYCLE, "endpoint.close", "endpoint_rev=%" PRIu64, e->revision);
    if (e->backend) e->context->transport->endpoint_close(e->context->transport->userdata, e->backend);
    free_string(&e->config.base.device_id, 0); free_string(&e->config.base.endpoint_id, 0);
    free_string(&e->config.base.origin, 0); free_string(&e->config.base.ca_file, 0);
    free_string(&e->config.base.username, 0); free_string(&e->config.base.password, 1);
    free_string(&e->config.auth_token, 1);
    free_string(&e->proxy.host, 0); free_string(&e->proxy.username, 1); free_string(&e->proxy.password, 1);
    --e->context->endpoints; free(e);
}
static int tls_valid(uint32_t v) { return v == 0 || (v >= 10 && v <= 13); }
uint32_t bc_abi_version(void) { return BC_ABI_VERSION; }
const char *bc_status_string(bc_status status) {
    static const char *const names[] = {"ok", "invalid_argument", "no_memory", "busy", "unsupported",
        "cancelled", "timeout", "tls_error", "limit_exceeded", "io_error", "shutting_down", "outcome_unknown", "http_error", "protocol_error", "redfish_error", "confirmation_required", "authentication_failed"};
    return status < sizeof(names) / sizeof(names[0]) ? names[status] : "unknown";
}
bc_status bc_context_create(const bc_context_options *o, bc_context **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!o || o->struct_size != sizeof(*o) || o->abi_version != BC_ABI_VERSION || o->reserved || !o->transport)
        return BC_INVALID_ARGUMENT;
    bc_transport *t = o->transport;
    if ((t->struct_size != sizeof(bc_transport_proxy) && t->struct_size != sizeof(*t) && t->struct_size != offsetof(bc_transport, cookie_set)) || t->abi_version != BC_ABI_VERSION || !t->endpoint_open ||
        !t->endpoint_close || !t->submit || !t->cancel || !t->poll) return BC_INVALID_ARGUMENT;
    if (o->max_response_bytes > SIZE_MAX - 1) return BC_INVALID_ARGUMENT;
    bc_context *c = calloc(1, sizeof(*c));
    if (!c) return BC_NO_MEMORY;
    c->transport = t; c->max_response = o->max_response_bytes ? o->max_response_bytes : 16u * 1024u * 1024u;
    c->max_requests = o->max_requests ? o->max_requests : 64u;
    *out = c;
    BC_LOG_INFO(BC_LOG_CATEGORY_LIFECYCLE, "context.create", "max_response=%" PRIu64 " max_requests=%u",
        c->max_response, c->max_requests);
    return BC_OK;
}
static bc_status create_endpoint(bc_context *c, const bc_endpoint_options *o, bc_string token, const bc_socks5_proxy *proxy, bc_endpoint **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!c || !o || o->struct_size != sizeof(*o) || o->abi_version != BC_ABI_VERSION || o->reserved || o->reserved2 ||
        (o->flags & ~BC_ENDPOINT_COOKIE_JAR)) return BC_INVALID_ARGUMENT;
    if (proxy) {
        if (proxy->struct_size != sizeof(*proxy) || !proxy->port || proxy->port > 65535 ||
            !valid_string(proxy->host, 255, 1) || !valid_string(proxy->username, 255, 0) ||
            !valid_string(proxy->password, 255, 0) || (!!proxy->username.length != !!proxy->password.length)) return BC_INVALID_ARGUMENT;
        if (c->transport->struct_size < sizeof(bc_transport_proxy) ||
            !((bc_transport_proxy *)c->transport)->endpoint_open_proxy) return BC_UNSUPPORTED;
    }
    if (c->shutdown) return BC_SHUTTING_DOWN;
    uint32_t min = o->tls_min ? o->tls_min : BC_TLS_1_2;
    if (!tls_valid(o->tls_min) || !tls_valid(o->tls_max) || (o->tls_max && o->tls_max < min) || o->cert_policy > BC_CERT_SKIP_ALL)
        return BC_INVALID_ARGUMENT;
    if (!valid_string(o->device_id, 1024, 1) || !valid_string(o->endpoint_id, 1024, 1) ||
        !valid_string(o->origin, 8192, 1) || !valid_string(o->ca_file, 32768, 0) ||
        !valid_string(o->username, 4096, 0) || !valid_string(o->password, 65536, 0)) return BC_INVALID_ARGUMENT;
    if (c->revision == UINT64_MAX) return BC_LIMIT_EXCEEDED;
    bc_endpoint *e = calloc(1, sizeof(*e));
    if (!e) return BC_NO_MEMORY;
    e->context = c; e->refs = 1; e->config.base = *o; ++c->endpoints;
    e->config.base.device_id = copy_string(o->device_id); e->config.base.endpoint_id = copy_string(o->endpoint_id);
    e->config.base.origin = copy_string(o->origin); e->config.base.ca_file = copy_string(o->ca_file);
    e->config.base.username = copy_string(o->username); e->config.base.password = copy_string(o->password);
    e->config.auth_token = copy_string(token);
    if (!e->config.base.device_id.data || !e->config.base.endpoint_id.data || !e->config.base.origin.data ||
        !e->config.base.ca_file.data || !e->config.base.username.data || !e->config.base.password.data || !e->config.auth_token.data) {
        endpoint_free(e); return BC_NO_MEMORY;
    }
    if (proxy) {
        e->proxy = *proxy;
        e->proxy.host = copy_string(proxy->host);
        e->proxy.username = copy_string(proxy->username);
        e->proxy.password = copy_string(proxy->password);
        if (!e->proxy.host.data || !e->proxy.username.data || !e->proxy.password.data) {
            endpoint_free(e); return BC_NO_MEMORY;
        }
    }
    e->config.base.tls_min = min;
    if (token.length) e->config.base.struct_size = sizeof(e->config);
    bc_status status = proxy ? ((bc_transport_proxy *)c->transport)->endpoint_open_proxy(
        c->transport->userdata, &e->config.base, &e->proxy, &e->backend) :
        c->transport->endpoint_open(c->transport->userdata, &e->config.base, &e->backend);
    if (status != BC_OK) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_LIFECYCLE, "endpoint.open_failed",
            "status=%s auth=%s user_len=%" PRIu64 " password=%u token=%u cookie_jar=%u cert_policy=%u tls_min=%u tls_max=%u ca=%u",
            bc_status_string(status), auth_name(e), o->username.length, o->password.length != 0, token.length != 0,
            (o->flags & BC_ENDPOINT_COOKIE_JAR) != 0, o->cert_policy, min, o->tls_max, o->ca_file.length != 0);
        endpoint_free(e); return status;
    }
    e->revision = ++c->revision; *out = e;
    BC_LOG_INFO(BC_LOG_CATEGORY_LIFECYCLE, "endpoint.open",
        "endpoint_rev=%" PRIu64 " auth=%s user_len=%" PRIu64 " password=%u token=%u cookie_jar=%u cert_policy=%u tls_min=%u tls_max=%u ca=%u",
        e->revision, auth_name(e), o->username.length, o->password.length != 0, token.length != 0,
        (o->flags & BC_ENDPOINT_COOKIE_JAR) != 0, o->cert_policy, min, o->tls_max, o->ca_file.length != 0);
    return BC_OK;
}
bc_status bc_endpoint_create(bc_context *c, const bc_endpoint_options *o, bc_endpoint **out) {
    return create_endpoint(c, o, (bc_string){NULL, 0}, NULL, out);
}
bc_status bc_endpoint_create_proxy(bc_context *c, const bc_endpoint_options *o, const bc_socks5_proxy *proxy, bc_endpoint **out) {
    return create_endpoint(c, o, (bc_string){NULL, 0}, proxy, out);
}
bc_status bc_endpoint_with_auth(const bc_endpoint *source, const bc_auth_options *auth, bc_endpoint **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!source || !auth || auth->struct_size != sizeof(*auth) || auth->abi_version != BC_ABI_VERSION || auth->reserved ||
        auth->mode > BC_AUTH_TOKEN || !valid_string(auth->username, 4096, 0) ||
        !valid_string(auth->password, 65536, 0) || !valid_string(auth->token, 8192, 0)) return BC_INVALID_ARGUMENT;
    if ((auth->mode == BC_AUTH_NONE && (auth->username.length || auth->password.length || auth->token.length)) ||
        (auth->mode == BC_AUTH_BASIC && (!auth->username.length || auth->token.length)) ||
        (auth->mode == BC_AUTH_TOKEN && (!auth->token.length || auth->username.length || auth->password.length))) return BC_INVALID_ARGUMENT;
    for (uint64_t i = 0; i < auth->token.length; ++i)
        if ((unsigned char)auth->token.data[i] < 33 || (unsigned char)auth->token.data[i] > 126) return BC_INVALID_ARGUMENT;
    bc_endpoint_options options = source->config.base;
    options.struct_size = sizeof(options); options.username = auth->username; options.password = auth->password;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_LIFECYCLE, "endpoint.derive", "auth=%s user_len=%" PRIu64 " token=%u",
        auth->mode == BC_AUTH_TOKEN ? "token" : auth->mode == BC_AUTH_BASIC ? "basic" : "none",
        auth->username.length, auth->token.length != 0);
    return create_endpoint(source->context, &options, auth->token, source->proxy.host.length ? &source->proxy : NULL, out);
}
bc_status bc_endpoint_copy_auth_token(const bc_endpoint *e, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (!e || (!out && capacity)) return BC_INVALID_ARGUMENT;
    if (e->context->shutdown) return BC_SHUTTING_DOWN;
    if (!e->config.auth_token.length) return BC_UNSUPPORTED;
    if (capacity < e->config.auth_token.length) return BC_LIMIT_EXCEEDED;
    memcpy(out, e->config.auth_token.data, (size_t)e->config.auth_token.length);
    *written = (uint32_t)e->config.auth_token.length;
    return BC_OK;
}
void bc_endpoint_retain(bc_endpoint *e) { if (e) ++e->refs; }
void bc_endpoint_release(bc_endpoint *e) { if (e && !--e->refs) endpoint_free(e); }
bc_status bc_endpoint_cookie_jar_available(const bc_endpoint *endpoint) {
    if (!endpoint) return BC_INVALID_ARGUMENT;
    if (endpoint->context->shutdown) return BC_SHUTTING_DOWN;
    const bc_transport *transport = endpoint->context->transport;
    return endpoint->config.base.flags & BC_ENDPOINT_COOKIE_JAR && transport->struct_size >= sizeof(*transport) && transport->cookie_set ? BC_OK : BC_UNSUPPORTED;
}
bc_status bc_endpoint_set_cookie(bc_endpoint *endpoint, bc_string name, bc_string value) {
    if (!endpoint || !valid_string(name, 128, 1) || !valid_string(value, 4096, 1)) return BC_INVALID_ARGUMENT;
    for (uint64_t i = 0; i < name.length; ++i) {
        unsigned char c = (unsigned char)name.data[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return BC_INVALID_ARGUMENT;
    }
    for (uint64_t i = 0; i < value.length; ++i) {
        unsigned char c = (unsigned char)value.data[i];
        if (c <= 32 || c >= 127 || c == ';' || c == ',' || c == '"' || c == '\\') return BC_INVALID_ARGUMENT;
    }
    if (endpoint->context->shutdown) return BC_SHUTTING_DOWN;
    bc_transport *transport = endpoint->context->transport;
    if (!(endpoint->config.base.flags & BC_ENDPOINT_COOKIE_JAR) || transport->struct_size < sizeof(*transport) || !transport->cookie_set) return BC_UNSUPPORTED;
    bc_status status = transport->cookie_set(transport->userdata, endpoint->backend, name, value);
    BC_LOG_DEBUG(BC_LOG_CATEGORY_LIFECYCLE, "endpoint.cookie", "endpoint_rev=%" PRIu64
        " name_len=%" PRIu64 " value_len=%" PRIu64 " status=%s",
        endpoint->revision, name.length, value.length, bc_status_string(status));
    return status;
}
uint64_t bc_endpoint_revision(const bc_endpoint *e) { return e ? e->revision : 0; }

static bc_string copy_observation(char *out, size_t size, bc_string source) {
    size_t n = source.data ? (source.length < size - 1 ? (size_t)source.length : size - 1) : 0;
    if (n) memcpy(out, source.data, n);
    out[n] = 0; return (bc_string){out, n};
}
static void complete(void *userdata, const bc_response *source) {
    bc_request *r = userdata;
    if (r->done) return;
    r->response = *source; r->response.struct_size = sizeof(r->response);
    r->response.cert_policy = r->endpoint->config.base.cert_policy;
    r->response.endpoint_revision = r->endpoint->revision;
    r->response.error = copy_observation(r->error, sizeof(r->error), source->error);
    r->response.tls_version = copy_observation(r->tls, sizeof(r->tls), source->tls_version);
    r->response.cipher = copy_observation(r->cipher, sizeof(r->cipher), source->cipher);
    r->response.body = (bc_bytes){NULL, 0};
    if (source->struct_size >= sizeof(bc_transport_response)) {
        const bc_http_metadata *m = &((const bc_transport_response *)source)->metadata;
        if (m->struct_size != sizeof(*m) || m->reserved || !valid_string(m->location, 8192, 0) ||
            !valid_string(m->retry_after, 128, 0) ||
            (m->location.length && (memchr(m->location.data, '\r', (size_t)m->location.length) || memchr(m->location.data, '\n', (size_t)m->location.length))) ||
            (m->retry_after.length && (memchr(m->retry_after.data, '\r', (size_t)m->retry_after.length) || memchr(m->retry_after.data, '\n', (size_t)m->retry_after.length))))
            r->response.status = BC_PROTOCOL_ERROR;
        else {
            r->metadata.struct_size = sizeof(r->metadata);
            r->metadata.location = copy_string(m->location); r->metadata.retry_after = copy_string(m->retry_after);
            if (!r->metadata.location.data || !r->metadata.retry_after.data) r->response.status = BC_NO_MEMORY;
        }
    }
    if (source->struct_size >= sizeof(bc_transport_auth_response)) {
        bc_status status = copy_token(((const bc_transport_auth_response *)source)->auth_token, &r->auth_token);
        if (status != BC_OK) r->response.status = status;
    }
    if (source->struct_size >= sizeof(bc_transport_cookie_response)) {
        bc_string cookie = ((const bc_transport_cookie_response *)source)->cookie_header;
        int valid = valid_string(cookie, 8192, 0);
        for (uint64_t i = 0; valid && i < cookie.length; ++i) {
            unsigned char c = (unsigned char)cookie.data[i];
            if (c < 32 || c > 126) valid = 0;
        }
        if (!valid) r->response.status = BC_PROTOCOL_ERROR;
        else if (cookie.length) {
            r->cookie_header = copy_string(cookie);
            if (!r->cookie_header.data) r->response.status = BC_NO_MEMORY;
        }
    }
    if (source->struct_size >= sizeof(bc_transport_session_response)) {
        bc_status status = copy_token(((const bc_transport_session_response *)source)->csrf_token, &r->csrf_token);
        if (status != BC_OK) r->response.status = status;
    }
    if (source->body.length > r->endpoint->context->max_response || (source->body.length && !source->body.data)) {
        r->response.status = BC_LIMIT_EXCEEDED;
    } else if (source->body.length) {
        r->body = malloc((size_t)source->body.length);
        if (!r->body) r->response.status = BC_NO_MEMORY;
        else {
            memcpy(r->body, source->body.data, (size_t)source->body.length);
            r->response.body = (bc_bytes){r->body, source->body.length};
        }
    }
    if (source->status == BC_OK && r->response.status != BC_OK && r->options.method != BC_HTTP_GET)
        r->response.status = BC_OUTCOME_UNKNOWN;
    if (r->response.status == BC_OK)
        BC_LOG_DEBUG(BC_LOG_CATEGORY_HTTP, "request.complete",
            "endpoint_rev=%" PRIu64 " request=%u method=%s status=%s http=%u bytes=%" PRIu64
            " tls=%s cipher=%s verified=%u token_len=%" PRIu64 " cookie_len=%" PRIu64 " metadata=%u",
            r->endpoint->revision, r->log_id, method_name(r->options.method), bc_status_string(r->response.status),
            r->response.http_status, r->response.body.length, r->tls[0] ? r->tls : "-", r->cipher[0] ? r->cipher : "-",
            r->response.peer_verified, r->auth_token.length, r->cookie_header.length, r->metadata.struct_size != 0);
    else
        BC_LOG_WARN(BC_LOG_CATEGORY_HTTP, "request.complete",
            "endpoint_rev=%" PRIu64 " request=%u method=%s status=%s http=%u bytes=%" PRIu64
            " tls=%s cipher=%s verified=%u token_len=%" PRIu64 " cookie_len=%" PRIu64,
            r->endpoint->revision, r->log_id, method_name(r->options.method), bc_status_string(r->response.status),
            r->response.http_status, r->response.body.length, r->tls[0] ? r->tls : "-", r->cipher[0] ? r->cipher : "-",
            r->response.peer_verified, r->auth_token.length, r->cookie_header.length);
    r->operation = NULL; r->done = 1;
}
static int ascii_lower(char c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
static int blocked_header(const char *name, size_t length) {
    static const char *const blocked[] = {"host", "content-length", "transfer-encoding", "connection", "cookie", "authorization"};
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); ++i) {
        size_t n = strlen(blocked[i]);
        if (n != length) continue;
        size_t j = 0;
        while (j < n && ascii_lower(name[j]) == blocked[i][j]) ++j;
        if (j == n) return 1;
    }
    return 0;
}
static int header_valid(bc_string header) {
    if (!header.data || header.length < 3 || header.length > 8192) return 0;
    size_t colon = 0;
    while (colon < header.length && header.data[colon] != ':') {
        char c = header.data[colon];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return 0;
        ++colon;
    }
    if (!colon || colon == header.length || blocked_header(header.data, colon)) return 0;
    for (size_t i = colon + 1; i < header.length; ++i) {
        unsigned char c = (unsigned char)header.data[i];
        if (c < 32 || c == 127) return 0;
    }
    return 1;
}
bc_status bc_http_submit(bc_endpoint *e, const bc_http_options *o, bc_completion callback, void *userdata, bc_request **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!e || !o || !callback || o->struct_size != sizeof(*o) || o->abi_version != BC_ABI_VERSION || o->method > BC_HTTP_DELETE ||
        !valid_string(o->path, 8192, 1) || o->path.data[0] != '/' || (o->path.length > 1 && o->path.data[1] == '/') ||
        memchr(o->path.data, '\r', (size_t)o->path.length) || memchr(o->path.data, '\n', (size_t)o->path.length) ||
        memchr(o->path.data, '\\', (size_t)o->path.length) || memchr(o->path.data, '#', (size_t)o->path.length) ||
        o->body.length > 16u * 1024u * 1024u || (o->body.length && !o->body.data) ||
        (o->method == BC_HTTP_GET && o->body.length) || o->timeout_ms > INT32_MAX ||
        o->reserved2 || o->header_count > 16 || (o->header_count && !o->headers)) return BC_INVALID_ARGUMENT;
    if (o->content_type.length > 128 || !valid_string(o->content_type, 128, 0)) return BC_INVALID_ARGUMENT;
    for (uint64_t i = 0; i < o->content_type.length; ++i) {
        unsigned char c = (unsigned char)o->content_type.data[i];
        if (c < 32 || c > 126) return BC_INVALID_ARGUMENT;
    }
    for (uint32_t i = 0; i < o->header_count; ++i) if (!header_valid(o->headers[i])) return BC_INVALID_ARGUMENT;
    bc_context *c = e->context;
    if (c->shutdown) return BC_SHUTTING_DOWN;
    if (c->active >= c->max_requests) return BC_BUSY;
    bc_request *r = calloc(1, sizeof(*r));
    if (!r) return BC_NO_MEMORY;
    r->endpoint = e; bc_endpoint_retain(e); r->refs = 1;
    r->options = *o; r->options.path = copy_string(o->path);
    r->options.content_type = copy_string(o->content_type);
    r->options.body = (bc_bytes){NULL, 0};
    r->options.headers = NULL; r->options.header_count = 0;
    if (o->header_count) {
        bc_string *headers = calloc(o->header_count, sizeof(*headers));
        if (headers) {
            for (uint32_t i = 0; i < o->header_count; ++i) headers[i] = copy_string(o->headers[i]);
            r->options.headers = headers; r->options.header_count = o->header_count;
        }
    }
    if (o->body.length) {
        uint8_t *p = malloc((size_t)o->body.length);
        if (p) { memcpy(p, o->body.data, (size_t)o->body.length); r->options.body = (bc_bytes){p, o->body.length}; }
    }
    int headers_ok = !o->header_count || (r->options.headers && r->options.header_count == o->header_count);
    if (headers_ok) for (uint32_t i = 0; i < o->header_count; ++i) if (!r->options.headers[i].data) headers_ok = 0;
    if (!r->options.path.data || !r->options.content_type.data || !headers_ok ||
        (o->body.length && !r->options.body.data)) { bc_request_release(r); return BC_NO_MEMORY; }
    r->callback = callback; r->userdata = userdata;
    r->log_id = ++c->next_request;
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_DEBUG
    char log_path[BC_LOG_PATH_MAX];
    uint32_t query = bc_log_path(log_path, sizeof(log_path), r->options.path.data, (size_t)r->options.path.length);
#endif
    BC_LOG_DEBUG(BC_LOG_CATEGORY_HTTP, "request.submit",
        "endpoint_rev=%" PRIu64 " request=%u method=%s path=%s query=%u body_bytes=%" PRIu64
        " headers=%u timeout_ms=%u auth=%s",
        e->revision, r->log_id, method_name(o->method), log_path, query, o->body.length, o->header_count,
        o->timeout_ms ? o->timeout_ms : 30000u, auth_name(e));
    bc_status status = c->transport->submit(c->transport->userdata, e->backend, &r->options, c->max_response, complete, r, &r->operation);
    if (status != BC_OK) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_HTTP, "request.submit_failed", "endpoint_rev=%" PRIu64
            " request=%u method=%s status=%s", e->revision, r->log_id, method_name(o->method), bc_status_string(status));
        bc_request_release(r); return status;
    }
    r->next = c->requests; c->requests = r; ++r->refs; ++c->active;
    *out = r; return BC_OK;
}
bc_status bc_request_cancel(bc_request *r) {
    if (!r) return BC_INVALID_ARGUMENT;
    if (r->done) return BC_OK;
    bc_context *c = r->endpoint->context;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_HTTP, "request.cancel", "endpoint_rev=%" PRIu64 " request=%u method=%s",
        r->endpoint->revision, r->log_id, method_name(r->options.method));
    if (r->operation) c->transport->cancel(c->transport->userdata, r->operation);
    bc_response response = {0};
    response.status = r->options.method == BC_HTTP_GET ? BC_CANCELLED : BC_OUTCOME_UNKNOWN;
    response.error = (bc_string){"cancelled", 9};
    complete(r, &response); return BC_OK;
}
void bc_request_retain(bc_request *r) { if (r) ++r->refs; }
void bc_request_release(bc_request *r) {
    if (!r || --r->refs) return;
    free_string(&r->options.path, 0); erase((void *)r->options.body.data, r->options.body.length); free((void *)r->options.body.data);
    free_string(&r->options.content_type, 0);
    for (uint32_t i = 0; i < r->options.header_count; ++i) free_string((bc_string *)&r->options.headers[i], 1);
    free((void *)r->options.headers);
    free_string(&r->metadata.location, 0); free_string(&r->metadata.retry_after, 0);
    free_string(&r->auth_token, 1);
    free_string(&r->cookie_header, 1);
    free_string(&r->csrf_token, 1);
    free(r->body); bc_endpoint_release(r->endpoint); free(r);
}
const bc_response *bc_request_response(const bc_request *r) { return r && r->done ? &r->response : NULL; }
const bc_endpoint *bc_request_endpoint(const bc_request *r) { return r ? r->endpoint : NULL; }
bc_string bc_request_path(const bc_request *r) { return r ? r->options.path : (bc_string){NULL, 0}; }
const bc_http_metadata *bc_request_http_metadata(const bc_request *r) {
    return r && r->done && r->metadata.struct_size ? &r->metadata : NULL;
}
bc_string bc_request_auth_token(const bc_request *r) { return r && r->done ? r->auth_token : (bc_string){NULL, 0}; }
bc_string bc_request_cookie_header(const bc_request *r) { return r && r->done ? r->cookie_header : (bc_string){NULL, 0}; }
bc_string bc_request_csrf_token(const bc_request *r) { return r && r->done ? r->csrf_token : (bc_string){NULL, 0}; }
bc_status bc_context_poll(bc_context *c, uint32_t timeout_ms) {
    if (!c) return BC_INVALID_ARGUMENT;
    if (c->polling) return BC_BUSY;
    c->polling = 1;
    uint32_t budget = c->active;
    int ready = 0;
    for (bc_request *r = c->requests; r; r = r->next) if (r->done) { ready = 1; break; }
    bc_status status = c->transport->poll(c->transport->userdata, ready ? 0 : timeout_ms);
    if (status != BC_OK) BC_LOG_ERROR(BC_LOG_CATEGORY_HTTP, "poll.failed", "status=%s active=%u", bc_status_string(status), c->active);
    for (uint32_t i = 0; i < budget; ++i) {
        bc_request **link = &c->requests;
        while (*link && !(*link)->done) link = &(*link)->next;
        if (!*link) break;
        bc_request *r = *link; *link = r->next; --c->active;
        r->callback(r, &r->response, r->userdata);
        bc_request_release(r);
    }
    c->polling = 0; return status;
}
bc_status bc_context_shutdown(bc_context *c) {
    if (!c) return BC_INVALID_ARGUMENT;
    BC_LOG_INFO(BC_LOG_CATEGORY_LIFECYCLE, "context.shutdown", "active=%u endpoints=%u", c->active, c->endpoints);
    c->shutdown = 1;
    for (bc_request *r = c->requests; r; r = r->next) bc_request_cancel(r);
    return BC_OK;
}
bc_status bc_context_destroy(bc_context *c) {
    if (!c) return BC_INVALID_ARGUMENT;
    if (c->polling || c->requests || c->endpoints) {
        BC_LOG_WARN(BC_LOG_CATEGORY_LIFECYCLE, "context.destroy", "status=busy active=%u endpoints=%u",
            c->active, c->endpoints);
        return BC_BUSY;
    }
    BC_LOG_INFO(BC_LOG_CATEGORY_LIFECYCLE, "context.destroy", "status=ok");
    free(c); return BC_OK;
}

bc_string bc_endpoint_origin(const bc_endpoint *endpoint) {
    return endpoint ? endpoint->config.base.origin : (bc_string){NULL, 0};
}

void bc_endpoint_redfish_profile_set(bc_endpoint *e, uint32_t profile) { if (e) e->redfish_profile = profile; }
uint32_t bc_endpoint_redfish_profile(const bc_endpoint *e) { return e ? e->redfish_profile : 0; }

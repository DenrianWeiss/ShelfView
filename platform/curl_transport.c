#define _POSIX_C_SOURCE 200809L
#include "bcontrol/transport.h"
#include "../core/log_internal.h"
#include <curl/curl.h>
#include "curl_socket.h"
#include "monotonic.h"
#include <openssl/ssl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct curl_backend curl_backend;
typedef struct curl_endpoint curl_endpoint;
typedef struct curl_operation curl_operation;
struct curl_endpoint {
    curl_endpoint *next;
    curl_backend *owner;
    CURLM *multi;
    CURLSH *share;
    const bc_endpoint_options *config;
    const bc_socks5_proxy *proxy;
    char *origin;
    uint32_t active;
    int avoid_dhe;
};
struct curl_backend { bc_transport_proxy api; curl_endpoint *endpoints; };
struct curl_operation {
    curl_endpoint *endpoint;
    CURL *easy;
    struct curl_slist *headers;
    char *url;
    uint8_t *body;
    size_t used, capacity;
    uint64_t limit, deadline;
    bc_transport_done done;
    void *userdata;
    uint32_t method, attempt;
    int limited, no_memory, opened_socket;
    size_t header_bytes;
    char error[CURL_ERROR_SIZE], tls[32], cipher[128];
};

#define CONNECT_ATTEMPTS 3u

static CURLcode set_attempt_timeout(curl_operation *o, uint32_t remaining) {
    uint32_t connect = remaining;
    if (o->attempt < CONNECT_ATTEMPTS && remaining > 1000) {
        connect = remaining / (CONNECT_ATTEMPTS - o->attempt + 1);
        if (connect < 1000) connect = 1000;
        if (connect > 8000) connect = 8000;
    }
    CURLcode status = curl_easy_setopt(o->easy, CURLOPT_TIMEOUT_MS, (long)remaining);
    return status == CURLE_OK ? curl_easy_setopt(o->easy, CURLOPT_CONNECTTIMEOUT_MS, (long)connect) : status;
}

static bc_string string(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
static int socket_options(void *userdata, curl_socket_t socket, curlsocktype purpose) {
    curl_operation *o = userdata;
    o->opened_socket = 1;
    return bc_curl_socket_options(NULL, socket, purpose);
}
static void erase(char *data, size_t length) {
    volatile char *p = data;
    for (size_t i = 0; i < length; ++i) p[i] = 0;
}
static void observe(curl_operation *o) {
    struct curl_tlssessioninfo *session = NULL;
    if (curl_easy_getinfo(o->easy, CURLINFO_TLS_SSL_PTR, &session) != CURLE_OK || !session ||
        session->backend != CURLSSLBACKEND_OPENSSL || !session->internals) return;
    SSL *ssl = session->internals;
    snprintf(o->tls, sizeof(o->tls), "%s", SSL_get_version(ssl));
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) snprintf(o->cipher, sizeof(o->cipher), "%s", SSL_CIPHER_get_name(cipher));
}
static size_t receive(char *data, size_t size, size_t count, void *userdata) {
    curl_operation *o = userdata;
    if (size && count > SIZE_MAX / size) return 0;
    size_t n = size * count;
    if (o->used > o->limit || n > o->limit - o->used) { o->limited = 1; return 0; }
    if (n > o->capacity - o->used) {
        size_t need = o->used + n;
        size_t capacity = o->capacity ? o->capacity : 4096;
        while (capacity < need) {
            if (capacity > SIZE_MAX / 2) { capacity = need; break; }
            capacity *= 2;
        }
        if (capacity > o->limit) capacity = (size_t)o->limit;
        uint8_t *p = realloc(o->body, capacity);
        if (!p) { o->no_memory = 1; return 0; }
        o->body = p; o->capacity = capacity;
    }
    if (n) memcpy(o->body + o->used, data, n);
    o->used += n; observe(o); return n;
}
static size_t receive_header(char *data, size_t size, size_t count, void *userdata) {
    (void)data; curl_operation *o = userdata; observe(o);
    if (size && count > SIZE_MAX / size) return 0;
    size_t n = size * count;
    if (n > 65536 - o->header_bytes) { o->limited = 1; return 0; }
    o->header_bytes += n; return n;
}
static bc_status metadata_read(CURL *easy, bc_http_metadata *metadata, bc_string *token, bc_string *csrf) {
    const char *names[] = {"Location", "Retry-After", "X-Auth-Token", "XSRF-TOKEN"};
    bc_string *outputs[] = {&metadata->location, &metadata->retry_after, token, csrf};
    const size_t limits[] = {8192, 128, 8192, 8192};
    metadata->struct_size = sizeof(*metadata);
    for (size_t i = 0; i < 4; ++i) {
        struct curl_header *header = NULL;
        CURLHcode code = curl_easy_header(easy, names[i], 0, CURLH_HEADER, -1, &header);
        if (code == CURLHE_MISSING || code == CURLHE_NOHEADERS || code == CURLHE_NOREQUEST) continue;
        if (code == CURLHE_NOT_BUILT_IN) return BC_UNSUPPORTED;
        if (code != CURLHE_OK) return code == CURLHE_OUT_OF_MEMORY ? BC_NO_MEMORY : BC_PROTOCOL_ERROR;
        if (header->amount != 1) return BC_PROTOCOL_ERROR;
        bc_string value = string(header->value);
        if (value.length > limits[i]) return BC_PROTOCOL_ERROR;
        for (uint64_t n = 0; n < value.length; ++n)
            if ((unsigned char)value.data[n] < (i >= 2 ? 33 : 32) || (unsigned char)value.data[n] == 127 ||
                (i >= 2 && (unsigned char)value.data[n] > 126)) return BC_PROTOCOL_ERROR;
        *outputs[i] = value;
    }
    return BC_OK;
}
static void operation_free(curl_operation *o) {
    curl_easy_cleanup(o->easy);
    for (struct curl_slist *header = o->headers; header; header = header->next) erase(header->data, strlen(header->data));
    curl_slist_free_all(o->headers);
    free(o->url); free(o->body); free(o);
}
static bc_status endpoint_open(void *userdata, const bc_endpoint_options *config, void **out) {
    curl_backend *b = userdata;
    CURLU *url = curl_url();
    if (!url) return BC_NO_MEMORY;
    char *scheme = NULL, *host = NULL, *path = NULL, *part = NULL, *origin = NULL, *port_text = NULL;
    long origin_port = 443;
    bc_status status = BC_INVALID_ARGUMENT;
    if (curl_url_set(url, CURLUPART_URL, config->origin.data, 0) != CURLUE_OK ||
        curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK || strcmp(scheme, "https") ||
        curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK || !*host ||
        curl_url_get(url, CURLUPART_PATH, &path, 0) != CURLUE_OK || strcmp(path, "/")) goto cleanup;
    if (curl_url_get(url, CURLUPART_PORT, &port_text, 0) == CURLUE_OK) origin_port = strtol(port_text, NULL, 10);
    if (curl_url_get(url, CURLUPART_USER, &part, 0) == CURLUE_OK) goto cleanup;
    if (curl_url_get(url, CURLUPART_PASSWORD, &part, 0) == CURLUE_OK) goto cleanup;
    if (curl_url_get(url, CURLUPART_QUERY, &part, 0) == CURLUE_OK) goto cleanup;
    if (curl_url_get(url, CURLUPART_FRAGMENT, &part, 0) == CURLUE_OK) goto cleanup;
    if (curl_url_get(url, CURLUPART_URL, &origin, 0) != CURLUE_OK) goto cleanup;
    curl_endpoint *e = calloc(1, sizeof(*e));
    if (!e) { status = BC_NO_MEMORY; goto cleanup; }
    size_t n = strlen(origin);
    while (n && origin[n - 1] == '/') --n;
    e->origin = malloc(n + 1);
    e->multi = curl_multi_init();
    if (!e->origin || !e->multi) {
        free(e->origin); if (e->multi) curl_multi_cleanup(e->multi); free(e);
        status = BC_NO_MEMORY; goto cleanup;
    }
    memcpy(e->origin, origin, n); e->origin[n] = 0;
    if (config->flags & BC_ENDPOINT_COOKIE_JAR) {
        e->share = curl_share_init();
        if (!e->share || curl_share_setopt(e->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE) != CURLSHE_OK) {
            if (e->share) curl_share_cleanup(e->share);
            free(e->origin); curl_multi_cleanup(e->multi); free(e);
            status = BC_NO_MEMORY; goto cleanup;
        }
    }
    e->owner = b; e->config = config;
    e->next = b->endpoints; b->endpoints = e; *out = e;
    status = BC_OK;
    BC_LOG_INFO(BC_LOG_CATEGORY_LIFECYCLE, "transport.endpoint_open",
        "host_len=%zu port=%ld auth=%s ca=%u cookie_jar=%u cert_policy=%u tls_min=%u tls_max=%u",
        strlen(host), origin_port, config->username.length ? "basic" : "none", config->ca_file.length != 0,
        (config->flags & BC_ENDPOINT_COOKIE_JAR) != 0, config->cert_policy, config->tls_min, config->tls_max);
cleanup:
    if (status != BC_OK)
        BC_LOG_ERROR(BC_LOG_CATEGORY_LIFECYCLE, "transport.endpoint_open_failed",
            "status=%s origin_len=%" PRIu64 " cert_policy=%u tls_min=%u tls_max=%u",
            bc_status_string(status), config->origin.length, config->cert_policy, config->tls_min, config->tls_max);
    curl_free(scheme); curl_free(host); curl_free(path); curl_free(part); curl_free(origin); curl_free(port_text); curl_url_cleanup(url);
    return status;
}
static bc_status endpoint_open_proxy(void *userdata, const bc_endpoint_options *config,
    const bc_socks5_proxy *proxy, void **out) {
    bc_status status = endpoint_open(userdata, config, out);
    if (status == BC_OK) ((curl_endpoint *)*out)->proxy = proxy;
    return status;
}
static void endpoint_close(void *userdata, void *endpoint) {
    curl_backend *b = userdata; curl_endpoint *e = endpoint;
    curl_endpoint **p = &b->endpoints;
    while (*p && *p != e) p = &(*p)->next;
    if (*p) *p = e->next;
    if (e->share) curl_share_cleanup(e->share);
    curl_multi_cleanup(e->multi); free(e->origin); free(e);
}
static bc_status cookie_set(void *userdata, void *endpoint, bc_string name, bc_string value) {
    (void)userdata; curl_endpoint *e = endpoint;
    if (!e->share) return BC_UNSUPPORTED;
    CURLU *url = curl_url(); char *host = NULL;
    if (!url) return BC_NO_MEMORY;
    if (curl_url_set(url, CURLUPART_URL, e->origin, 0) != CURLUE_OK || curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK) {
        curl_free(host); curl_url_cleanup(url); return BC_INVALID_ARGUMENT;
    }
    size_t size = strlen(host) + (size_t)name.length + (size_t)value.length + 32;
    char *line = malloc(size); CURL *easy = curl_easy_init();
    bc_status status = !line || !easy ? BC_NO_MEMORY : BC_OK;
    if (status == BC_OK) {
        snprintf(line, size, "%s\tFALSE\t/\tTRUE\t0\t%.*s\t%.*s", host, (int)name.length, name.data, (int)value.length, value.data);
        if (curl_easy_setopt(easy, CURLOPT_SHARE, e->share) != CURLE_OK ||
            curl_easy_setopt(easy, CURLOPT_COOKIEFILE, "") != CURLE_OK ||
            curl_easy_setopt(easy, CURLOPT_COOKIELIST, line) != CURLE_OK) status = BC_IO_ERROR;
    }
    if (line) { erase(line, size); free(line); }
    if (easy) curl_easy_cleanup(easy);
    curl_free(host); curl_url_cleanup(url); return status;
}
static long min_version(uint32_t v) {
    switch (v) {
    case BC_TLS_1_0: return CURL_SSLVERSION_TLSv1_0;
    case BC_TLS_1_1: return CURL_SSLVERSION_TLSv1_1;
    case BC_TLS_1_3: return CURL_SSLVERSION_TLSv1_3;
    default: return CURL_SSLVERSION_TLSv1_2;
    }
}
static long max_version(uint32_t v) {
    switch (v) {
    case BC_TLS_1_0: return CURL_SSLVERSION_MAX_TLSv1_0;
    case BC_TLS_1_1: return CURL_SSLVERSION_MAX_TLSv1_1;
    case BC_TLS_1_2: return CURL_SSLVERSION_MAX_TLSv1_2;
    default: return CURL_SSLVERSION_MAX_TLSv1_3;
    }
}
static bc_status submit(void *userdata, void *endpoint, const bc_http_options *request, uint64_t limit,
    bc_transport_done done, void *arg, void **out) {
    (void)userdata;
    curl_endpoint *e = endpoint;
    const bc_endpoint_options *config = e->config;
    curl_operation *o = calloc(1, sizeof(*o));
    if (!o) return BC_NO_MEMORY;
    o->endpoint = e; o->limit = limit; o->done = done; o->userdata = arg; o->method = request->method;
    o->url = malloc(strlen(e->origin) + (size_t)request->path.length + 1);
    o->easy = curl_easy_init();
    if (!o->url || !o->easy) { operation_free(o); return BC_NO_MEMORY; }
    strcpy(o->url, e->origin); strcat(o->url, request->path.data);
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_DEBUG
    char log_path[BC_LOG_PATH_MAX];
    uint32_t query = bc_log_path(log_path, sizeof(log_path), request->path.data, (size_t)request->path.length);
    BC_LOG_DEBUG(BC_LOG_CATEGORY_HTTP, "transport.submit",
        "method=%s path=%s query=%u body_bytes=%" PRIu64 " headers=%u timeout_ms=%u auth=%s",
        o->method == BC_HTTP_GET ? "GET" : o->method == BC_HTTP_POST ? "POST" : o->method == BC_HTTP_PATCH ? "PATCH" : "DELETE",
        log_path, query, request->body.length, request->header_count,
        request->timeout_ms ? request->timeout_ms : 30000u, config->username.length ? "basic" : "none");
#endif
    CURL *easy = o->easy;
#define SET(option, value) do { if (curl_easy_setopt(easy, option, value) != CURLE_OK) goto fail; } while (0)
    SET(CURLOPT_URL, o->url);
    SET(CURLOPT_PROTOCOLS_STR, "https");
    SET(CURLOPT_FOLLOWLOCATION, 0L);
    SET(CURLOPT_ACCEPT_ENCODING, "gzip");
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_SOCKOPTFUNCTION, socket_options);
    SET(CURLOPT_SOCKOPTDATA, o);
    if (e->proxy) {
        SET(CURLOPT_PROXY, e->proxy->host.data);
        SET(CURLOPT_PROXYPORT, (long)e->proxy->port);
        SET(CURLOPT_PROXYTYPE, (long)CURLPROXY_SOCKS5_HOSTNAME);
        SET(CURLOPT_NOPROXY, "");
        SET(CURLOPT_SOCKS5_AUTH, (long)(e->proxy->username.length ? CURLAUTH_BASIC : CURLAUTH_NONE));
        if (e->proxy->username.length) {
            SET(CURLOPT_PROXYUSERNAME, e->proxy->username.data);
            SET(CURLOPT_PROXYPASSWORD, e->proxy->password.data);
        }
    } else {
        SET(CURLOPT_PROXY, "");
    }
    SET(CURLOPT_SSL_VERIFYPEER, config->cert_policy == BC_CERT_STRICT ? 1L : 0L);
    SET(CURLOPT_SSL_VERIFYHOST, config->cert_policy == BC_CERT_SKIP_ALL ? 0L : 2L);
    SET(CURLOPT_SSLVERSION, min_version(config->tls_min) | max_version(config->tls_max));
    if (e->avoid_dhe)
        SET(CURLOPT_SSL_CIPHER_LIST, "DEFAULT:!DH");
    else if (config->tls_min < BC_TLS_1_2)
        SET(CURLOPT_SSL_CIPHER_LIST, "DEFAULT:AES128-SHA:AES256-SHA:@SECLEVEL=0");
    if (config->ca_file.length) SET(CURLOPT_CAINFO, config->ca_file.data);
#ifdef _WIN32
    else SET(CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA);
#endif
    if (config->username.length) {
        SET(CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
        SET(CURLOPT_USERNAME, config->username.data); SET(CURLOPT_PASSWORD, config->password.data);
    }
    uint32_t timeout = request->timeout_ms ? request->timeout_ms : 30000;
    o->deadline = bc_monotonic_ms() + timeout;
    o->attempt = 1;
    if (set_attempt_timeout(o, timeout) != CURLE_OK) goto fail;
    SET(CURLOPT_WRITEFUNCTION, receive); SET(CURLOPT_WRITEDATA, o);
    SET(CURLOPT_HEADERFUNCTION, receive_header); SET(CURLOPT_HEADERDATA, o);
    SET(CURLOPT_ERRORBUFFER, o->error); SET(CURLOPT_PRIVATE, o);
    o->headers = curl_slist_append(NULL, "Accept: application/json");
    if (!o->headers) goto no_memory;
    if (config->struct_size >= sizeof(bc_transport_endpoint_config)) {
        bc_string token = ((const bc_transport_endpoint_config *)config)->auth_token;
        if (token.length) {
            const char prefix[] = "X-Auth-Token: ";
            size_t length = sizeof(prefix) - 1 + (size_t)token.length;
            char *header = malloc(length + 1);
            if (!header) goto no_memory;
            memcpy(header, prefix, sizeof(prefix) - 1); memcpy(header + sizeof(prefix) - 1, token.data, (size_t)token.length); header[length] = 0;
            struct curl_slist *headers = curl_slist_append(o->headers, header);
            erase(header, length); free(header);
            if (!headers) goto no_memory;
            o->headers = headers;
        }
    }
    if (request->method != BC_HTTP_GET) {
        SET(CURLOPT_FRESH_CONNECT, 1L);
        SET(CURLOPT_FORBID_REUSE, 1L);
        SET(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
        static const char *const methods[] = {"GET", "POST", "PATCH", "DELETE"};
        SET(CURLOPT_CUSTOMREQUEST, methods[request->method]);
        SET(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)request->body.length);
        SET(CURLOPT_POSTFIELDS, request->body.length ? (const char *)request->body.data : "");
        if (!request->content_type.length) {
            struct curl_slist *headers = curl_slist_append(o->headers, "Content-Type: application/json");
            if (!headers) goto no_memory;
            o->headers = headers;
        }
    }
    for (uint32_t i = 0; i < request->header_count; ++i) {
        struct curl_slist *headers = curl_slist_append(o->headers, request->headers[i].data);
        if (!headers) goto no_memory;
        o->headers = headers;
    }
    if (request->content_type.length) {
        static const char prefix[] = "Content-Type: ";
        size_t length = sizeof(prefix) - 1 + (size_t)request->content_type.length;
        char *header = malloc(length + 1);
        if (!header) goto no_memory;
        memcpy(header, prefix, sizeof(prefix) - 1);
        memcpy(header + sizeof(prefix) - 1, request->content_type.data, (size_t)request->content_type.length);
        header[length] = 0;
        struct curl_slist *headers = curl_slist_append(o->headers, header);
        free(header);
        if (!headers) goto no_memory;
        o->headers = headers;
    }
    SET(CURLOPT_HTTPHEADER, o->headers);
    if (e->share) { SET(CURLOPT_SHARE, e->share); SET(CURLOPT_COOKIEFILE, ""); }
    if (curl_multi_add_handle(e->multi, easy) != CURLM_OK) goto fail;
    ++e->active; *out = o; return BC_OK;
no_memory:
    BC_LOG_ERROR(BC_LOG_CATEGORY_HTTP, "transport.submit_failed", "status=no_memory");
    operation_free(o); return BC_NO_MEMORY;
fail:
    BC_LOG_ERROR(BC_LOG_CATEGORY_HTTP, "transport.submit_failed", "status=io_error");
    operation_free(o); return BC_IO_ERROR;
#undef SET
}
static void cancel(void *userdata, void *operation) {
    (void)userdata; curl_operation *o = operation;
    curl_multi_remove_handle(o->endpoint->multi, o->easy); --o->endpoint->active; operation_free(o);
}
static bc_status translate(CURLcode code) {
    switch (code) {
    case CURLE_OK: return BC_OK;
    case CURLE_OPERATION_TIMEDOUT: return BC_TIMEOUT;
    case CURLE_OUT_OF_MEMORY: return BC_NO_MEMORY;
    case CURLE_PEER_FAILED_VERIFICATION: case CURLE_SSL_CONNECT_ERROR: case CURLE_SSL_CACERT_BADFILE:
    case CURLE_SSL_CIPHER: case CURLE_SSL_CERTPROBLEM: return BC_TLS_ERROR;
    default: return BC_IO_ERROR;
    }
}

static int retry_connection(curl_operation *o, CURLcode result, long http, long sent) {
    if (o->attempt >= CONNECT_ATTEMPTS || http || sent || o->header_bytes || o->used) return 0;
    switch (result) {
    case CURLE_COULDNT_CONNECT: case CURLE_OPERATION_TIMEDOUT: case CURLE_SSL_CONNECT_ERROR:
    case CURLE_RECV_ERROR: case CURLE_SEND_ERROR: case CURLE_GOT_NOTHING: break;
    default: return 0;
    }
    /* Once TLS finished, a failed write can still have delivered bytes to the peer. */
    curl_off_t tls_ready = 0;
    if (curl_easy_getinfo(o->easy, CURLINFO_APPCONNECT_TIME_T, &tls_ready) != CURLE_OK || tls_ready) return 0;
    if (!o->opened_socket && result != CURLE_COULDNT_CONNECT) return 0;
    uint64_t now = bc_monotonic_ms();
    if (now >= o->deadline || o->deadline - now < 250) return 0;
    CURLM *multi = o->endpoint->multi;
    if (curl_multi_remove_handle(multi, o->easy) != CURLM_OK) return 0;
    ++o->attempt;
    /* Some old servers select a DH group that OpenSSL rejects. Retry with the
     * remaining suites at the default security level before sending any HTTP. */
    if (result == CURLE_SSL_CONNECT_ERROR && strstr(o->error, "dh key too small")) {
        if (curl_easy_setopt(o->easy, CURLOPT_SSL_CIPHER_LIST, "DEFAULT:!DH") != CURLE_OK) return 0;
        o->endpoint->avoid_dhe = 1;
    }
    if (set_attempt_timeout(o, (uint32_t)(o->deadline - now)) != CURLE_OK ||
        curl_easy_setopt(o->easy, CURLOPT_FRESH_CONNECT, 1L) != CURLE_OK ||
        curl_multi_add_handle(multi, o->easy) != CURLM_OK) return 0;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_HTTP, "transport.connect_retry", "attempt=%u curl_code=%d", o->attempt, (int)result);
    o->opened_socket = 0;
    o->error[0] = o->tls[0] = o->cipher[0] = 0;
    return 1;
}
static void cookie_export(CURL *easy, char **header, size_t *length) {
    *header = NULL; *length = 0;
    struct curl_slist *list = NULL;
    if (curl_easy_getinfo(easy, CURLINFO_COOKIELIST, &list) != CURLE_OK || !list) return;
    size_t capacity = 256, used = 0;
    char *value = malloc(capacity);
    if (!value) { curl_slist_free_all(list); return; }
    for (struct curl_slist *item = list; item; item = item->next) {
        const char *line = item->data;
        const char *fields[7]; size_t lengths[7];
        int count = 0; const char *start = line;
        for (const char *p = line; count < 7; ++p) {
            if (*p == '\t' || *p == 0) {
                fields[count] = start; lengths[count] = (size_t)(p - start); ++count;
                if (!*p) break;
                start = p + 1;
            }
        }
        if (count < 7 || !lengths[5] || !lengths[6]) continue;
        size_t needed = lengths[5] + 1 + lengths[6] + 2;
        if (used + needed + 1 > 4096) break;
        while (used + needed + 1 > capacity) capacity *= 2;
        char *grown = realloc(value, capacity);
        if (!grown) break;
        value = grown;
        if (used) { value[used++] = ';'; value[used++] = ' '; }
        memcpy(value + used, fields[5], lengths[5]); used += lengths[5];
        value[used++] = '=';
        memcpy(value + used, fields[6], lengths[6]); used += lengths[6];
    }
    curl_slist_free_all(list);
    value[used] = 0;
    *header = value; *length = used;
}
static bc_status perform(curl_endpoint *e) {
    int running = 0;
    if (curl_multi_perform(e->multi, &running) != CURLM_OK) return BC_IO_ERROR;
    int left;
    CURLMsg *message;
    while ((message = curl_multi_info_read(e->multi, &left))) {
        if (message->msg != CURLMSG_DONE) continue;
        curl_operation *o = NULL;
        curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &o);
        CURLcode result = message->data.result;
        long http = 0, sent = 0;
        curl_easy_getinfo(o->easy, CURLINFO_RESPONSE_CODE, &http);
        curl_easy_getinfo(o->easy, CURLINFO_REQUEST_SIZE, &sent);
        if (retry_connection(o, result, http, sent)) continue;
        bc_response response = {0};
        response.struct_size = sizeof(response); response.status = translate(result);
        if (o->limited) response.status = BC_LIMIT_EXCEEDED;
        else if (o->no_memory) response.status = BC_NO_MEMORY;
        bc_transport_session_response extended = {0};
        bc_status metadata_status = metadata_read(o->easy, &extended.cookie.auth.response.metadata, &extended.cookie.auth.auth_token, &extended.csrf_token);
        char *cookies = NULL; size_t cookie_length = 0;
        if (metadata_status != BC_UNSUPPORTED) cookie_export(o->easy, &cookies, &cookie_length);
        if (response.status == BC_OK && metadata_status != BC_OK && metadata_status != BC_UNSUPPORTED) response.status = metadata_status;
        response.http_status = (uint32_t)http;
        if (metadata_status == BC_OK && http == 200 && !o->limited && !o->no_memory &&
            (result == CURLE_PARTIAL_FILE || (result == CURLE_RECV_ERROR &&
                strstr(o->error, "unexpected eof while reading"))))
            response.flags |= BC_RESPONSE_EARLY_EOF;
        if (o->method == BC_HTTP_GET && http >= 400 && http <= 599 &&
            result == CURLE_BAD_CONTENT_ENCODING && !o->limited && !o->no_memory) {
            response.status = BC_HTTP_ERROR;
            o->used = 0;
        }
        if (response.status == BC_OK && http >= 400) response.status = BC_HTTP_ERROR;
        if (o->method != BC_HTTP_GET && sent && response.status != BC_OK && response.status != BC_HTTP_ERROR)
            response.status = BC_OUTCOME_UNKNOWN;
        response.body = (bc_bytes){o->body, o->used};
        response.error = string(result == CURLE_OK ? (response.status == BC_OK ? "" : bc_status_string(response.status)) :
            (o->error[0] ? o->error : curl_easy_strerror(result)));
        response.tls_version = string(o->tls); response.cipher = string(o->cipher);
        response.peer_verified = result == CURLE_OK && e->config->cert_policy == BC_CERT_STRICT;
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_DEBUG
        long verify_result = 0, http_version = 0, connects = 0;
        curl_off_t total_time = 0;
        curl_easy_getinfo(o->easy, CURLINFO_SSL_VERIFYRESULT, &verify_result);
        curl_easy_getinfo(o->easy, CURLINFO_HTTP_VERSION, &http_version);
        curl_easy_getinfo(o->easy, CURLINFO_NUM_CONNECTS, &connects);
        curl_easy_getinfo(o->easy, CURLINFO_TOTAL_TIME_T, &total_time);
        if (o->tls[0])
            BC_LOG_DEBUG(BC_LOG_CATEGORY_TLS, "tls.negotiated", "tls=%s cipher=%s verify_result=%ld verified=%u",
                o->tls, o->cipher[0] ? o->cipher : "-", verify_result, response.peer_verified);
        BC_LOG_DEBUG(BC_LOG_CATEGORY_HTTP, "transport.complete",
            "curl_code=%d status=%s http=%ld bytes=%zu tls=%s cipher=%s verify_result=%ld verified=%u"
            " http_version=%ld connects=%ld time_ms=%" PRIu64 " metadata=%s",
            (int)result, bc_status_string(response.status), http, o->used, o->tls[0] ? o->tls : "-",
            o->cipher[0] ? o->cipher : "-", verify_result, response.peer_verified, http_version, connects,
            (uint64_t)total_time, bc_status_string(metadata_status));
#endif
        curl_multi_remove_handle(e->multi, o->easy); --e->active;
        extended.cookie.auth.response.base = response;
        if (metadata_status == BC_UNSUPPORTED) extended.cookie.auth.response.base.struct_size = sizeof(response);
        else {
            extended.cookie.cookie_header = (bc_string){cookies, cookie_length};
            extended.cookie.auth.response.base.struct_size = sizeof(extended);
        }
        o->done(o->userdata, &extended.cookie.auth.response.base);
        free(cookies); operation_free(o);
    }
    return BC_OK;
}
static bc_status poll_backend(void *userdata, uint32_t timeout_ms) {
    curl_backend *b = userdata; curl_endpoint *wait = NULL;
    for (curl_endpoint *e = b->endpoints; e; e = e->next) {
        bc_status status = perform(e);
        if (status != BC_OK) { BC_LOG_ERROR(BC_LOG_CATEGORY_HTTP, "transport.poll_failed", "status=%s", bc_status_string(status)); return status; }
        if (e->active && !wait) wait = e;
    }
    if (wait && timeout_ms) {
        int count;
        int ms = (int)(timeout_ms > 50 ? 50 : timeout_ms);
        if (curl_multi_poll(wait->multi, NULL, 0, ms, &count) != CURLM_OK) {
            BC_LOG_ERROR(BC_LOG_CATEGORY_HTTP, "transport.poll_failed", "status=io_error stage=wait");
            return BC_IO_ERROR;
        }
        for (curl_endpoint *e = b->endpoints; e; e = e->next) {
            bc_status status = perform(e);
            if (status != BC_OK) { BC_LOG_ERROR(BC_LOG_CATEGORY_HTTP, "transport.poll_failed", "status=%s stage=complete", bc_status_string(status)); return status; }
        }
    }
    return BC_OK;
}
/* libcurl global state is process-wide; per-transport cleanup would invalidate
 * other active transports. Creation/destruction are serialized by the owner. */
#include "mutex.h"
static bc_mutex global_lock=BC_MUTEX_INITIALIZER;
static unsigned global_users;

static bc_status transport_create(bc_transport **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!global_users) {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return BC_IO_ERROR;
    }
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if (!version->ssl_version || strncmp(version->ssl_version, "OpenSSL/3.", 10)) {
        if (!global_users) curl_global_cleanup();
        return BC_UNSUPPORTED;
    }
    curl_backend *b = calloc(1, sizeof(*b));
    if (!b) { if (!global_users) curl_global_cleanup(); return BC_NO_MEMORY; }
    ++global_users;
    b->api.base = (bc_transport){sizeof(bc_transport_proxy), BC_ABI_VERSION, b, endpoint_open, endpoint_close, submit, cancel, poll_backend, cookie_set};
    b->api.endpoint_open_proxy = endpoint_open_proxy;
    *out = &b->api.base;
    BC_LOG_INFO(BC_LOG_CATEGORY_LIFECYCLE, "transport.create", "curl=%s ssl=%s", version->version, version->ssl_version);
    return BC_OK;
}
static bc_status transport_destroy(bc_transport *api) {
    if (!api) return BC_INVALID_ARGUMENT;
    curl_backend *b = api->userdata;
    if (b->endpoints) {
        BC_LOG_WARN(BC_LOG_CATEGORY_LIFECYCLE, "transport.destroy", "status=busy");
        return BC_BUSY;
    }
    BC_LOG_INFO(BC_LOG_CATEGORY_LIFECYCLE, "transport.destroy", "status=ok");
    free(b);
    if (global_users && --global_users == 0) curl_global_cleanup();
    return BC_OK;
}

bc_status bc_curl_transport_create(bc_transport **out) {
    bc_mutex_lock(&global_lock); bc_status status=transport_create(out); bc_mutex_unlock(&global_lock); return status;
}
bc_status bc_curl_transport_destroy(bc_transport *transport) {
    bc_mutex_lock(&global_lock); bc_status status=transport_destroy(transport); bc_mutex_unlock(&global_lock); return status;
}

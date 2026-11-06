#define _POSIX_C_SOURCE 200809L
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include "media_pull.h"
#include "civetweb.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_BYTES 32
#define TOKEN_TEXT (TOKEN_BYTES * 2)
#define SOURCE_LIMIT 16
typedef struct {
    int used, removed;
    unsigned refs;
    char token[TOKEN_TEXT + 1];
    char *path;
    uint64_t size;
    bc_media_source stream;
    void (*release)(void *);
} source;
struct bc_media_pull {
    struct mg_context *context;
    char *advertise;
    source sources[SOURCE_LIMIT];
};
static int quiet_log(const struct mg_connection *c, const char *message) { (void)c; (void)message; return 1; }
static void clear_source(source *entry) {
    if (entry->release) entry->release(entry->stream.userdata);
    free(entry->path); OPENSSL_cleanse(entry, sizeof(*entry));
}
static int token_equal(const char *left, const char *right) {
    if (!left || !right || strlen(left) != TOKEN_TEXT || strlen(right) != TOKEN_TEXT) return 0;
    return CRYPTO_memcmp(left, right, TOKEN_TEXT) == 0;
}
static int send_status(struct mg_connection *c, int status, const char *message) {
    mg_printf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %" PRIu64 "\r\nConnection: close\r\n\r\n%s",
        status, mg_get_response_code_text(c, status), (uint64_t)strlen(message), message);
    return status;
}
static int file_seek(FILE *file, uint64_t offset) {
    if (offset > INT64_MAX) return -1;
#ifdef _WIN32
    return _fseeki64(file, (int64_t)offset, SEEK_SET);
#else
    if ((uint64_t)(off_t)offset != offset) return -1;
    return fseeko(file, (off_t)offset, SEEK_SET);
#endif
}
static uint64_t file_size(FILE *file) {
#ifdef _WIN32
    if (_fseeki64(file, 0, SEEK_END)) return 0;
    int64_t size = _ftelli64(file);
#else
    if (fseeko(file, 0, SEEK_END)) return 0;
    off_t size = ftello(file);
#endif
    return size > 0 ? (uint64_t)size : 0;
}
static int serve_range(struct mg_connection *c, bc_media_pull *pull, source *entry, uint64_t start, uint64_t end, int partial) {
    FILE *file = NULL;
    if (!entry->stream.read) {
        file = fopen(entry->path, "rb");
        if (!file) return send_status(c, 503, "source unavailable");
        if (file_seek(file, start)) { fclose(file); return send_status(c, 503, "source unavailable"); }
    }
    uint64_t length = end - start + 1, remaining = length;
    int headers = 0;
    uint8_t buffer[65536];
    while (remaining) {
        mg_lock_context(pull->context); int removed = entry->removed; mg_unlock_context(pull->context);
        if (removed) break;
        uint32_t want = remaining < sizeof(buffer) ? (uint32_t)remaining : (uint32_t)sizeof(buffer);
        if (entry->stream.read) {
            if (entry->stream.read(entry->stream.userdata, start + length - remaining, want, buffer) != BC_OK) break;
        } else if (fread(buffer, 1, want, file) != want) break;
        mg_lock_context(pull->context); removed = entry->removed; mg_unlock_context(pull->context);
        if (removed) break;
        if (!headers) {
            mg_printf(c, "HTTP/1.1 %d %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %" PRIu64
                "\r\nAccept-Ranges: bytes\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
                partial ? 206 : 200, partial ? "Partial Content" : "OK", length);
            if (partial) mg_printf(c, "Content-Range: bytes %" PRIu64 "-%" PRIu64 "/%" PRIu64 "\r\n", start, end, entry->size);
            mg_printf(c, "Connection: close\r\n\r\n"); headers = 1;
        }
        if (mg_write(c, buffer, want) != (int)want) break;
        remaining -= want;
    }
    if (file) fclose(file);
    return headers ? (partial ? 206 : 200) : send_status(c, 503, "source unavailable");
}
static source *acquire(bc_media_pull *pull, const char *token) {
    for (unsigned i = 0; i < SOURCE_LIMIT; ++i) {
        if (pull->sources[i].used && !pull->sources[i].removed && token_equal(pull->sources[i].token, token)) {
            ++pull->sources[i].refs;
            return &pull->sources[i];
        }
    }
    return NULL;
}
static void release(bc_media_pull *pull, source *entry) {
    (void)pull;
    if (--entry->refs == 0 && entry->removed) {
        clear_source(entry);
    }
}
static int range_number(const char **cursor, uint64_t *value) {
    const char *p = *cursor; uint64_t n = 0;
    if (*p < '0' || *p > '9') return 0;
    do {
        unsigned digit = (unsigned)(*p - '0');
        if (n > (UINT64_MAX - digit) / 10) return 0;
        n = n * 10 + digit; ++p;
    } while (*p >= '0' && *p <= '9');
    *cursor = p; *value = n; return 1;
}
static int parse_range(const char *value, uint64_t size, uint64_t *start, uint64_t *end) {
    if (!size) return 0;
    static const char prefix[] = "bytes=";
    for (size_t i = 0; i < sizeof(prefix) - 1; ++i)
        if (value[i] != prefix[i] && !(i < 5 && value[i] == prefix[i] - ('a' - 'A'))) return 0;
    const char *p = value + 6; uint64_t first = 0, last = size - 1;
    if (*p == '-') {
        ++p;
        if (!range_number(&p, &first) || !first) return 0;
        first = first < size ? size - first : 0;
    } else {
        if (!range_number(&p, &first) || *p++ != '-' || first >= size) return 0;
        if (*p >= '0' && *p <= '9') {
            if (!range_number(&p, &last) || last < first) return 0;
            if (last >= size) last = size - 1;
        }
    }
    while (*p == ' ' || *p == '\t') ++p;
    if (*p) return 0;
    *start = first; *end = last; return 1;
}
static int handler(struct mg_connection *c, void *userdata) {
    bc_media_pull *pull = userdata;
    const struct mg_request_info *info = mg_get_request_info(c);
    const char *method = info->request_method;
    if (strcmp(method, "GET") && strcmp(method, "HEAD")) return send_status(c, 405, "method not allowed");
    const char prefix[] = "/media/";
    const char *uri = info->local_uri;
    if (strncmp(uri, prefix, sizeof(prefix) - 1)) return send_status(c, 404, "not found");
    mg_lock_context(pull->context);
    source *entry = acquire(pull, uri + sizeof(prefix) - 1);
    uint64_t size = 0;
    if (entry) size = entry->size;
    mg_unlock_context(pull->context);
    if (!entry) return send_status(c, 404, "not found");
    int status;
    const char *range = mg_get_header(c, "Range");
    uint64_t start = 0, end = size ? size - 1 : 0;
    int partial = 0;
    if (range && !strcmp(method, "GET")) {
        if (!parse_range(range, size, &start, &end)) {
            mg_printf(c, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */%" PRIu64 "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", size);
            status = 416;
        } else { partial = 1; status = 0; }
    } else status = 0;
    if (!status) {
        if (!strcmp(method, "HEAD")) {
            mg_printf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %" PRIu64
                "\r\nAccept-Ranges: bytes\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", size);
            status = 200;
        } else {
            status = serve_range(c, pull, entry, start, end, partial);
        }
    }
    mg_lock_context(pull->context);
    release(pull, entry);
    mg_unlock_context(pull->context);
    return status;
}
static int random_token(char token[TOKEN_TEXT + 1]) {
    unsigned char bytes[TOKEN_BYTES];
    const char *hex = "0123456789abcdef";
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) return 0;
    for (unsigned i = 0; i < sizeof(bytes); ++i) { token[2 * i] = hex[bytes[i] >> 4]; token[2 * i + 1] = hex[bytes[i] & 15]; }
    token[TOKEN_TEXT] = 0;
    OPENSSL_cleanse(bytes, sizeof(bytes));
    return 1;
}
bc_media_pull *bc_media_pull_create(const char *listen, const char *advertise) {
    if (!listen || !advertise || strncmp(advertise, "http://", 7)) return NULL;
    for (const char *p = advertise; *p; ++p) if ((unsigned char)*p <= 32 || (unsigned char)*p >= 127) return NULL;
    bc_media_pull *pull = calloc(1, sizeof(*pull));
    if (!pull) return NULL;
    pull->advertise = malloc(strlen(advertise) + 1);
    if (!pull->advertise) { free(pull); return NULL; }
    strcpy(pull->advertise, advertise);
    const char *options[] = {"listening_ports", listen, "num_threads", "4", "enable_keep_alive", "no",
        "decode_url", "no", "request_timeout_ms", "10000", NULL, NULL};
    struct mg_callbacks callbacks = {0};
    callbacks.log_message = quiet_log;
    pull->context = mg_start(&callbacks, pull, options);
    if (!pull->context) { free(pull->advertise); free(pull); return NULL; }
    mg_set_request_handler(pull->context, "/media/", handler, pull);
    return pull;
}
static int register_source(bc_media_pull *pull, source *value, char token[65], char *url, size_t capacity) {
    char fresh[TOKEN_TEXT + 1];
    if (!random_token(fresh)) return 0;
    int written = snprintf(url, capacity, "%s/media/%s", pull->advertise, fresh);
    if (written < 0 || (size_t)written >= capacity) { OPENSSL_cleanse(fresh, sizeof(fresh)); return 0; }
    int added = 0;
    mg_lock_context(pull->context);
    for (unsigned i = 0; i < SOURCE_LIMIT; ++i) {
        if (pull->sources[i].used) continue;
        value->used = 1; memcpy(value->token, fresh, sizeof(fresh));
        pull->sources[i] = *value; memcpy(token, fresh, sizeof(fresh)); added = 1; break;
    }
    mg_unlock_context(pull->context); OPENSSL_cleanse(fresh, sizeof(fresh)); return added;
}
int bc_media_pull_add(bc_media_pull *pull, const char *path, char token[65], char *url, size_t capacity, uint64_t *size_out) {
    if (!pull || !path || !token || !url || !capacity) return 0;
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    uint64_t size = file_size(file); fclose(file);
    if (!size) return 0;
    source value = {0}; value.size = size;
    value.path = malloc(strlen(path) + 1);
    if (!value.path) return 0;
    strcpy(value.path, path);
    if (!register_source(pull, &value, token, url, capacity)) { free(value.path); return 0; }
    if (size_out) *size_out = value.size;
    return 1;
}
int bc_media_pull_add_source(bc_media_pull *pull, const bc_media_source *stream, void (*release_source)(void *), char token[65], char *url, size_t capacity) {
    if (!pull || !stream || stream->struct_size < sizeof(*stream) || !stream->read || !stream->size || !token || !url || !capacity) return 0;
    source value = {0}; value.size = stream->size; value.stream = *stream; value.release = release_source;
    return register_source(pull, &value, token, url, capacity);
}
void bc_media_pull_remove(bc_media_pull *pull, const char *token) {
    if (!pull || !token) return;
    mg_lock_context(pull->context);
    for (unsigned i = 0; i < SOURCE_LIMIT; ++i) {
        source *entry = &pull->sources[i];
        if (!entry->used || entry->removed || !token_equal(entry->token, token)) continue;
        entry->removed = 1;
        if (!entry->refs) clear_source(entry);
        break;
    }
    mg_unlock_context(pull->context);
}
void bc_media_pull_destroy(bc_media_pull *pull) {
    if (!pull) return;
    if (pull->context) mg_stop(pull->context);
    for (unsigned i = 0; i < SOURCE_LIMIT; ++i) clear_source(&pull->sources[i]);
    OPENSSL_cleanse(pull->advertise, strlen(pull->advertise));
    free(pull->advertise);
    free(pull);
}

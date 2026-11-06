#include "media_service.h"
#include "server.h"
#include "bcontrol/bcontrol.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SOURCE_LIMIT 4
#define SESSION_LIMIT 8
#define BLOCK_LIMIT 1048576u
typedef struct media_session media_session;
typedef struct {
    int used, invalid, connected, busy, result;
    char id[33], owner[33], name[121];
    unsigned char ticket[32];
    uint64_t size, expires, next_id, read_id, offset;
    uint32_t channel, length;
    unsigned char *data;
    unsigned leases;
    media_session *session;
} media_source;
struct media_session {
    int used, closing, authenticated, pins, opcode;
    struct mg_connection *connection;
    uint64_t opened;
    unsigned char *fragment;
    size_t length, capacity;
    media_source *source;
};
struct bc_media_service {
    struct mg_context *http;
    bc_media_hooks hooks;
    media_source sources[SOURCE_LIMIT];
    media_session sessions[SESSION_LIMIT];
    uint32_t channel;
    int stopping;
};
typedef struct { bc_media_service *service; media_source *source; } source_lease;
static int hash(const char *text, unsigned char output[32]) {
    unsigned length;
    return EVP_Digest(text, strlen(text), output, &length, EVP_sha256(), NULL) && length == 32;
}
static int random_hex(char *out, unsigned n) {
    unsigned char bytes[32]; const char *hex = "0123456789abcdef";
    if (n > sizeof(bytes) || RAND_bytes(bytes, (int)n) != 1) return 0;
    for (unsigned i = 0; i < n; ++i) { out[2*i] = hex[bytes[i] >> 4]; out[2*i+1] = hex[bytes[i] & 15]; }
    out[n*2] = 0; OPENSSL_cleanse(bytes, sizeof(bytes)); return 1;
}
static int decimal(const char *s, uint64_t *out) {
    if (!s || !*s || (s[0] == '0' && s[1])) return 0;
    uint64_t n = 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || n > (UINT64_MAX - (unsigned)(*s - '0')) / 10) return 0;
        n = n * 10 + (unsigned)(*s - '0');
    }
    *out = n; return 1;
}
static int error(struct mg_connection *c, bc_media_service *m, int code, const char *reason) {
    return m->hooks.error(c, m->hooks.userdata, code, reason);
}
static void describe(yyjson_mut_doc *d, yyjson_mut_val *out, const media_source *s) {
    char size[32]; snprintf(size, sizeof(size), "%" PRIu64, s->size);
    yyjson_mut_obj_add_strcpy(d, out, "source_id", s->id);
    yyjson_mut_obj_add_strcpy(d, out, "name", s->name);
    yyjson_mut_obj_add_strcpy(d, out, "size", size);
    yyjson_mut_obj_add_uint(d, out, "channel", s->channel);
    yyjson_mut_obj_add_uint(d, out, "max_block", BLOCK_LIMIT);
    yyjson_mut_obj_add_uint(d, out, "window", 1);
}
static int ticket(struct mg_connection *c, bc_media_service *m, const char *owner) {
    yyjson_doc *doc = bc_agent_read_json(c);
    if (!doc) return error(c, m, 400, "invalid_json");
    yyjson_val *root = yyjson_doc_get_root(doc);
    const char *name = bc_agent_json_field(root, "name", 120), *size = bc_agent_json_field(root, "size", 20);
    uint64_t length;
    if (!bc_agent_json_fields(root, "name", "size") || !name || !*name || !decimal(size, &length)) {
        yyjson_doc_free(doc); return error(c, m, 400, "invalid_source");
    }
    char id[33], secret[65]; unsigned char digest[32];
    if (!random_hex(id, 16) || !random_hex(secret, 32) || !hash(secret, digest)) {
        yyjson_doc_free(doc); return error(c, m, 500, "random_source_failed");
    }
    yyjson_mut_doc *out = yyjson_mut_doc_new(NULL); yyjson_mut_val *row = yyjson_mut_obj(out); yyjson_mut_doc_set_root(out, row);
    int found = 0;
    mg_lock_context(m->http);
    if (!m->stopping && m->channel != UINT32_MAX && m->hooks.client_active_locked(m->hooks.userdata, owner)) {
        for (int i = 0; i < SOURCE_LIMIT; ++i) if (!m->sources[i].used) {
            media_source *s = &m->sources[i]; memset(s, 0, sizeof(*s));
            s->used = 1; s->size = length; s->expires = bc_agent_now_ms() + 60000; s->channel = ++m->channel;
            memcpy(s->id, id, sizeof(id)); memcpy(s->owner, owner, 33); memcpy(s->ticket, digest, 32);
            snprintf(s->name, sizeof(s->name), "%s", name); describe(out, row, s); found = 1; break;
        }
    }
    mg_unlock_context(m->http); yyjson_doc_free(doc); OPENSSL_cleanse(digest, sizeof(digest));
    if (!found) { yyjson_mut_doc_free(out); OPENSSL_cleanse(secret, sizeof(secret)); return error(c, m, 409, "source_limit"); }
    yyjson_mut_obj_add_strcpy(out, row, "ticket", secret); yyjson_mut_obj_add_str(out, row, "websocket_path", "/v1/media/ws");
    yyjson_mut_obj_add_uint(out, row, "expires_in_ms", 60000); OPENSSL_cleanse(secret, sizeof(secret));
    return m->hooks.json(c, m->hooks.userdata, 201, out);
}
static void close_frame(struct mg_connection *c, unsigned code) {
    const char bytes[2] = {(char)(code >> 8), (char)code};
    mg_websocket_write(c, MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE, bytes, 2);
}
static int utf8_valid(const unsigned char *data, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char first = data[i++];
        if (first < 128) continue;
        unsigned count;
        uint32_t value, minimum;
        if (first >= 0xc2 && first <= 0xdf) { count = 1; value = first & 31; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { count = 2; value = first & 15; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { count = 3; value = first & 7; minimum = 0x10000; }
        else return 0;
        if (count > n - i) return 0;
        while (count--) { unsigned char c = data[i++]; if ((c & 0xc0) != 0x80) return 0; value = (value << 6) | (c & 63); }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return 0;
    }
    return 1;
}
static int connect_ws(const struct mg_connection *c, void *userdata) {
    bc_media_service *m = userdata;
    const struct mg_request_info *ri = mg_get_request_info(c);
    return !m->hooks.allowed(c, m->hooks.userdata) || !ri->local_uri || strcmp(ri->local_uri, "/v1/media/ws");
}
static void ready_ws(struct mg_connection *c, void *userdata) {
    bc_media_service *m = userdata; media_session *session = NULL;
    mg_lock_context(m->http);
    if (!m->stopping) for (int i = 0; i < SESSION_LIMIT; ++i) if (!m->sessions[i].used) {
        session = &m->sessions[i]; memset(session, 0, sizeof(*session));
        session->used = 1; session->connection = c; session->opened = bc_agent_now_ms(); break;
    }
    mg_set_user_connection_data(c, session); mg_unlock_context(m->http);
    if (!session) { close_frame(c, 1013); mg_bcontrol_shutdown(c); }
}
static int authenticate_ws(struct mg_connection *c, bc_media_service *m, media_session *session, const char *data, size_t size) {
    if (size > 1024) return 0;
    yyjson_doc *doc = yyjson_read(data, size, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    const char *secret = root && yyjson_is_obj(root) ? bc_agent_json_field(root, "ticket", 64) : NULL;
    unsigned char digest[32]; int ok = secret && strlen(secret) == 64 && bc_agent_json_fields(root, "ticket", NULL) && hash(secret, digest);
    yyjson_mut_doc *answer = yyjson_mut_doc_new(NULL); yyjson_mut_val *out = yyjson_mut_obj(answer); yyjson_mut_doc_set_root(answer, out);
    int found = 0;
    mg_lock_context(m->http);
    if (ok && !session->closing) for (int i = 0; i < SOURCE_LIMIT; ++i) {
        media_source *s = &m->sources[i];
        if (s->used && !s->invalid && !s->connected && s->expires > bc_agent_now_ms() &&
            !CRYPTO_memcmp(s->ticket, digest, 32) && m->hooks.client_active_locked(m->hooks.userdata, s->owner)) {
            s->connected = 1; s->session = session; s->expires = 0; OPENSSL_cleanse(s->ticket, 32);
            session->source = s;
            describe(answer, out, s); yyjson_mut_obj_add_str(answer, out, "type", "ready"); found = 1; break;
        }
    }
    mg_unlock_context(m->http); OPENSSL_cleanse(digest, sizeof(digest));
    if (doc) yyjson_doc_free(doc);
    size_t length; char *json = found ? yyjson_mut_write(answer, 0, &length) : NULL;
    int sent = json && mg_websocket_write(c, MG_WEBSOCKET_OPCODE_TEXT, json, length) > 0;
    mg_lock_context(m->http);
    if (found && sent && !session->closing) session->authenticated = 1;
    int authenticated = session->authenticated;
    mg_unlock_context(m->http);
    free(json); yyjson_mut_doc_free(answer); return authenticated;
}
static int consume(struct mg_connection *c, bc_media_service *m, media_session *session, int opcode, const unsigned char *data, size_t size) {
    if (opcode == MG_WEBSOCKET_OPCODE_TEXT && !utf8_valid(data, size)) { close_frame(c, 1007); return -1; }
    if (!session->authenticated) return opcode == MG_WEBSOCKET_OPCODE_TEXT && authenticate_ws(c, m, session, (const char *)data, size);
    if (opcode != MG_WEBSOCKET_OPCODE_BINARY) return 0;
    bc_media_header h;
    if (bc_media_header_decode(data, size, BLOCK_LIMIT, &h) != BC_OK || (h.opcode != BC_MEDIA_DATA && h.opcode != BC_MEDIA_ERROR)) return 0;
    int ok = 0;
    mg_lock_context(m->http);
    media_source *s = session->source;
    if (!session->closing && s && !s->invalid && m->hooks.client_active_locked(m->hooks.userdata, s->owner) && s->busy && !s->result && h.channel == s->channel && h.request_id == s->read_id && h.offset == s->offset) {
        if (h.opcode == BC_MEDIA_DATA && h.payload_length == s->length) {
            s->data = malloc(s->length);
            if (s->data) { memcpy(s->data, data + 40, s->length); s->result = 1; ok = 1; }
        } else if (h.opcode == BC_MEDIA_ERROR && h.payload_length <= 1024) {
            yyjson_doc *error_doc = yyjson_read((const char *)data + 40, h.payload_length, 0);
            yyjson_val *root = error_doc ? yyjson_doc_get_root(error_doc) : NULL;
            if (root && yyjson_is_obj(root) && bc_agent_json_fields(root, "error", NULL) && bc_agent_json_field(root, "error", 64)) { s->result = -2; ok = 1; }
            if (error_doc) yyjson_doc_free(error_doc);
        }
    }
    mg_unlock_context(m->http); return ok;
}
static int data_ws(struct mg_connection *c, int bits, char *data, size_t size, void *userdata) {
    bc_media_service *m = userdata;
    media_session *session = mg_get_user_connection_data(c);
    if (!session) return 0;
    mg_lock_context(m->http); int closing = session->closing; mg_unlock_context(m->http);
    if (closing) return 0;
    int opcode = bits & 15, final = bits & 128;
    if (opcode == MG_WEBSOCKET_OPCODE_PING) { mg_websocket_write(c, MG_WEBSOCKET_OPCODE_PONG, data, size); return 1; }
    if (opcode == MG_WEBSOCKET_OPCODE_PONG) return 1;
    if (opcode == MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE) {
        unsigned code = size >= 2 ? ((unsigned char)data[0] << 8) | (unsigned char)data[1] : 1000;
        if (size == 1 || (size >= 2 && ((code < 1000 || code >= 5000) || (code >= 1004 && code <= 1006) || code == 1015 || (code >= 1016 && code < 3000)))) close_frame(c, 1002);
        else if (size > 2 && !utf8_valid((unsigned char *)data + 2, size - 2)) close_frame(c, 1007);
        else mg_websocket_write(c, MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE, data, size);
        return 0;
    }
    size_t limit = session->authenticated ? BLOCK_LIMIT + 40u : 1024u;
    if ((opcode && session->opcode) || (!opcode && !session->opcode)) { close_frame(c, 1002); return 0; }
    if (size > limit - session->length) { close_frame(c, 1009); return 0; }
    if (final && !session->opcode) {
        int ok = consume(c, m, session, opcode, (unsigned char *)data, size);
        if (!ok) close_frame(c, 1008);
        return ok > 0;
    }
    if (opcode) session->opcode = opcode;
    size_t needed = session->length + size;
    if (needed > session->capacity) {
        size_t capacity = session->capacity ? session->capacity : 1024;
        while (capacity < needed) capacity *= 2;
        if (capacity > limit) capacity = limit;
        unsigned char *buffer = realloc(session->fragment, capacity);
        if (!buffer) { close_frame(c, 1011); return 0; }
        session->fragment = buffer; session->capacity = capacity;
    }
    if (size) memcpy(session->fragment + session->length, data, size);
    session->length += size;
    if (!final) return 1;
    int ok = consume(c, m, session, session->opcode, session->fragment, session->length);
    session->length = 0; session->opcode = 0;
    if (!ok) close_frame(c, 1008);
    return ok > 0;
}
static void closed_ws(const struct mg_connection *c, void *userdata) {
    bc_media_service *m = userdata; media_session *session = mg_get_user_connection_data(c);
    if (!session) return;
    mg_lock_context(m->http); session->closing = 1;
    if (session->source) {
        media_source *s = session->source; s->connected = 0; s->invalid = 1; s->session = NULL;
        if (s->busy && !s->result) s->result = -1;
    }
    mg_unlock_context(m->http);
    for (;;) {
        mg_lock_context(m->http); int pins = session->pins; mg_unlock_context(m->http);
        if (!pins) break;
        bc_agent_sleep(1);
    }
    mg_lock_context(m->http); free(session->fragment); memset(session, 0, sizeof(*session)); mg_unlock_context(m->http);
}
static bc_status read_bytes(bc_media_service *m, media_source *s, uint64_t offset, uint32_t length,
                            int wait_busy, unsigned char **bytes) {
    *bytes = NULL;
    if (!length || length > BLOCK_LIMIT || bc_media_range_check(s->size, offset, length) != BC_OK) return BC_INVALID_ARGUMENT;
    uint64_t deadline = bc_agent_now_ms() + 5000;
    media_session *session = NULL; uint8_t request[44];
    for (;;) {
        mg_lock_context(m->http);
        if (bc_agent_now_ms() >= deadline) { mg_unlock_context(m->http); return BC_TIMEOUT; }
        if (m->stopping || s->invalid || !s->connected || !s->session || !s->session->authenticated ||
            s->session->closing || !m->hooks.client_active_locked(m->hooks.userdata, s->owner)) {
            mg_unlock_context(m->http); return BC_IO_ERROR;
        }
        if (!s->busy) {
            if (s->next_id == UINT64_MAX) { mg_unlock_context(m->http); return BC_LIMIT_EXCEEDED; }
            bc_media_header h = {BC_MEDIA_READ, s->channel, 0, ++s->next_id, offset, 4, 0};
            bc_status status = bc_media_read_encode(&h, length, s->size, BLOCK_LIMIT, request);
            if (status != BC_OK) { mg_unlock_context(m->http); return status; }
            s->busy = 1; s->result = 0; s->read_id = h.request_id; s->offset = offset; s->length = length;
            session = s->session; ++session->pins;
            mg_unlock_context(m->http); break;
        }
        mg_unlock_context(m->http);
        if (!wait_busy) return BC_BUSY;
        if (bc_agent_now_ms() >= deadline) return BC_TIMEOUT;
        bc_agent_sleep(2);
    }
    int sent = mg_websocket_write(session->connection, MG_WEBSOCKET_OPCODE_BINARY, (const char *)request, sizeof(request));
    mg_lock_context(m->http); --session->pins;
    if (sent <= 0) { s->result = -1; s->invalid = 1; }
    mg_unlock_context(m->http);
    int result;
    for (;;) {
        mg_lock_context(m->http);
        if (m->stopping || s->invalid || !m->hooks.client_active_locked(m->hooks.userdata, s->owner)) { s->result = -1; s->invalid = 1; }
        if (!s->result && bc_agent_now_ms() >= deadline) { s->result = -3; s->invalid = 1; }
        result = s->result;
        if (result) { *bytes = s->data; s->data = NULL; s->busy = 0; }
        mg_unlock_context(m->http);
        if (result) break;
        bc_agent_sleep(2);
    }
    if (result == 1) return BC_OK;
    free(*bytes); *bytes = NULL;
    return result == -3 ? BC_TIMEOUT : result == -2 ? BC_PROTOCOL_ERROR : BC_IO_ERROR;
}
static bc_status leased_read(void *userdata, uint64_t offset, uint32_t length, uint8_t *output) {
    source_lease *lease = userdata;
    if (!lease || !output) return BC_INVALID_ARGUMENT;
    unsigned char *bytes = NULL;
    bc_status status = read_bytes(lease->service, lease->source, offset, length, 1, &bytes);
    if (status == BC_OK) memcpy(output, bytes, length);
    free(bytes); return status;
}
int bc_media_service_source_active_locked(bc_media_service *m, const char *owner, const char *id) {
    if (!m || !owner || !id || m->stopping) return 0;
    for (unsigned i = 0; i < SOURCE_LIMIT; ++i) {
        media_source *s = &m->sources[i];
        if (s->used && !s->invalid && !strcmp(s->owner, owner) && !strcmp(s->id, id) && s->connected &&
            s->session && s->session->authenticated && !s->session->closing) return 1;
    }
    return 0;
}
bc_status bc_media_service_source_acquire(bc_media_service *m, const char *owner, const char *id, bc_media_source *out) {
    if (!m || !owner || !id || !out || strlen(owner) != 32 || strlen(id) != 32) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    source_lease *lease = calloc(1, sizeof(*lease));
    if (!lease) return BC_NO_MEMORY;
    mg_lock_context(m->http);
    if (!m->stopping && m->hooks.client_active_locked(m->hooks.userdata, owner)) {
        for (unsigned i = 0; i < SOURCE_LIMIT; ++i) {
            media_source *s = &m->sources[i];
            if (!s->used || s->invalid || strcmp(s->owner, owner) || strcmp(s->id, id) || !s->connected ||
                !s->session || !s->session->authenticated || s->session->closing || s->leases >= 16) continue;
            ++s->leases; lease->service = m; lease->source = s;
            *out = (bc_media_source){sizeof(*out), lease, s->size, leased_read}; break;
        }
    }
    mg_unlock_context(m->http);
    if (!lease->source) { free(lease); return BC_UNSUPPORTED; }
    return BC_OK;
}
void bc_media_service_source_release(void *userdata) {
    source_lease *lease = userdata;
    if (!lease) return;
    mg_lock_context(lease->service->http); --lease->source->leases; mg_unlock_context(lease->service->http);
    free(lease);
}
static int read_source(struct mg_connection *c, bc_media_service *m, const char *id) {
    yyjson_doc *doc = bc_agent_read_json(c);
    if (!doc) return error(c, m, 400, "invalid_json");
    yyjson_val *root = yyjson_doc_get_root(doc), *length_value = yyjson_obj_get(root, "length");
    uint64_t offset = 0, length = yyjson_get_uint(length_value);
    int valid = bc_agent_json_fields(root, "offset", "length") && decimal(bc_agent_json_field(root, "offset", 20), &offset) && yyjson_is_uint(length_value) && length && length <= BLOCK_LIMIT;
    yyjson_doc_free(doc);
    if (!valid) return error(c, m, 400, "invalid_read");
    media_source *s = NULL;
    mg_lock_context(m->http);
    for (unsigned i = 0; i < SOURCE_LIMIT; ++i) if (m->sources[i].used && !strcmp(m->sources[i].id, id)) {
        s = &m->sources[i]; ++s->leases; break;
    }
    mg_unlock_context(m->http);
    if (!s) return error(c, m, 404, "source_unavailable");
    unsigned char *bytes = NULL;
    bc_status read = read_bytes(m, s, offset, (uint32_t)length, 0, &bytes);
    mg_lock_context(m->http); --s->leases; mg_unlock_context(m->http);
    char client_id[33];
    if (!m->hooks.authorize(c, m->hooks.userdata, client_id)) { free(bytes); return error(c, m, 401, "client_revoked"); }
    int status = read == BC_OK ? m->hooks.bytes(c, m->hooks.userdata, bytes, (size_t)length) :
        error(c, m, read == BC_BUSY ? 409 : read == BC_INVALID_ARGUMENT ? 416 : read == BC_TIMEOUT ? 504 : read == BC_PROTOCOL_ERROR ? 502 : 410,
              read == BC_BUSY ? "source_busy" : read == BC_INVALID_ARGUMENT ? "invalid_range" : "source_read_failed");
    free(bytes); return status;
}
int bc_media_service_http(bc_media_service *m, struct mg_connection *c, const char *path, const char *method) {
    if (strncmp(path, "/v1/media/", 10)) return 0;
    char owner[33];
    if (!m->hooks.authorize(c, m->hooks.userdata, owner)) return error(c, m, 401, "authentication_required");
    if (!strcmp(path, "/v1/media/tickets") && !strcmp(method, "POST")) return ticket(c, m, owner);
    if (!strcmp(path, "/v1/media/sources") && !strcmp(method, "GET")) {
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *out = yyjson_mut_arr(doc); yyjson_mut_doc_set_root(doc, out);
        mg_lock_context(m->http);
        for (int i = 0; i < SOURCE_LIMIT; ++i) if (m->sources[i].used && !m->sources[i].invalid) {
            yyjson_mut_val *row = yyjson_mut_obj(doc); describe(doc, row, &m->sources[i]);
            yyjson_mut_obj_add_bool(doc, row, "connected", m->sources[i].connected && m->sources[i].session && m->sources[i].session->authenticated); yyjson_mut_arr_append(out, row);
        }
        mg_unlock_context(m->http); return m->hooks.json(c, m->hooks.userdata, 200, doc);
    }
    const char *prefix = "/v1/media/sources/";
    size_t n = strlen(prefix);
    if (!strncmp(path, prefix, n) && strlen(path + n) >= 32) {
        char id[33]; memcpy(id, path + n, 32); id[32] = 0;
        if (!strcmp(path + n + 32, "/read") && !strcmp(method, "POST")) return read_source(c, m, id);
        if (!path[n + 32] && !strcmp(method, "DELETE")) {
            int found = 0; mg_lock_context(m->http);
            for (int i = 0; i < SOURCE_LIMIT; ++i) if (m->sources[i].used && !strcmp(m->sources[i].id, id)) { m->sources[i].invalid = 1; found = 1; }
            mg_unlock_context(m->http); return error(c, m, found ? 200 : 404, found ? "source_closed" : "not_found");
        }
    }
    return error(c, m, 404, "not_found");
}
bc_media_service *bc_media_service_create(struct mg_context *http, const bc_media_hooks *hooks) {
    bc_media_service *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->http = http; m->hooks = *hooks;
    mg_set_websocket_handler(http, "/v1/media/ws", connect_ws, ready_ws, data_ws, closed_ws, m);
    return m;
}
void bc_media_service_tick(bc_media_service *m) {
    media_session *closing[SESSION_LIMIT]; size_t count = 0;
    mg_lock_context(m->http);
    uint64_t now = bc_agent_now_ms();
    for (int i = 0; i < SOURCE_LIMIT; ++i) {
        media_source *s = &m->sources[i];
        if (!s->used) continue;
        if (m->stopping || !m->hooks.client_active_locked(m->hooks.userdata, s->owner) || (s->expires && now >= s->expires)) s->invalid = 1;
        if (s->invalid && s->busy && !s->result) s->result = -1;
        if (s->invalid && !s->busy && !s->connected && !s->leases) { free(s->data); memset(s, 0, sizeof(*s)); }
    }
    for (int i = 0; i < SESSION_LIMIT; ++i) {
        media_session *s = &m->sessions[i];
        if (s->used && !s->closing && (m->stopping || (!s->authenticated && now - s->opened >= 5000) || (s->source && s->source->invalid))) {
            s->closing = 1; ++s->pins; closing[count++] = s;
        }
    }
    mg_unlock_context(m->http);
    for (size_t i = 0; i < count; ++i) {
        media_session *s = closing[i]; close_frame(s->connection, 1008); mg_bcontrol_shutdown(s->connection);
        mg_lock_context(m->http); --s->pins; mg_unlock_context(m->http);
    }
}
void bc_media_service_shutdown(bc_media_service *m) {
    mg_lock_context(m->http); m->stopping = 1; mg_unlock_context(m->http); bc_media_service_tick(m);
}
void bc_media_service_destroy(bc_media_service *m) {
    if (!m) return;
    for (int i = 0; i < SOURCE_LIMIT; ++i) free(m->sources[i].data);
    for (int i = 0; i < SESSION_LIMIT; ++i) free(m->sessions[i].fragment);
    OPENSSL_cleanse(m, sizeof(*m)); free(m);
}

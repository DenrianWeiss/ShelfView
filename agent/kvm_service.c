#include "kvm_service.h"
#include "server.h"
#include "openssl/evp.h"
#include "bcontrol/bcontrol.h"
#include "bcontrol/kvm_transport.h"
#include "bcontrol/kvm_session.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define TICKET_LIMIT 8
#define SESSION_LIMIT 8
#define QUEUE_LIMIT (1u * 1024u * 1024u)
#define TICKET_TTL_MS 60000u
typedef struct { int used; char owner[33]; unsigned char digest[32]; uint64_t expires; } ticket;
typedef struct {
    int used, closing, authenticated, connected;
    char owner[33];
    struct mg_connection *connection;
    uint64_t opened;
    uint8_t opcode;
    uint8_t *fragment;
    size_t length, capacity;
    uint8_t *pending;
    size_t pending_length, pending_offset;
    bc_kvm_transport *transport;
    bc_console_session *input;
    uint8_t input_bytes[128];
    uint32_t input_length;
} kvm_session;
struct bc_kvm_service {
    struct mg_context *http;
    bc_kvm_hooks hooks;
    bc_agent_kvm_options options;
    char *url, *ca_file;
    bc_string *headers;
    ticket tickets[TICKET_LIMIT];
    kvm_session sessions[SESSION_LIMIT];
    int stopping;
};
static int connect_ws(const struct mg_connection *, void *);
static void ready_ws(struct mg_connection *, void *);
static int data_ws(struct mg_connection *, int, char *, size_t, void *);
static void closed_ws(const struct mg_connection *, void *);
static bc_status encode_input(void *user, const uint8_t *bytes, uint32_t length) {
    kvm_session *session = user;
    if (length > sizeof(session->input_bytes) - session->input_length) return BC_LIMIT_EXCEEDED;
    memcpy(session->input_bytes + session->input_length, bytes, length);
    session->input_length += length;
    return BC_OK;
}
static char *copy_string(const char *value) {
    if (!value) return NULL;
    char *copy = malloc(strlen(value) + 1);
    if (copy) strcpy(copy, value);
    return copy;
}
bc_kvm_service *bc_kvm_service_create(struct mg_context *http, const bc_kvm_hooks *hooks, const bc_agent_kvm_options *options) {
    if (!http || !hooks || !options || !options->url || !*options->url ||
        options->cert_policy > BC_CERT_SKIP_ALL || options->header_count > 16 ||
        (options->header_count && !options->headers)) return NULL;
    bc_kvm_service *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->http = http; s->hooks = *hooks;
    s->url = copy_string(options->url);
    s->ca_file = copy_string(options->ca_file);
    if (!s->url || (options->ca_file && !s->ca_file)) goto fail;
    if (options->header_count) {
        s->headers = calloc(options->header_count, sizeof(*s->headers));
        if (!s->headers) goto fail;
        for (uint32_t i = 0; i < options->header_count; ++i) {
            size_t length = options->headers[i].length;
            char *copy = malloc(length + 1);
            if (!copy) goto fail;
            memcpy(copy, options->headers[i].data, length); copy[length] = 0;
            s->headers[i] = (bc_string){copy, length};
        }
    }
    s->options = *options;
    s->options.management_device_id = copy_string(options->management_device_id);
    if (options->management_device_id && !s->options.management_device_id) goto fail;
    s->options.url = s->url; s->options.ca_file = s->ca_file; s->options.headers = s->headers;
    if (!s->options.timeout_ms) s->options.timeout_ms = 5000;
    mg_set_websocket_handler(http, "/v1/kvm/ws", connect_ws, ready_ws, data_ws, closed_ws, s);
    return s;
fail:
    if (s->headers) for (uint32_t i = 0; i < options->header_count; ++i) free((void *)s->headers[i].data);
    free((void *)s->options.management_device_id);
    free(s->headers); free(s->url); free(s->ca_file); free(s);
    return NULL;
}
static int hash(const char *text, unsigned char out[32]) {
    unsigned length = 0;
    return EVP_Digest(text, strlen(text), out, &length, EVP_sha256(), NULL) && length == 32;
}
static void close_frame(struct mg_connection *c, unsigned code) {
    const char body[2] = {(char)(code >> 8), (char)code};
    mg_websocket_write(c, MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE, body, 2);
}
static int ticket_route(struct mg_connection *c, bc_kvm_service *s) {
    char owner[33];
    if (!s->hooks.authorize(c, s->hooks.userdata, owner)) return s->hooks.error(c, s->hooks.userdata, 401, "client_revoked");
    unsigned char secret_bytes[32], digest[32];
    const char *hex = "0123456789abcdef";
    char secret[65];
    if (RAND_bytes(secret_bytes, sizeof(secret_bytes)) != 1) return s->hooks.error(c, s->hooks.userdata, 500, "random_source_failed");
    for (unsigned i = 0; i < sizeof(secret_bytes); ++i) { secret[2 * i] = hex[secret_bytes[i] >> 4]; secret[2 * i + 1] = hex[secret_bytes[i] & 15]; }
    secret[64] = 0;
    hash(secret, digest);
    int found = 0;
    mg_lock_context(s->http);
    for (int i = 0; i < TICKET_LIMIT; ++i) if (!s->tickets[i].used) {
        s->tickets[i].used = 1; memcpy(s->tickets[i].owner, owner, 33);
        memcpy(s->tickets[i].digest, digest, 32);
        s->tickets[i].expires = bc_agent_now_ms() + TICKET_TTL_MS;
        found = 1; break;
    }
    mg_unlock_context(s->http);
    OPENSSL_cleanse(secret_bytes, sizeof(secret_bytes)); OPENSSL_cleanse(digest, sizeof(digest));
    if (!found) { OPENSSL_cleanse(secret, sizeof(secret)); return s->hooks.error(c, s->hooks.userdata, 409, "ticket_limit"); }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_strcpy(doc, root, "ticket", secret);
    yyjson_mut_obj_add_strcpy(doc, root, "websocket_path", "/v1/kvm/ws");
    yyjson_mut_obj_add_uint(doc, root, "expires_in_ms", TICKET_TTL_MS);
    yyjson_mut_obj_add_uint(doc, root, "input_version", 1);
    if (s->options.management_device_id)
        yyjson_mut_obj_add_strcpy(doc, root, "management_device_id", s->options.management_device_id);
    OPENSSL_cleanse(secret, sizeof(secret));
    return s->hooks.json(c, s->hooks.userdata, 201, doc);
}
int bc_kvm_service_http(bc_kvm_service *s, struct mg_connection *c, const char *path, const char *method) {
    if (!s) return 0;
    if (!strcmp(path, "/v1/kvm/tickets") && !strcmp(method, "POST")) return ticket_route(c, s);
    return 0;
}
static int connect_ws(const struct mg_connection *c, void *userdata) {
    bc_kvm_service *s = userdata;
    const struct mg_request_info *ri = mg_get_request_info(c);
    return !s->hooks.allowed(c, s->hooks.userdata) || !ri->local_uri || strcmp(ri->local_uri, "/v1/kvm/ws");
}
static void ready_ws(struct mg_connection *c, void *userdata) {
    bc_kvm_service *s = userdata;
    kvm_session *session = NULL;
    mg_lock_context(s->http);
    if (!s->stopping) for (int i = 0; i < SESSION_LIMIT; ++i) if (!s->sessions[i].used) {
        kvm_session *candidate = &s->sessions[i]; memset(candidate, 0, sizeof(*candidate));
        if (bc_kvm_input_wrap(encode_input, candidate, &candidate->input) != BC_OK) break;
        session = candidate;
        session->used = 1; session->connection = c; session->opened = bc_agent_now_ms(); break;
    }
    mg_set_user_connection_data(c, session);
    mg_unlock_context(s->http);
    if (!session) { close_frame(c, 1013); mg_bcontrol_shutdown(c); }
}
static int authenticate_ws(struct mg_connection *c, bc_kvm_service *s, kvm_session *session, const char *data, size_t size) {
    if (size > 1024) return 0;
    yyjson_doc *doc = yyjson_read(data, size, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    const char *secret = root && yyjson_is_obj(root) ? bc_agent_json_field(root, "ticket", 64) : NULL;
    unsigned char digest[32];
    int ok = secret && strlen(secret) == 64 && bc_agent_json_fields(root, "ticket", NULL) && hash(secret, digest);
    int found = 0;
    mg_lock_context(s->http);
    if (ok && !session->closing) for (int i = 0; i < TICKET_LIMIT; ++i) {
        ticket *ticket = &s->tickets[i];
        if (ticket->used && ticket->expires > bc_agent_now_ms() && !CRYPTO_memcmp(ticket->digest, digest, 32) &&
            s->hooks.client_active_locked(s->hooks.userdata, ticket->owner)) {
            ticket->used = 0; OPENSSL_cleanse(ticket->digest, 32);
            memcpy(session->owner, ticket->owner, sizeof(session->owner));
            session->authenticated = 1; found = 1; break;
        }
    }
    mg_unlock_context(s->http);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (doc) yyjson_doc_free(doc);
    if (!found) return 0;
    char ready[80];
    int length = snprintf(ready, sizeof(ready), "{\"type\":\"ready\",\"input_capabilities\":%" PRIu32 "}",
        bc_console_session_input_capabilities(session->input));
    return length > 0 && (size_t)length < sizeof(ready) &&
        mg_websocket_write(c, MG_WEBSOCKET_OPCODE_TEXT, ready, (size_t)length) > 0;
}
static void mark_closing(bc_kvm_service *s, kvm_session *session) {
    mg_lock_context(s->http); session->closing = 1; mg_unlock_context(s->http);
}
static int session_write(bc_kvm_service *s, kvm_session *session, const uint8_t *data, size_t size) {
    mg_lock_context(s->http);
    int result = session->connection && !session->closing &&
        mg_websocket_write(session->connection, MG_WEBSOCKET_OPCODE_BINARY, (const char *)data, size) > 0;
    mg_unlock_context(s->http);
    return result;
}
static int queue_bytes(kvm_session *session, const uint8_t *data, size_t size) {
    if (session->pending_offset) {
        memmove(session->pending, session->pending + session->pending_offset, session->pending_length - session->pending_offset);
        session->pending_length -= session->pending_offset; session->pending_offset = 0;
    }
    if (session->pending_length + size > QUEUE_LIMIT) return 0;
    uint8_t *grown = realloc(session->pending, session->pending_length + size);
    if (!grown) return 0;
    session->pending = grown;
    memcpy(session->pending + session->pending_length, data, size);
    session->pending_length += size;
    return 1;
}
static int input_uint(yyjson_val *root, const char *key, uint32_t *out) {
    yyjson_val *value = yyjson_obj_get(root, key);
    if (!yyjson_is_uint(value) || yyjson_get_uint(value) > UINT32_MAX) return 0;
    *out = (uint32_t)yyjson_get_uint(value);
    return 1;
}
static bc_status input_event(kvm_session *session, yyjson_val *root) {
    if (!yyjson_is_obj(root) || yyjson_obj_size(root) != 2 || !bc_agent_json_fields(root, "type", "event"))
        return BC_INVALID_ARGUMENT;
    const char *type = bc_agent_json_field(root, "type", 16);
    yyjson_val *value = yyjson_obj_get(root, "event");
    const char *event = yyjson_is_obj(value) ? bc_agent_json_field(value, "type", 16) : NULL;
    if (!type || strcmp(type, "input") || !event) return BC_INVALID_ARGUMENT;
    size_t fields = yyjson_obj_size(value);
    if (!strcmp(event, "chord")) {
        yyjson_val *keys = yyjson_obj_get(value, "keys");
        size_t count = yyjson_arr_size(keys);
        if (fields != 2 || !yyjson_is_arr(keys) || !count || count > 8) return BC_INVALID_ARGUMENT;
        uint32_t keysyms[8];
        for (size_t i = 0; i < count; ++i) {
            yyjson_val *key = yyjson_arr_get(keys, i);
            if (!yyjson_is_uint(key) || yyjson_get_uint(key) > UINT32_MAX) return BC_INVALID_ARGUMENT;
            keysyms[i] = (uint32_t)yyjson_get_uint(key);
        }
        return bc_console_session_chord(session->input, keysyms, (uint32_t)count);
    }
    bc_console_input input = {0}; input.struct_size = sizeof(input);
    if (!strcmp(event, "key")) {
        yyjson_val *down = yyjson_obj_get(value, "down");
        if (fields != 3 || !yyjson_is_bool(down) || !input_uint(value, "keysym", &input.keysym)) return BC_INVALID_ARGUMENT;
        input.type = BC_CONSOLE_INPUT_KEY; input.down = yyjson_get_bool(down);
    } else {
        int scroll = !strcmp(event, "scroll");
        if ((!scroll && strcmp(event, "pointer")) || fields != (scroll ? 7u : 6u) ||
            !input_uint(value, "x", &input.x) || !input_uint(value, "y", &input.y) ||
            !input_uint(value, "buttons", &input.buttons) || !input_uint(value, "width", &input.width) ||
            !input_uint(value, "height", &input.height)) return BC_INVALID_ARGUMENT;
        input.type = scroll ? BC_CONSOLE_INPUT_SCROLL : BC_CONSOLE_INPUT_POINTER;
        if (scroll) {
            yyjson_val *wheel = yyjson_obj_get(value, "wheel");
            if (!yyjson_is_int(wheel) || (yyjson_is_uint(wheel) && yyjson_get_uint(wheel) > 127) ||
                yyjson_get_sint(wheel) < -127 || yyjson_get_sint(wheel) > 127) return BC_INVALID_ARGUMENT;
            input.wheel = (int32_t)yyjson_get_sint(wheel);
        }
    }
    return bc_console_session_input(session->input, &input);
}
static void consume_ws(struct mg_connection *c, bc_kvm_service *s, kvm_session *session, int opcode, const uint8_t *data, size_t size) {
    if (!session->authenticated) {
        if (opcode == MG_WEBSOCKET_OPCODE_TEXT && !authenticate_ws(c, s, session, (const char *)data, size)) {
            close_frame(c, 1008); mark_closing(s, session);
        }
        return;
    }
    if (opcode == MG_WEBSOCKET_OPCODE_TEXT) {
        yyjson_doc *doc = size <= 1024 ? yyjson_read((const char *)data, size, 0) : NULL;
        mg_lock_context(s->http);
        session->input_length = 0;
        bc_status status = !session->closing && doc ? input_event(session, yyjson_doc_get_root(doc)) : BC_INVALID_ARGUMENT;
        if (status == BC_OK && session->input_length && !queue_bytes(session, session->input_bytes, session->input_length))
            status = BC_LIMIT_EXCEEDED;
        mg_unlock_context(s->http);
        if (doc) yyjson_doc_free(doc);
        if (status != BC_OK) { close_frame(c, status == BC_LIMIT_EXCEEDED ? 1009 : 1008); mark_closing(s, session); }
        return;
    }
    if (opcode != MG_WEBSOCKET_OPCODE_BINARY) return;
    mg_lock_context(s->http);
    int ok = !session->closing && queue_bytes(session, data, size);
    mg_unlock_context(s->http);
    if (!ok) { close_frame(c, 1009); mark_closing(s, session); }
}
static int data_ws(struct mg_connection *c, int bits, char *data, size_t size, void *userdata) {
    bc_kvm_service *s = userdata;
    kvm_session *session = mg_get_user_connection_data(c);
    if (!session) return 0;
    mg_lock_context(s->http); int closing = session->closing; mg_unlock_context(s->http);
    if (closing) return 0;
    int opcode = bits & 15, final = bits & 128;
    if (opcode == MG_WEBSOCKET_OPCODE_PING) { mg_websocket_write(c, MG_WEBSOCKET_OPCODE_PONG, data, size); return 1; }
    if (opcode == MG_WEBSOCKET_OPCODE_PONG) return 1;
    if (opcode == MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE) {
        mg_websocket_write(c, MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE, data, size);
        mark_closing(s, session); return 0;
    }
    if ((opcode && session->opcode) || (!opcode && !session->opcode)) { close_frame(c, 1002); return 0; }
    if (size > QUEUE_LIMIT - session->length) { close_frame(c, 1009); return 0; }
    if (final && !session->opcode) {
        consume_ws(c, s, session, opcode, (uint8_t *)data, size);
        return 1;
    }
    if (opcode) session->opcode = (uint8_t)opcode;
    size_t needed = session->length + size;
    if (needed > session->capacity) {
        size_t capacity = session->capacity ? session->capacity : 4096;
        while (capacity < needed) capacity *= 2;
        if (capacity > QUEUE_LIMIT) capacity = QUEUE_LIMIT;
        uint8_t *grown = realloc(session->fragment, capacity);
        if (!grown) { close_frame(c, 1011); return 0; }
        session->fragment = grown; session->capacity = capacity;
    }
    if (size) memcpy(session->fragment + session->length, data, size);
    session->length += size;
    if (!final) return 1;
    consume_ws(c, s, session, session->opcode, session->fragment, session->length);
    session->length = 0; session->opcode = 0;
    return 1;
}
static void closed_ws(const struct mg_connection *c, void *userdata) {
    bc_kvm_service *s = userdata;
    kvm_session *session = mg_get_user_connection_data(c);
    if (!session) return;
    mg_lock_context(s->http);
    session->closing = 1; session->connection = NULL;
    mg_set_user_connection_data(c, NULL);
    mg_unlock_context(s->http);
}
static void close_session(bc_kvm_service *s, kvm_session *session) {
    if (session->transport) { bc_kvm_transport_close(session->transport); bc_kvm_transport_destroy(session->transport); session->transport = NULL; }
    mg_lock_context(s->http);
    session->closing = 1;
    if (session->connection) { mg_bcontrol_shutdown(session->connection); mg_unlock_context(s->http); return; }
    free(session->fragment); free(session->pending);
    bc_console_session_destroy(session->input);
    memset(session, 0, sizeof(*session));
    mg_unlock_context(s->http);
}
void bc_kvm_service_tick(bc_kvm_service *s) {
    if (!s) return;
    mg_lock_context(s->http);
    uint64_t now = bc_agent_now_ms();
    for (int i = 0; i < TICKET_LIMIT; ++i)
        if (s->tickets[i].used && s->tickets[i].expires <= now) { memset(&s->tickets[i], 0, sizeof(s->tickets[i])); }
    mg_unlock_context(s->http);
    uint8_t input[65536], output[65536];
    for (int i = 0; i < SESSION_LIMIT; ++i) {
        kvm_session *session = &s->sessions[i];
        mg_lock_context(s->http); int used = session->used, closing = session->closing, authenticated = session->authenticated;
        uint64_t opened = session->opened;
        int revoked = authenticated && !s->hooks.client_active_locked(s->hooks.userdata, session->owner);
        mg_unlock_context(s->http);
        if (!used) continue;
        if (closing || s->stopping || revoked || (!authenticated && bc_agent_now_ms() - opened >= 5000)) { close_session(s, session); continue; }
        if (!authenticated) continue;
        if (!session->connected) {
            bc_kvm_transport_options options = {0};
            options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
            options.url = (bc_string){s->url, strlen(s->url)};
            options.ca_file = s->ca_file ? (bc_string){s->ca_file, strlen(s->ca_file)} : (bc_string){NULL, 0};
            options.headers = s->headers; options.header_count = s->options.header_count;
            options.cert_policy = s->options.cert_policy; options.tls_min = s->options.tls_min; options.tls_max = s->options.tls_max;
            options.flags = s->options.flags; options.timeout_ms = s->options.timeout_ms;
            if (bc_kvm_transport_connect(&options, &session->transport) != BC_OK) {
                mark_closing(s, session); continue;
            }
            session->connected = 1;
        }
        mg_lock_context(s->http);
        size_t queued = session->pending_length - session->pending_offset;
        size_t copy = queued < sizeof(output) ? queued : sizeof(output);
        if (copy) { memcpy(output, session->pending + session->pending_offset, copy); session->pending_offset += copy; }
        mg_unlock_context(s->http);
        if (copy && bc_kvm_transport_send(session->transport, output, (uint32_t)copy) != BC_OK) {
            mark_closing(s, session); continue;
        }
        uint32_t received = 0;
        bc_status status = bc_kvm_transport_recv(session->transport, input, sizeof(input), &received, 5);
        if (status == BC_TIMEOUT) continue;
        if (status != BC_OK) { mark_closing(s, session); continue; }
        if (received && !session_write(s, session, input, received)) {
            mark_closing(s, session);
        }
    }
}
void bc_kvm_service_shutdown(bc_kvm_service *s) {
    if (!s) return;
    mg_lock_context(s->http);
    s->stopping = 1;
    for (int i = 0; i < SESSION_LIMIT; ++i) if (s->sessions[i].connection) mg_bcontrol_shutdown(s->sessions[i].connection);
    mg_unlock_context(s->http);
}
void bc_kvm_service_destroy(bc_kvm_service *s) {
    if (!s) return;
    for (int i = 0; i < SESSION_LIMIT; ++i) {
        bc_kvm_transport_destroy(s->sessions[i].transport);
        bc_console_session_destroy(s->sessions[i].input);
        free(s->sessions[i].fragment); free(s->sessions[i].pending);
    }
    for (uint32_t i = 0; i < s->options.header_count; ++i) free((void *)s->headers[i].data);
    free((void *)s->options.management_device_id);
    free(s->headers); free(s->url); free(s->ca_file);
    OPENSSL_cleanse(s, sizeof(*s)); free(s);
}

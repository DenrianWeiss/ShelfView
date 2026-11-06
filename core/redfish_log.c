#include "redfish_internal.h"
#include "log_internal.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_VERBOSE
#define LOG_BODY_MAX 1024u
#define LOG_VALUE_MAX 256u
#define LOG_DEPTH_MAX 32u

typedef struct { int changed; } redaction;

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
static int contains(const char *key, const char *needle) {
    size_t n = strlen(needle);
    for (; *key; ++key) {
        size_t i = 0;
        while (i < n && key[i] && lower((unsigned char)key[i]) == needle[i]) ++i;
        if (i == n) return 1;
    }
    return 0;
}
static int sensitive_key(const char *key) {
    return contains(key, "password") || contains(key, "passwd") || contains(key, "passphrase") || contains(key, "pwd") || contains(key, "passcode") ||
        contains(key, "token") || contains(key, "secret") || contains(key, "cookie") || contains(key, "csrf") ||
        contains(key, "authorization") || contains(key, "credential") || contains(key, "user") ||
        contains(key, "privatekey") || contains(key, "sessionkey");
}
static int url_key(const char *key) {
    return contains(key, "image") || contains(key, "url") || contains(key, "uri") ||
        contains(key, "location") || contains(key, "address");
}
static int has_scheme(const char *text, size_t length) {
    return (length >= 8 && !strncmp(text, "https://", 8)) ||
        (length >= 7 && !strncmp(text, "http://", 7));
}
static yyjson_mut_val *literal(yyjson_mut_doc *doc, const char *text) {
    return yyjson_mut_strcpy(doc, text);
}
static yyjson_mut_val *clean_string(yyjson_mut_doc *doc, yyjson_val *value, redaction *state) {
    const char *text = yyjson_get_str(value);
    size_t length = yyjson_get_len(value);
    if (!text) return NULL;
    char buffer[LOG_VALUE_MAX + 4];
    buffer[0] = 0;
    size_t used = 0;
    for (size_t i = 0; i < length && used < LOG_VALUE_MAX; ++i) {
        unsigned char c = (unsigned char)text[i];
        buffer[used++] = (char)(c < 32 || c == 127 ? '?' : c);
    }
    if (used < length) { buffer[used++] = '.'; buffer[used++] = '.'; buffer[used++] = '.'; state->changed = 1; }
    return yyjson_mut_strncpy(doc, buffer, used);
}
static yyjson_mut_val *make_value(yyjson_mut_doc *doc, yyjson_val *value, const char *key, unsigned depth, redaction *state) {
    if (!value) return NULL;
    if (depth >= LOG_DEPTH_MAX || sensitive_key(key ? key : "")) {
        state->changed = 1;
        return literal(doc, "<redacted>");
    }
    if (yyjson_is_str(value)) {
        if (url_key(key ? key : "") && has_scheme(yyjson_get_str(value), yyjson_get_len(value))) {
            state->changed = 1;
            return literal(doc, "<redacted-url>");
        }
        return clean_string(doc, value, state);
    }
    if (yyjson_is_obj(value)) {
        yyjson_mut_val *object = yyjson_mut_obj(doc);
        if (!object) return NULL;
        size_t index = 0, count = 0;
        yyjson_val *item_key = NULL, *item = NULL;
        yyjson_obj_foreach(value, index, count, item_key, item) {
            (void)index; (void)count;
            const char *name = yyjson_get_str(item_key);
            if (!name) return NULL;
            yyjson_mut_val *converted = make_value(doc, item, name, depth + 1, state);
            if (!converted || !yyjson_mut_obj_add_val(doc, object, name, converted)) return NULL;
        }
        return object;
    }
    if (yyjson_is_arr(value)) {
        yyjson_mut_val *array = yyjson_mut_arr(doc);
        if (!array) return NULL;
        size_t index = 0, count = 0;
        yyjson_val *item = NULL;
        yyjson_arr_foreach(value, index, count, item) {
            (void)index; (void)count;
            yyjson_mut_val *converted = make_value(doc, item, key, depth + 1, state);
            if (!converted || !yyjson_mut_arr_append(array, converted)) return NULL;
        }
        return array;
    }
    return yyjson_val_mut_copy(doc, value);
}
#endif
void bc_redfish_log_request(const char *owner, const bc_endpoint *endpoint, uint32_t method,
    bc_string path, bc_bytes body) {
#if BC_LOG_COMPILE_LEVEL < BC_LOG_LEVEL_VERBOSE
    (void)owner; (void)endpoint; (void)method; (void)path; (void)body;
    return;
#else
    if (!bc_log_enabled(BC_LOG_LEVEL_VERBOSE, BC_LOG_CATEGORY_REDFISH)) return;
    static const char *const methods[] = {"GET", "POST", "PATCH", "DELETE"};
    char clean[BC_LOG_PATH_MAX];
    uint32_t query = bc_log_path(clean, sizeof(clean), path.data, (size_t)path.length);
    const char *method_name = method < sizeof(methods) / sizeof(methods[0]) ? methods[method] : "?";
    const char *name = owner ? owner : "";
    if (!body.length) {
        BC_LOG_VERBOSE(BC_LOG_CATEGORY_REDFISH, "redfish.request",
            "owner=%s endpoint_rev=%" PRIu64 " method=%s path=%s query=%u body_bytes=0",
            name, bc_endpoint_revision(endpoint), method_name, clean, query);
        return;
    }
    yyjson_doc *document = yyjson_read((const char *)body.data, (size_t)body.length, 0);
    if (!document) {
        BC_LOG_VERBOSE(BC_LOG_CATEGORY_REDFISH, "redfish.request",
            "owner=%s endpoint_rev=%" PRIu64 " method=%s path=%s query=%u body_bytes=%" PRIu64 " body=<non-json>",
            name, bc_endpoint_revision(endpoint), method_name, clean, query, body.length);
        return;
    }
    yyjson_mut_doc *output = yyjson_mut_doc_new(NULL);
    redaction changed = {0};
    yyjson_mut_val *root = output ? make_value(output, yyjson_doc_get_root(document), NULL, 0, &changed) : NULL;
    if (!root) {
        if (output) yyjson_mut_doc_free(output);
        yyjson_doc_free(document);
        BC_LOG_VERBOSE(BC_LOG_CATEGORY_REDFISH, "redfish.request",
            "owner=%s endpoint_rev=%" PRIu64 " method=%s path=%s query=%u body_bytes=%" PRIu64 " body=<redaction-unavailable>",
            name, bc_endpoint_revision(endpoint), method_name, clean, query, body.length);
        return;
    }
    yyjson_mut_doc_set_root(output, root);
    size_t length = 0;
    char *json = yyjson_mut_write(output, 0, &length);
    char rendered[LOG_BODY_MAX];
    int truncated = 0;
    if (json) {
        size_t used = length < sizeof(rendered) - 1 ? length : sizeof(rendered) - 1;
        memcpy(rendered, json, used);
        rendered[used] = 0;
        truncated = used < length;
        if (truncated) { rendered[used - 3] = '.'; rendered[used - 2] = '.'; rendered[used - 1] = '.'; }
        free(json);
    } else {
        memcpy(rendered, "<redaction-failed>", 19);
    }
    BC_LOG_VERBOSE(BC_LOG_CATEGORY_REDFISH, "redfish.request",
        "owner=%s endpoint_rev=%" PRIu64 " method=%s path=%s query=%u body_bytes=%" PRIu64
        " body=%s redacted=%u truncated=%u",
        name, bc_endpoint_revision(endpoint), method_name, clean, query, body.length, rendered,
        (unsigned)changed.changed, (unsigned)truncated);
    yyjson_mut_doc_free(output);
    yyjson_doc_free(document);
#endif
}

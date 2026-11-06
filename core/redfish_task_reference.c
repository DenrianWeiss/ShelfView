#include "bcontrol/redfish_task_reference.h"
#include "redfish_internal.h"
#include <stdio.h>
#include <string.h>

static int equal(bc_string value, const char *text) {
    return value.data && value.length == strlen(text) && !memcmp(value.data, text, (size_t)value.length);
}
static int token(const char *text) {
    if (!text || !*text) return 0;
    for (; *text; ++text) {
        unsigned char c = (unsigned char)*text;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return 0;
    }
    return strcmp(text, ".") && strcmp(text, "..");
}
static int uri(const char *text) {
    if (!text || strlen(text) > 1023 || strncmp(text, "/redfish/v1/", 12)) return 0;
    const char *part = text + 1;
    for (const char *p = part;; ++p) {
        if (*p == '/' || !*p) {
            size_t n = (size_t)(p - part);
            if (!n || (n == 1 && *part == '.') || (n == 2 && !memcmp(part, "..", 2))) return 0;
            if (!*p) return 1;
            part = p + 1;
        } else {
            unsigned char c = (unsigned char)*p;
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return 0;
        }
    }
}
static int copy_text(char *out, size_t capacity, bc_string text) {
    if (!text.data || !text.length || text.length >= capacity || memchr(text.data, 0, (size_t)text.length)) return 0;
    memcpy(out, text.data, (size_t)text.length); out[text.length] = 0; return 1;
}
static int hex(const char *text, size_t length, int uuid) {
    if (strlen(text) != length) return 0;
    for (size_t i = 0; i < length; ++i) {
        char c = text[i];
        if (uuid && (i == 8 || i == 13 || i == 18 || i == 23)) { if (c != '-') return 0; }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
    }
    return 1;
}
static int number(const char *p, size_t n) {
    int value = 0;
    for (size_t i = 0; i < n; ++i) { if (p[i] < '0' || p[i] > '9') return -1; value = value * 10 + p[i] - '0'; }
    return value;
}
static int date(const char *text) {
    size_t n = strlen(text);
    if (n < 20 || n > 64 || text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':') return 0;
    int year = number(text, 4), month = number(text + 5, 2), day = number(text + 8, 2);
    int hour = number(text + 11, 2), minute = number(text + 14, 2), second = number(text + 17, 2);
    static const int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if (year < 1 || month < 1 || month > 12 || day < 1 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) return 0;
    int maximum = days[month - 1] + (month == 2 && !(year % 4) && (year % 100 || !(year % 400)));
    if (day > maximum) return 0;
    size_t i = 19;
    if (text[i] == '.') { size_t start = ++i; while (i < n && text[i] >= '0' && text[i] <= '9') ++i; if (i == start) return 0; }
    if (i + 1 == n && text[i] == 'Z') return 1;
    if (i + 6 != n || (text[i] != '+' && text[i] != '-') || text[i + 3] != ':') return 0;
    hour = number(text + i + 1, 2); minute = number(text + i + 4, 2);
    return hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59;
}
static int binding(const bc_redfish_task_binding *value, bc_redfish_task_reference *out) {
    if (!value || value->struct_size < sizeof(*value) || value->reserved ||
        (value->action != BC_REDFISH_TASK_REFERENCE_INSERT && value->action != BC_REDFISH_TASK_REFERENCE_EJECT) ||
        (value->http_method != BC_HTTP_POST && value->http_method != BC_HTTP_PATCH)) return 0;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->action = value->action; out->http_method = value->http_method;
    if (!copy_text(out->endpoint_id, sizeof(out->endpoint_id), value->endpoint_id) || !hex(out->endpoint_id, 36, 1) ||
        !copy_text(out->address_digest, sizeof(out->address_digest), value->address_digest) || !hex(out->address_digest, 64, 0) ||
        !copy_text(out->collection_uri, sizeof(out->collection_uri), value->collection_uri) || !uri(out->collection_uri) ||
        !copy_text(out->media_uri, sizeof(out->media_uri), value->media_uri) || !uri(out->media_uri) ||
        !copy_text(out->target_uri, sizeof(out->target_uri), value->target_uri) || !uri(out->target_uri)) return 0;
    size_t n = strlen(out->media_uri);
    return !strncmp(out->target_uri, out->media_uri, n) && (!out->target_uri[n] || out->target_uri[n] == '/');
}
static yyjson_val *member(yyjson_val *object, const char *name, int *valid) {
    if (!yyjson_is_obj(object)) { *valid = 0; return NULL; }
    size_t i, n; yyjson_val *key, *value, *found = NULL;
    yyjson_obj_foreach(object, i, n, key, value) {
        const char *text = yyjson_get_str(key);
        if (!text || strlen(text) != yyjson_get_len(key)) { *valid = 0; continue; }
        if (text && !strcmp(text, name)) { if (found) *valid = 0; found = value; }
    }
    return found;
}
static int field(yyjson_val *root, const char *name, char *out, size_t size, int *valid) {
    yyjson_val *value = member(root, name, valid);
    const char *text = yyjson_get_str(value);
    return text && copy_text(out, size, (bc_string){text, yyjson_get_len(value)});
}
static int task_type(const char *text) {
    if (strncmp(text, "#Task.v", 7)) return 0;
    const char *p = text + 7;
    for (unsigned i = 0; i < 3; ++i) {
        const char *start = p; while (*p >= '0' && *p <= '9') ++p;
        if (p == start || (i < 2 && *p++ != '_')) return 0;
    }
    return !strcmp(p, ".Task");
}
static int task(yyjson_val *root, bc_redfish_task_reference *out, uint32_t *flags) {
    int valid = 1; char method[8], target[1024], type[128];
    if (!field(root, "@odata.type", type, sizeof(type), &valid) || !task_type(type) ||
        !field(root, "@odata.id", out->task_uri, sizeof(out->task_uri), &valid) || !uri(out->task_uri) ||
        !field(root, "Id", out->task_id, sizeof(out->task_id), &valid) || !token(out->task_id) ||
        !field(root, "StartTime", out->start_time, sizeof(out->start_time), &valid) || !date(out->start_time)) return 0;
    size_t n = strlen(out->collection_uri);
    if (strncmp(out->task_uri, out->collection_uri, n) || out->task_uri[n] != '/' || strcmp(out->task_uri + n + 1, out->task_id)) return 0;
    yyjson_val *hidden = member(root, "HidePayload", &valid);
    if (hidden && (!yyjson_is_bool(hidden) || yyjson_get_bool(hidden))) return 0;
    yyjson_val *payload = member(root, "Payload", &valid);
    if (!field(payload, "HttpOperation", method, sizeof(method), &valid) ||
        strcmp(method, out->http_method == BC_HTTP_POST ? "POST" : "PATCH") ||
        !field(payload, "TargetUri", target, sizeof(target), &valid) || strcmp(target, out->target_uri)) return 0;
    if (flags) {
        char state[64]; *flags = 0;
        if (!field(root, "TaskState", state, sizeof(state), &valid)) return 0;
        if (!strcmp(state, "Completed") || !strcmp(state, "Exception") || !strcmp(state, "Killed") || !strcmp(state, "Cancelled")) *flags |= BC_TASK_TERMINAL;
        if (!strcmp(state, "Exception")) *flags |= BC_TASK_FAILED;
        if (!strcmp(state, "Killed") || !strcmp(state, "Cancelled")) *flags |= BC_TASK_CANCELLED;
        char status[64];
        yyjson_val *health = member(root, "TaskStatus", &valid);
        if (health && !field(root, "TaskStatus", status, sizeof(status), &valid)) return 0;
        if (health && !strcmp(status, "Critical") && (*flags & BC_TASK_TERMINAL)) *flags |= BC_TASK_FAILED;
    }
    return valid;
}
static yyjson_doc *document(bc_bytes json) {
    return json.data && json.length && json.length <= BC_REDFISH_MAX_BODY ? yyjson_read((const char *)json.data, (size_t)json.length, 0) : NULL;
}
bc_status bc_redfish_task_reference_export(bc_bytes json, const bc_redfish_task_binding *value, unsigned char *output, uint32_t capacity, uint32_t *written) {
    if (written) *written = 0;
    if (!output || !written || !capacity) return BC_INVALID_ARGUMENT;
    output[0] = 0;
    bc_redfish_task_reference ref;
    if (!binding(value, &ref)) return BC_INVALID_ARGUMENT;
    yyjson_doc *doc = document(json);
    int valid = task(doc ? yyjson_doc_get_root(doc) : NULL, &ref, NULL);
    if (doc) yyjson_doc_free(doc);
    if (!valid) return BC_UNSUPPORTED;
    int n = snprintf((char *)output, capacity, "{\"version\":1,\"endpoint\":\"%s\",\"address\":\"%s\",\"collection\":\"%s\",\"media\":\"%s\",\"target\":\"%s\",\"method\":%u,\"action\":%u,\"task\":\"%s\",\"id\":\"%s\",\"start\":\"%s\"}",
        ref.endpoint_id, ref.address_digest, ref.collection_uri, ref.media_uri, ref.target_uri, ref.http_method, ref.action, ref.task_uri, ref.task_id, ref.start_time);
    if (n < 0 || (uint32_t)n >= capacity || (uint32_t)n > BC_REDFISH_TASK_REFERENCE_MAX) { output[0] = 0; return BC_LIMIT_EXCEEDED; }
    *written = (uint32_t)n; return BC_OK;
}
bc_status bc_redfish_task_reference_import(bc_bytes json, const bc_redfish_task_binding *value, bc_redfish_task_reference *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    bc_redfish_task_reference ref;
    if (!binding(value, &ref) || json.length > BC_REDFISH_TASK_REFERENCE_MAX) return BC_INVALID_ARGUMENT;
    yyjson_doc *doc = document(json); yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    int valid = 1;
    yyjson_val *version = member(root, "version", &valid), *method = member(root, "method", &valid), *action = member(root, "action", &valid);
    const char *keys[] = {"endpoint", "address", "collection", "media", "target"};
    const char *texts[] = {ref.endpoint_id, ref.address_digest, ref.collection_uri, ref.media_uri, ref.target_uri};
    if (!yyjson_is_obj(root) || yyjson_obj_size(root) != 11 || !yyjson_is_uint(version) || yyjson_get_uint(version) != 1 ||
        !yyjson_is_uint(method) || yyjson_get_uint(method) != ref.http_method || !yyjson_is_uint(action) || yyjson_get_uint(action) != ref.action) valid = 0;
    for (size_t i = 0; i < 5; ++i) {
        yyjson_val *v = member(root, keys[i], &valid); const char *text = yyjson_get_str(v);
        if (!text || !equal((bc_string){text, yyjson_get_len(v)}, texts[i])) valid = 0;
    }
    if (!field(root, "task", ref.task_uri, sizeof(ref.task_uri), &valid) || !uri(ref.task_uri) ||
        !field(root, "id", ref.task_id, sizeof(ref.task_id), &valid) || !token(ref.task_id) ||
        !field(root, "start", ref.start_time, sizeof(ref.start_time), &valid) || !date(ref.start_time)) valid = 0;
    size_t n = strlen(ref.collection_uri);
    if (strncmp(ref.task_uri, ref.collection_uri, n) || ref.task_uri[n] != '/' || strcmp(ref.task_uri + n + 1, ref.task_id)) valid = 0;
    if (doc) yyjson_doc_free(doc);
    if (!valid) return BC_UNSUPPORTED;
    *out = ref; return BC_OK;
}
bc_status bc_redfish_task_reference_match(const bc_redfish_task_reference *ref, bc_bytes json, uint32_t *flags) {
    if (flags) *flags = 0;
    if (!ref || !flags || ref->struct_size != sizeof(*ref) || ref->reserved) return BC_INVALID_ARGUMENT;
    if (!memchr(ref->endpoint_id, 0, sizeof(ref->endpoint_id)) || !memchr(ref->address_digest, 0, sizeof(ref->address_digest)) ||
        !memchr(ref->collection_uri, 0, sizeof(ref->collection_uri)) || !memchr(ref->media_uri, 0, sizeof(ref->media_uri)) ||
        !memchr(ref->target_uri, 0, sizeof(ref->target_uri)) || !memchr(ref->task_uri, 0, sizeof(ref->task_uri)) ||
        !memchr(ref->task_id, 0, sizeof(ref->task_id)) || !memchr(ref->start_time, 0, sizeof(ref->start_time))) return BC_INVALID_ARGUMENT;
    if (!hex(ref->endpoint_id, 36, 1) || !hex(ref->address_digest, 64, 0) || !uri(ref->collection_uri) ||
        !uri(ref->media_uri) || !uri(ref->target_uri) || !uri(ref->task_uri) || !token(ref->task_id) || !date(ref->start_time) ||
        (ref->action != BC_REDFISH_TASK_REFERENCE_INSERT && ref->action != BC_REDFISH_TASK_REFERENCE_EJECT) ||
        (ref->http_method != BC_HTTP_POST && ref->http_method != BC_HTTP_PATCH)) return BC_INVALID_ARGUMENT;
    bc_redfish_task_reference actual = *ref;
    yyjson_doc *doc = document(json); uint32_t result = 0;
    int valid = task(doc ? yyjson_doc_get_root(doc) : NULL, &actual, &result);
    if (doc) yyjson_doc_free(doc);
    if (!valid || strcmp(actual.task_uri, ref->task_uri) || strcmp(actual.task_id, ref->task_id) || strcmp(actual.start_time, ref->start_time)) return BC_UNSUPPORTED;
    *flags = result; return BC_OK;
}

bc_status bc_redfish_task_identity_capture(bc_bytes json, unsigned char *output, uint32_t capacity, uint32_t *written) {
    if (written) *written = 0;
    if (!output || !written || !capacity) return BC_INVALID_ARGUMENT;
    output[0] = 0;
    bc_redfish_task_reference ref = {0}; int valid = 1; char method[8] = "", type[128], state[64], status[64] = "";
    yyjson_doc *doc = document(json); yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_val *payload = member(root, "Payload", &valid);
    if (!field(root, "@odata.type", type, sizeof(type), &valid) || !task_type(type) ||
        !field(root, "@odata.id", ref.task_uri, sizeof(ref.task_uri), &valid) || !uri(ref.task_uri) ||
        !field(payload, "TargetUri", ref.target_uri, sizeof(ref.target_uri), &valid) || !uri(ref.target_uri) ||
        !field(payload, "HttpOperation", method, sizeof(method), &valid) || (strcmp(method, "POST") && strcmp(method, "PATCH")) ||
        !field(root, "TaskState", state, sizeof(state), &valid) || !token(state)) valid = 0;
    const char *last = strrchr(ref.task_uri, '/');
    if (!last || (size_t)(last - ref.task_uri) >= sizeof(ref.collection_uri)) valid = 0;
    else { size_t n = (size_t)(last - ref.task_uri); memcpy(ref.collection_uri, ref.task_uri, n); ref.collection_uri[n] = 0; }
    ref.http_method = !strcmp(method, "POST") ? BC_HTTP_POST : BC_HTTP_PATCH;
    uint32_t flags = 0;
    if (!valid || !task(root, &ref, &flags)) valid = 0;
    yyjson_val *health = member(root, "TaskStatus", &valid);
    if (health && (!field(root, "TaskStatus", status, sizeof(status), &valid) || !token(status))) valid = 0;
    if (doc) yyjson_doc_free(doc);
    if (!valid) return BC_UNSUPPORTED;
    int n = snprintf((char *)output, capacity,
        "{\"@odata.type\":\"%s\",\"@odata.id\":\"%s\",\"Id\":\"%s\",\"StartTime\":\"%s\",\"TaskState\":\"%s\"%s%s%s,\"Payload\":{\"HttpOperation\":\"%s\",\"TargetUri\":\"%s\"}}",
        type, ref.task_uri, ref.task_id, ref.start_time, state, *status ? ",\"TaskStatus\":\"" : "", status, *status ? "\"" : "", method, ref.target_uri);
    if (n < 0 || (uint32_t)n >= capacity) { output[0] = 0; return BC_LIMIT_EXCEEDED; }
    *written = (uint32_t)n; return BC_OK;
}

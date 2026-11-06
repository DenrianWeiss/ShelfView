#include "bcontrol/diagnostic_assets.h"
#include "launch_xml.h"
#include <stdlib.h>
#include <string.h>
#define MAX_OUTPUT 524288u
#define REDACTED "[redacted]"
typedef struct { char name[128], key[128]; uint32_t arguments; int pending; } frame;
typedef struct { char name[64], value[4097]; uint32_t length; } attribute;
typedef struct {
    frame frames[32]; attribute attributes[32];
    uint32_t depth, attrs, capture, text_length, used, capacity;
    int named_arguments;
    char text[4097]; char *output;
} document;
static void erase(void *p, size_t n) { volatile unsigned char *b = p; while (n--) *b++ = 0; }
static bc_status append(document *d, const char *text) {
    size_t n = strlen(text);
    if (n > MAX_OUTPUT - d->used) return BC_LIMIT_EXCEEDED;
    if (d->output) {
        if (d->used + n >= d->capacity) return BC_LIMIT_EXCEEDED;
        memcpy(d->output + d->used, text, n); d->output[d->used + n] = 0;
    }
    d->used += (uint32_t)n; return BC_OK;
}
static bc_status escaped(document *d, const char *text) {
    for (; *text; ++text) {
        const char *value = *text == '&' ? "&amp;" : *text == '<' ? "&lt;" :
            *text == '>' ? "&gt;" : *text == '"' ? "&quot;" : *text == '\'' ? "&apos;" : NULL;
        char one[2] = {*text, 0}; bc_status status = append(d, value ? value : one);
        if (status != BC_OK) return status;
    }
    return BC_OK;
}
static int identifier(const char *text, int qualified) {
    size_t length = strlen(text); int dot = 0;
    if (!length || length > 127) return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c == '.') dot = 1;
        else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '-')) return 0;
    }
    return !qualified || dot;
}
static int xml_name(const char *name) {
    for (size_t i = 0; name[i]; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':' ||
            (i && ((c >= '0' && c <= '9') || c == '-' || c == '.')))) return 0;
    }
    return *name != 0;
}
static int relative_archive(const char *path) {
    size_t n = strlen(path);
    if (!n || n > 1024 || path[0] == '/' || n < 4 || strcmp(path + n - 4, ".jar")) return 0;
    const char *segment = path;
    for (const char *p = path;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (!c || c == '/') {
            size_t size = (size_t)(p - segment);
            if (!size || (size == 1 && segment[0] == '.') || (size == 2 && !memcmp(segment, "..", 2))) return 0;
            if (!c) return 1;
            segment = p + 1;
        } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '~')) return 0;
    }
}
static int archive_list(const char *text) {
    char part[1025]; size_t at = 0, n = strlen(text);
    if (!n || n > 4096) return 0;
    for (size_t i = 0; i <= n; ++i) {
        if (!text[i] || text[i] == ',') {
            part[at] = 0; if (!relative_archive(part)) return 0; at = 0;
        } else { if (at == sizeof(part) - 1) return 0; part[at++] = text[i]; }
    }
    return 1;
}
static int listed(const char *name, const char *const *names, size_t count) {
    for (size_t i = 0; i < count; ++i) if (!strcmp(name, names[i])) return 1;
    return 0;
}
static int public_value(const char *name, const char *value) {
    char key[128]; size_t n = strlen(name); if (n > 127) return 0;
    size_t at = 0; while (*name == '-') ++name;
    for (; *name; ++name) { unsigned char c = (unsigned char)*name; key[at++] = c >= 'A' && c <= 'Z' ? (char)(c + 32) : (char)c; }
    key[at] = 0;
    static const char *const ports[] = {"port", "kvmport", "vmmport", "cdport", "fdport", "hdport", "webport", "sslport"};
    static const char *const flags[] = {"kvmsecure", "vmsecure", "singleportenabled", "secure", "ssl", "compress", "compression", "readonly", "read_only"};
    uint32_t number;
    if (listed(key, ports, sizeof(ports)/sizeof(*ports))) return bc_launch_number(value, 65535, &number) == BC_OK && number;
    if (listed(key, flags, sizeof(flags)/sizeof(*flags))) return !strcmp(value, "0") || !strcmp(value, "1") || !strcmp(value, "true") || !strcmp(value, "false");
    return !strcmp(key, "kvmtokentype") && !strcmp(value, "0");
}
static const char *attribute_value(document *d, const char *element, attribute *a) {
    const char *key = "";
    for (uint32_t i = 0; i < d->attrs; ++i) if (!strcmp(d->attributes[i].name, "name")) key = d->attributes[i].value;
    if ((!strcmp(element, "param") || !strcmp(element, "property")) && !strcmp(a->name, "name") && identifier(a->value, 0)) return a->value;
    if ((!strcmp(element, "param") || !strcmp(element, "property")) && !strcmp(a->name, "value") && public_value(key, a->value)) return a->value;
    if ((!strcmp(element, "jar") || !strcmp(element, "nativelib")) && !strcmp(a->name, "href") && relative_archive(a->value)) return a->value;
    if (!strcmp(element, "applet-desc") && !strcmp(a->name, "archive") && archive_list(a->value)) return a->value;
    if ((!strcmp(element, "application-desc") || !strcmp(element, "applet-desc")) && !strcmp(a->name, "main-class") && identifier(a->value, 1)) return a->value;
    if (!strcmp(element, "jar") && !strcmp(a->name, "main") && (!strcmp(a->value, "true") || !strcmp(a->value, "false"))) return a->value;
    if (!strcmp(element, "jar") && !strcmp(a->name, "download") && (!strcmp(a->value, "eager") || !strcmp(a->value, "lazy"))) return a->value;
    return REDACTED;
}
static bc_status header(document *d) {
    if (!d->depth || !d->frames[d->depth - 1].pending) return BC_OK;
    frame *f = d->frames + d->depth - 1;
    bc_status status = append(d, "<"); if (status == BC_OK) status = append(d, f->name);
    for (uint32_t i = 0; i < d->attrs && status == BC_OK; ++i) {
        attribute *a = d->attributes + i;
        status = append(d, " "); if (status == BC_OK) status = append(d, a->name);
        if (status == BC_OK) status = append(d, "=\"");
        if (status == BC_OK) status = escaped(d, attribute_value(d, f->name, a));
        if (status == BC_OK) status = append(d, "\"");
    }
    if (status == BC_OK) status = append(d, ">");
    f->pending = 0; erase(d->attributes, sizeof(d->attributes)); d->attrs = d->capture = 0;
    return status;
}
static bc_status content(document *d) {
    if (!d->depth || !d->text_length) return BC_OK;
    const char *value = REDACTED; frame *f = d->frames + d->depth - 1;
    if (d->named_arguments && d->depth > 1 && !strcmp(f->name, "argument") &&
        !strcmp(d->frames[d->depth - 2].name, "application-desc")) {
        frame *app = d->frames + d->depth - 2;
        if (!(app->arguments++ & 1u)) {
            if (d->text[0] == '-' && identifier(d->text + 1, 0)) { strcpy(app->key, d->text); value = d->text; }
            else app->key[0] = 0;
        } else if (public_value(app->key, d->text)) value = d->text;
    } else {
        int blank = 1;
        for (uint32_t i = 0; i < d->text_length; ++i) if (d->text[i] != ' ' && d->text[i] != '\t' && d->text[i] != '\r' && d->text[i] != '\n') blank = 0;
        if (blank) value = "";
    }
    bc_status status = escaped(d, value); erase(d->text, sizeof(d->text)); d->text_length = 0; return status;
}
static bc_status event(void *user, enum bc_launch_xml_event kind, uint32_t depth, const char *name, const char *data) {
    document *d = user; bc_status status = BC_OK;
    if (kind == BC_XML_START) {
        if (depth != d->depth + 1 || (depth == 1 && strcmp(name, "jnlp")) || strlen(name) >= sizeof(d->frames[0].name) || !xml_name(name)) return BC_PROTOCOL_ERROR;
        status = header(d); if (status == BC_OK) status = content(d); if (status != BC_OK) return status;
        frame *f = d->frames + d->depth++; memset(f, 0, sizeof(*f)); strcpy(f->name, name); f->pending = 1;
    } else if (kind == BC_XML_ATTRIBUTE) {
        if (!d->depth || !d->frames[d->depth - 1].pending || d->attrs == 32 || !xml_name(name)) return BC_PROTOCOL_ERROR;
        attribute *a = d->attributes + d->attrs++; strcpy(a->name, name); d->capture = d->attrs;
    } else if (kind == BC_XML_ATTRIBUTE_VALUE) {
        if (!d->capture) return BC_PROTOCOL_ERROR;
        attribute *a = d->attributes + d->capture - 1;
        status = bc_launch_append(a->value, &a->length, sizeof(a->value), data);
    } else if (kind == BC_XML_ATTRIBUTE_END) d->capture = 0;
    else if (kind == BC_XML_CONTENT) {
        status = header(d); if (status != BC_OK) return status;
        status = bc_launch_append(d->text, &d->text_length, sizeof(d->text), data);
    } else if (kind == BC_XML_END) {
        if (depth != d->depth) return BC_PROTOCOL_ERROR;
        status = header(d); if (status == BC_OK) status = content(d);
        if (status == BC_OK) status = append(d, "</");
        if (status == BC_OK) status = append(d, d->frames[d->depth - 1].name);
        if (status == BC_OK) status = append(d, ">");
        erase(d->frames + --d->depth, sizeof(d->frames[0]));
    }
    return status;
}
static bc_status render(document *d, const uint8_t *data, uint32_t length) {
    bc_status status = append(d, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    if (status == BC_OK) status = bc_launch_xml_parse(data, length, event, d);
    return status;
}
bc_status bc_diagnostic_jnlp_redact(const uint8_t *data, uint32_t length,
    char *output, uint32_t capacity, uint32_t *written) {
    if (written) *written = 0;
    if (output && capacity) output[0] = 0;
    if (!written || (!output && capacity) || (output && !capacity) || capacity > MAX_OUTPUT + 1) return BC_INVALID_ARGUMENT;
    document *d = calloc(1, sizeof(*d)); if (!d) return BC_NO_MEMORY;
    bc_megarac_kvm_info info; bc_service_profile profile;
    d->named_arguments = bc_megarac_discover_jnlp(data, length, &info, &profile) == BC_OK;
    erase(&info, sizeof(info)); erase(&profile, sizeof(profile));
    int named = d->named_arguments; bc_status status = render(d, data, length); uint32_t required = d->used;
    int valid = status == BC_OK;
    if (status == BC_OK && output && capacity <= required) status = BC_LIMIT_EXCEEDED;
    if (status == BC_OK && output) {
        erase(d, sizeof(*d)); d->named_arguments = named; d->output = output; d->capacity = capacity;
        status = render(d, data, length);
    }
    if (valid && (status == BC_OK || status == BC_LIMIT_EXCEEDED)) *written = required;
    if (status != BC_OK && output) { erase(output, capacity); output[0] = 0; }
    erase(d, sizeof(*d)); free(d); return status;
}

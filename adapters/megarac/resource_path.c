#include "megarac.h"
#include "launch_xml.h"
#include <string.h>
#include <stdio.h>

typedef struct {
    char base[1025], href[1025], main[16], first[1025], selected[1025];
    uint32_t base_length, href_length, main_length, resources, jar, jars, capture;
    int qualified;
} resources;
static bc_status event(void *user, enum bc_launch_xml_event kind, uint32_t depth, const char *name, const char *data) {
    resources *r = user;
    if (kind == BC_XML_START) {
        if (depth == 1 && strcmp(name, "jnlp")) return BC_PROTOCOL_ERROR;
        if (!strcmp(name, "resources")) {
            if (depth != 2 || r->resources) return BC_PROTOCOL_ERROR;
            r->resources = depth; r->qualified = 0;
        }
        if (!strcmp(name, "jar")) {
            if (!r->resources || depth != r->resources + 1 || r->jar) return BC_PROTOCOL_ERROR;
            r->jar = depth; r->href_length = r->main_length = 0; r->href[0] = r->main[0] = 0;
        }
    } else if (kind == BC_XML_ATTRIBUTE) {
        if (r->jar && depth == r->jar && !r->qualified && !strcmp(name, "version")) return BC_UNSUPPORTED;
        r->capture = depth == 1 && !strcmp(name, "codebase") ? 1 :
            r->jar && depth == r->jar && !strcmp(name, "href") ? 2 :
            r->jar && depth == r->jar && !strcmp(name, "main") ? 3 : 0;
        if (r->resources && depth == r->resources &&
            (!strcmp(name, "os") || !strcmp(name, "arch") || !strcmp(name, "locale"))) r->qualified = 1;
    } else if (kind == BC_XML_ATTRIBUTE_VALUE) {
        if (r->capture == 1) return bc_launch_append(r->base, &r->base_length, sizeof(r->base), data);
        if (r->capture == 2) return bc_launch_append(r->href, &r->href_length, sizeof(r->href), data);
        if (r->capture == 3) return bc_launch_append(r->main, &r->main_length, sizeof(r->main), data);
    } else if (kind == BC_XML_ATTRIBUTE_END) r->capture = 0;
    else if (kind == BC_XML_END) {
        if (r->jar == depth) {
            if (!r->qualified) {
                if (!r->href[0] || (r->main[0] && strcmp(r->main, "true") && strcmp(r->main, "false"))) return BC_PROTOCOL_ERROR;
                if (!r->jars) strcpy(r->first, r->href);
                if (++r->jars > 32) return BC_LIMIT_EXCEEDED;
                if (!strcmp(r->main, "true")) {
                    if (r->selected[0] && strcmp(r->selected, r->href)) return BC_PROTOCOL_ERROR;
                    strcpy(r->selected, r->href);
                }
            }
            r->jar = 0;
        }
        if (r->resources == depth) r->resources = 0;
    }
    return BC_OK;
}
static int safe_path(const char *s) {
    if (s[0] != '/' || s[1] == '/') return 0;
    const char *segment = s + 1;
    for (const char *p = s + 1;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (!c || c == '/') {
            size_t length = (size_t)(p - segment);
            if (!length || (length == 1 && segment[0] == '.') || (length == 2 && !memcmp(segment, "..", 2))) return 0;
            if (!c) return 1;
            segment = p + 1;
        } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                     c == '-' || c == '_' || c == '.' || c == '~')) return 0;
    }
}
static unsigned char folded(unsigned char c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; }
static int authority(const char *s, size_t length, bc_string *host, uint32_t *port, const char **path) {
    static const char scheme[] = "https://";
    if (length < 8) return 0;
    for (unsigned i = 0; i < 8; ++i) if (folded((unsigned char)s[i]) != (unsigned char)scheme[i]) return 0;
    size_t end = 8;
    while (end < length && s[end] != '/') ++end;
    size_t host_end = 8;
    if (host_end < end && s[host_end] == '[') {
        ++host_end; unsigned colons = 0;
        while (host_end < end && s[host_end] != ']') {
            unsigned char c = folded((unsigned char)s[host_end++]);
            if (c == ':') ++colons;
            else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '.')) return 0;
        }
        if (host_end == end || !colons) return 0;
        ++host_end;
    } else {
        while (host_end < end && s[host_end] != ':') {
            unsigned char c = folded((unsigned char)s[host_end++]);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return 0;
        }
    }
    if (host_end == 8) return 0;
    host->data = s + 8; host->length = host_end - 8; *port = 443;
    if (host_end != end) {
        if (s[host_end++] != ':' || host_end == end) return 0;
        *port = 0;
        while (host_end < end) {
            unsigned char c = (unsigned char)s[host_end++];
            if (c < '0' || c > '9' || *port > 6553) return 0;
            *port = *port * 10 + c - '0';
        }
        if (!*port || *port > 65535) return 0;
    }
    *path = end < length ? s + end : NULL; return 1;
}
static const char *local(const char *s, bc_string original, uint32_t original_port) {
    if (strchr(s, ':')) {
        bc_string host; uint32_t port; const char *path;
        if (!authority(s, strlen(s), &host, &port, &path) || host.length != original.length || port != original_port) return NULL;
        for (uint64_t i = 0; i < host.length; ++i)
            if (folded((unsigned char)host.data[i]) != folded((unsigned char)original.data[i])) return NULL;
        return path ? path : "/";
    }
    return !strncmp(s, "//", 2) ? NULL : s;
}
bc_status bc_megarac_jviewer_resource_path(const uint8_t *data, uint32_t length, bc_string origin,
    bc_string launch_path, char *out, uint32_t capacity) {
    if (!out || !capacity) return BC_INVALID_ARGUMENT;
    out[0] = 0;
    if (!origin.data || origin.length <= 8 || origin.length > 1024 ||
        memchr(origin.data, 0, (size_t)origin.length) || !launch_path.data || !launch_path.length || launch_path.length > 1024 ||
        memchr(launch_path.data, 0, (size_t)launch_path.length)) return BC_INVALID_ARGUMENT;
    bc_string host; uint32_t port; const char *origin_path;
    if (!authority(origin.data, (size_t)origin.length, &host, &port, &origin_path) ||
        (origin_path && (uint64_t)(origin_path - origin.data) + 1 != origin.length)) return BC_INVALID_ARGUMENT;
    resources r = {0}; bc_status status = bc_launch_xml_parse(data, length, event, &r);
    if (status != BC_OK) return status;
    if (!r.jars) return BC_UNSUPPORTED;
    const char *base = local(r.base, host, port), *href = local(r.selected[0] ? r.selected : r.first, host, port);
    if (!base || !href) return BC_UNSUPPORTED;
    char source[1025], directory[1025], resolved_base[2049], result[3074];
    memcpy(source, launch_path.data, (size_t)launch_path.length); source[launch_path.length] = 0;
    if (!safe_path(source)) return BC_INVALID_ARGUMENT;
    strcpy(directory, source); char *slash = strrchr(directory, '/'); slash[1] = 0;
    int written = snprintf(resolved_base, sizeof(resolved_base), "%s%s", base[0] == '/' ? "" : directory, base);
    if (written < 0 || (size_t)written >= sizeof(resolved_base)) return BC_LIMIT_EXCEEDED;
    size_t used = strlen(resolved_base);
    if (!used || resolved_base[used - 1] != '/') {
        if (used + 1 >= sizeof(resolved_base)) return BC_LIMIT_EXCEEDED;
        resolved_base[used++] = '/'; resolved_base[used] = 0;
    }
    written = snprintf(result, sizeof(result), "%s%s", href[0] == '/' ? "" : resolved_base, href);
    if (written < 0 || (size_t)written >= sizeof(result) || written > 1024 || (uint32_t)written >= capacity) return BC_LIMIT_EXCEEDED;
    if (!safe_path(result)) return BC_UNSUPPORTED;
    memcpy(out, result, (size_t)written + 1); return BC_OK;
}

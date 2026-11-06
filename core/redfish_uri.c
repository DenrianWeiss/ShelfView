#include "bcontrol/redfish.h"
#include "redfish_internal.h"
#include <string.h>

static int path(bc_string value) {
    if (!bc_redfish_uri_supported(value) || memchr(value.data, '?', (size_t)value.length) ||
        (value.length > 12 && value.data[value.length - 1] == '/')) return 0;
    for (uint64_t i = 12; i < value.length; ++i)
        if (value.data[i] == '/' && value.data[i - 1] == '/') return 0;
    return 1;
}
static bc_string segment(bc_string value, uint64_t *offset) {
    uint64_t start = *offset;
    while (*offset < value.length && value.data[*offset] != '/') ++*offset;
    bc_string result = {value.data + start, *offset - start};
    if (*offset < value.length) ++*offset;
    return result;
}
static unsigned char fold(unsigned char c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; }
static int same(bc_string a, bc_string b, int insensitive) {
    if (a.length != b.length) return 0;
    for (uint64_t i = 0; i < a.length; ++i)
        if (insensitive ? fold((unsigned char)a.data[i]) != fold((unsigned char)b.data[i]) : a.data[i] != b.data[i])
            return 0;
    return 1;
}
static int authority(bc_string value, bc_string *scheme, bc_string *host, bc_string *rest) {
    uint64_t n = 0;
    while (n < value.length && value.data[n] != ':') ++n;
    if (n + 3 > value.length || memcmp(value.data + n, "://", 3)) return 0;
    *scheme = (bc_string){value.data, n};
    int https = same(*scheme, (bc_string){"https", 5}, 1);
    if (!https && !same(*scheme, (bc_string){"http", 4}, 1)) return 0;
    uint64_t start = n + 3; n = start;
    while (n < value.length && value.data[n] != '/') {
        unsigned char c = (unsigned char)value.data[n++];
        if (c <= 32 || c >= 127 || c == '@' || c == '\\' || c == '?' || c == '#') return 0;
    }
    *host = (bc_string){value.data + start, n - start};
    const char *port = https ? ":443" : ":80";
    size_t port_length = strlen(port);
    if (host->length > port_length && !memcmp(host->data + host->length - port_length, port, port_length))
        host->length -= port_length;
    *rest = (bc_string){value.data + n, value.length - n};
    return host->length != 0;
}
int bc_redfish_same_origin_path(bc_string origin, bc_string value, bc_string *out) {
    if (bc_redfish_uri_valid(value)) { *out = value; return 1; }
    if (!origin.data || !value.data || value.length > 8192) return 0;
    bc_string os, oh, op, vs, vh, vp;
    if (!authority(origin, &os, &oh, &op) || !authority(value, &vs, &vh, &vp) ||
        !same(os, vs, 1) || !same(oh, vh, 1) || !bc_redfish_uri_valid(vp)) return 0;
    *out = vp; return 1;
}
static int template_valid(bc_string pattern) {
    if (!path(pattern)) return 0;
    uint64_t at = 12;
    while (at < pattern.length) {
        bc_string part = segment(pattern, &at);
        if (part.length == 1 && part.data[0] == '*') continue;
        for (uint64_t i = 0; i < part.length; ++i) {
            unsigned char c = (unsigned char)part.data[i];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return 0;
        }
    }
    return 1;
}
uint32_t bc_redfish_resource_uri_match(bc_string requested, bc_string returned, bc_string pattern) {
    if (!path(requested) || !path(returned)) return BC_REDFISH_URI_NO_MATCH;
    if (!pattern.length) return same(requested, returned, 0) ? BC_REDFISH_URI_EXACT : BC_REDFISH_URI_NO_MATCH;
    if (!template_valid(pattern)) return BC_REDFISH_URI_NO_MATCH;
    uint64_t a = 12, b = 12, p = 12;
    while (p < pattern.length && a < requested.length && b < returned.length) {
        bc_string expected = segment(pattern, &p), left = segment(requested, &a), right = segment(returned, &b);
        if (expected.length == 1 && expected.data[0] == '*') {
            if (!same(left, right, 0)) return BC_REDFISH_URI_NO_MATCH;
        } else if (!same(left, expected, 1) || !same(right, expected, 1)) return BC_REDFISH_URI_NO_MATCH;
    }
    if (p != pattern.length || a != requested.length || b != returned.length) return BC_REDFISH_URI_NO_MATCH;
    return same(requested, returned, 0) ? BC_REDFISH_URI_EXACT : BC_REDFISH_URI_FIXED_CASE;
}

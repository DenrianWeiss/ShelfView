#include "bcontrol/idrac_kvm.h"
#include "launch_xml.h"
#include "yyjson.h"
#include <string.h>

bc_status bc_idrac_kvm_launch_location(const uint8_t *data, uint32_t length,
    char *out, uint32_t capacity, uint32_t *written) {
    if (written) *written = 0;
    if (out && capacity) out[0] = 0;
    if (!data || !length || !out || !capacity || !written) return BC_INVALID_ARGUMENT;
    if (length > 65536) return BC_LIMIT_EXCEEDED;
    yyjson_doc *doc = yyjson_read((const char *)data, length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL, *location = NULL;
    bc_status status = yyjson_is_obj(root) ? BC_OK : BC_PROTOCOL_ERROR;
    uint32_t matches = 0;
    if (status == BC_OK) {
        size_t index, count; yyjson_val *key, *value;
        yyjson_obj_foreach(root, index, count, key, value) {
            if (yyjson_get_len(key) == 8 && !memcmp(yyjson_get_str(key), "Location", 8)) {
                location = value; ++matches;
            }
        }
        if (matches != 1 || !yyjson_is_str(location)) status = BC_PROTOCOL_ERROR;
    }
    if (status == BC_OK) {
        size_t size = yyjson_get_len(location);
        const char *text = yyjson_get_str(location);
        if (!size) status = BC_PROTOCOL_ERROR;
        else if (size > 8192 || size >= capacity) status = BC_LIMIT_EXCEEDED;
        for (size_t i = 0; i < size && status == BC_OK; ++i)
            if ((unsigned char)text[i] < 33 || (unsigned char)text[i] > 126) status = BC_PROTOCOL_ERROR;
        if (status == BC_OK) { memcpy(out, text, size + 1); *written = (uint32_t)size; }
    }
    if (doc) yyjson_doc_free(doc);
    return status;
}

static int ascii_equal(bc_string a, bc_string b) {
    if (a.length != b.length || !a.data || !b.data) return 0;
    for (uint64_t i = 0; i < a.length; ++i) {
        unsigned char x = (unsigned char)a.data[i], y = (unsigned char)b.data[i];
        if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
        if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
        if (x != y) return 0;
    }
    return 1;
}
static int valid_host(bc_string host) {
    if (!host.data || !host.length || host.length > 255) return 0;
    for (uint64_t i = 0; i < host.length; ++i) {
        unsigned char c = (unsigned char)host.data[i];
        if (c <= 32 || c > 126 || c == '@' || c == '/' || c == '\\' || c == '?' || c == '#') return 0;
    }
    return 1;
}
static int hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bc_status decode(const char *data, size_t length, char *out, size_t capacity, int space) {
    size_t used = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)data[i];
        if (c == '#') return BC_PROTOCOL_ERROR;
        if (c == '%') {
            if (i + 2 >= length) return BC_PROTOCOL_ERROR;
            int hi = hex((unsigned char)data[i + 1]), lo = hex((unsigned char)data[i + 2]);
            if (hi < 0 || lo < 0) return BC_PROTOCOL_ERROR;
            c = (unsigned char)((hi << 4) | lo); i += 2;
        }
        if (c < (space ? 32 : 33) || c > 126) return BC_PROTOCOL_ERROR;
        if (used + 1 >= capacity) return BC_LIMIT_EXCEEDED;
        out[used++] = (char)c;
    }
    out[used] = 0;
    return BC_OK;
}
static bc_status query(bc_string text, bc_string host, bc_idrac_console_launch *launch) {
    char names[64][64], value[513];
    uint32_t count = 0, seen = 0;
    bc_status status = BC_OK;
    for (size_t at = 0; at < text.length && status == BC_OK;) {
        size_t end = at, equal = at;
        while (end < text.length && text.data[end] != '&') ++end;
        while (equal < end && text.data[equal] != '=') ++equal;
        if (count == 64) { status = BC_LIMIT_EXCEEDED; break; }
        if (equal == at || equal == end || end + 1 == text.length) { status = BC_PROTOCOL_ERROR; break; }
        status = decode(text.data + at, equal - at, names[count], sizeof(names[count]), 0);
        if (status == BC_OK) status = decode(text.data + equal + 1, end - equal - 1, value, sizeof(value), 1);
        if (status != BC_OK) break;
        for (uint32_t i = 0; i < count; ++i)
            if (!strcmp(names[i], names[count])) status = BC_PROTOCOL_ERROR;
        if (status != BC_OK) break;
        const char *name = names[count++];
        if (!strcmp(name, "VCSID") || !strcmp(name, "VCSID2")) {
            size_t length = strlen(value);
            if (!length || length > 256) { status = BC_PROTOCOL_ERROR; break; }
            if (memchr(value, ' ', length)) { status = BC_PROTOCOL_ERROR; break; }
            if (!strcmp(name, "VCSID")) { memcpy(launch->primary_key, value, length + 1); seen |= 1; }
            else { memcpy(launch->secondary_key, value, length + 1); seen |= 2; }
        } else if (!strcmp(name, "ip")) {
            if (!ascii_equal((bc_string){value, strlen(value)}, host)) { status = BC_PROTOCOL_ERROR; break; }
            seen |= 4;
        } else if (!strcmp(name, "kvmport")) {
            status = bc_launch_number(value, 65535, &launch->kvm_port);
            if (status != BC_OK || !launch->kvm_port) { status = BC_PROTOCOL_ERROR; break; }
            seen |= 8;
        }
        at = end + 1;
    }
    volatile char *secret = value;
    for (size_t i = 0; i < sizeof(value); ++i) secret[i] = 0;
    return status == BC_OK && seen != 15 ? BC_PROTOCOL_ERROR : status;
}

bc_status bc_idrac_kvm_discover_launch(const bc_idrac_launch_uri *uri, bc_string host,
    uint32_t port, bc_idrac_console_launch *out, bc_service_profile *profile) {
    if (!out || !profile) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    *profile = (bc_service_profile){sizeof(*profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_IDRAC, 0, 0};
    if (!uri || uri->struct_size != sizeof(*uri) || !valid_host(host) || port > 65535)
        return BC_INVALID_ARGUMENT;
    if (uri->flags || !valid_host(uri->host) || uri->port > 65535 ||
        !ascii_equal(uri->host, host) || (uri->port ? uri->port : 443) != (port ? port : 443))
        return BC_PROTOCOL_ERROR;
    static const char path[] = "/restgui/vconsole/index.html";
    if (!ascii_equal(uri->scheme, (bc_string){"https", 5}) ||
        uri->path.length != sizeof(path) - 1 || !uri->path.data || memcmp(uri->path.data, path, sizeof(path) - 1))
        return BC_UNSUPPORTED;
    if (!uri->query.data || !uri->query.length) return BC_PROTOCOL_ERROR;
    if (uri->query.length > 8192) return BC_LIMIT_EXCEEDED;
    bc_idrac_console_launch launch = {0};
    bc_status status = query(uri->query, host, &launch);
    if (status == BC_OK) {
        launch.struct_size = sizeof(launch); *out = launch;
        profile->variant = BC_SERVICE_IDRAC_KVM_EHTML5;
        profile->evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR;
    }
    volatile uint8_t *secret = (volatile uint8_t *)&launch;
    for (size_t i = 0; i < sizeof(launch); ++i) secret[i] = 0;
    return status;
}

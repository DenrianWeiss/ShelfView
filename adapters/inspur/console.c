#include "internal.h"
#include "bcontrol/wire.h"
#include "yyjson.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "login_key.h"
#include "../megarac/h5_internal.h"

int bc_inspur_web_media_proxy_matches(const uint8_t *data, uint32_t length) {
    return bc_megarac_h5_contains(data, length, "\"WEB_APP_PROXY\"") &&
        bc_megarac_h5_contains(data, length, "9999==this.port?new WebSocket");
}

static uint32_t round_f(uint32_t x) {
    return ((inspur_s[x >> 24] + inspur_s[256 + ((x >> 16) & 255)]) ^
        inspur_s[512 + ((x >> 8) & 255)]) + inspur_s[768 + (x & 255)];
}
static size_t browser_bytes(bc_string value, uint8_t *out) {
    size_t at = 0;
    for (size_t i = 0; i < value.length;) {
        uint8_t c = (uint8_t)value.data[i];
        unsigned n = c < 0x80 ? 1 : c >= 0xc2 && c <= 0xdf ? 2 :
            c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
        if (!n || i + n > value.length) return 0;
        uint32_t code = c & (n == 1 ? 0x7f : n == 2 ? 0x1f : n == 3 ? 0x0f : 7);
        for (unsigned j = 1; j < n; ++j) {
            uint8_t next = (uint8_t)value.data[i + j];
            if ((next & 0xc0) != 0x80) return 0;
            code = (code << 6) | (next & 63);
        }
        if ((n == 2 && code < 0x80) || (n == 3 && code < 0x800) || (n == 4 && code < 0x10000) ||
            code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return 0;
        if (n == 4) {
            /* The firmware's JavaScript encodes UTF-16 surrogate pairs separately. */
            uint32_t pair[] = {0xd800 + ((code - 0x10000) >> 10), 0xdc00 + ((code - 0x10000) & 1023)};
            for (unsigned j = 0; j < 2; ++j) {
                out[at++] = (uint8_t)(0xe0 | (pair[j] >> 12));
                out[at++] = (uint8_t)(0x80 | ((pair[j] >> 6) & 63));
                out[at++] = (uint8_t)(0x80 | (pair[j] & 63));
            }
        } else { memcpy(out + at, value.data + i, n); at += n; }
        i += n;
    }
    return at;
}
static char *credential(bc_string value, unsigned mode) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!value.data || !value.length || value.length > 1024 || memchr(value.data, 0, (size_t)value.length)) return NULL;
    uint8_t bytes[1536] = {0};
    size_t length = browser_bytes(value, bytes);
    if (!length) {
        volatile uint8_t *wipe = bytes; for (size_t i = 0; i < sizeof(bytes); ++i) wipe[i] = 0;
        return NULL;
    }
    if (mode == 1) {
        char *out = malloc(length * 5 + 1);
        size_t at = 0;
        if (out) for (size_t i = 0; i < length;) {
            uint32_t unit = bytes[i++];
            if (unit >= 0xe0) {
                unit = ((unit & 15) << 6) | (bytes[i++] & 63);
                unit = (unit << 6) | (bytes[i++] & 63);
            } else if (unit >= 0xc0) unit = ((unit & 31) << 6) | (bytes[i++] & 63);
            at += (size_t)snprintf(out + at, length * 5 + 1 - at, "%s%x",
                at ? "-" : "", (unsigned)(unit ^ 127));
        }
        volatile uint8_t *wipe = bytes; for (size_t i = 0; i < sizeof(bytes); ++i) wipe[i] = 0;
        return out;
    }
    length = (length + 7) & ~(size_t)7;
    for (size_t i = 0; i < length; i += 8) {
        uint32_t l = (uint32_t)bc_wire_read_be(bytes + i, 4), r = (uint32_t)bc_wire_read_be(bytes + i + 4, 4);
        for (unsigned j = 0; j < 16; ++j) { l ^= inspur_p[j]; r ^= round_f(l); uint32_t t = l; l = r; r = t; }
        uint32_t t = l; l = r; r = t; r ^= inspur_p[16]; l ^= inspur_p[17];
        bc_wire_write_be(bytes + i, l, 4); bc_wire_write_be(bytes + i + 4, r, 4);
    }
    char *out = malloc(((length + 2) / 3) * 12 + 1); size_t at = 0;
    if (out) for (size_t i = 0; i < length; i += 3) {
        uint32_t x = (uint32_t)bytes[i] << 16;
        if (i + 1 < length) x |= (uint32_t)bytes[i + 1] << 8;
        if (i + 2 < length) x |= bytes[i + 2];
        char encoded[] = {alphabet[x >> 18], alphabet[(x >> 12) & 63],
            i + 1 < length ? alphabet[(x >> 6) & 63] : '=', i + 2 < length ? alphabet[x & 63] : '='};
        for (unsigned j = 0; j < 4; ++j) {
            char c = encoded[j];
            if (c == '+' || c == '/' || c == '=') {
                static const char hex[] = "0123456789ABCDEF";
                out[at++] = '%'; out[at++] = hex[(unsigned char)c >> 4]; out[at++] = hex[c & 15];
            } else out[at++] = c;
        }
    }
    volatile uint8_t *wipe = bytes; for (size_t i = 0; i < sizeof(bytes); ++i) wipe[i] = 0;
    if (out) out[at] = 0;
    return out;
}
bc_status bc_inspur_login_form(bc_string username, bc_string password, const uint8_t *data, uint32_t length, char **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    yyjson_doc *doc = data && length <= 65536 ? yyjson_read((const char *)data, length, 0) : NULL;
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_val *tag = yyjson_obj_get(root, "random"), *control = yyjson_obj_get(root, "encrypt_ctrl");
    if (!yyjson_is_uint(tag) || yyjson_get_uint(tag) > UINT32_MAX) { if (doc) yyjson_doc_free(doc); return BC_PROTOCOL_ERROR; }
    if (control && (!yyjson_is_uint(control) || (yyjson_get_uint(control) != 1 && yyjson_get_uint(control) != 2))) {
        yyjson_doc_free(doc);
        return BC_UNSUPPORTED;
    }
    unsigned mode = control ? (unsigned)yyjson_get_uint(control) : 2;
    uint32_t random = (uint32_t)yyjson_get_uint(tag); yyjson_doc_free(doc);
    char *user = credential(username, mode), *pass = credential(password, mode);
    if (!user || !pass) { free(user); free(pass); return BC_INVALID_ARGUMENT; }
    size_t n = strlen(user) + strlen(pass) + 100;
    *out = malloc(n);
    if (*out) snprintf(*out, n, "username=%s&password=%s&encrypt_flag=%u&login_tag=%lu", user, pass, mode, (unsigned long)random);
    size_t pass_length = strlen(pass); volatile char *wipe = pass; for (size_t i = 0; i < pass_length; ++i) wipe[i] = 0;
    free(user); free(pass); return *out ? BC_OK : BC_NO_MEMORY;
}

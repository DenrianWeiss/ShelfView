#include "bcontrol/socks5.h"
#include "bcontrol/wire.h"
#include <string.h>

static int valid(const bc_socks5_address *a) {
    if (!a) return 0;
    if (a->type == BC_SOCKS5_IPV4) return a->length == 4;
    if (a->type == BC_SOCKS5_IPV6) return a->length == 16;
    if (a->type != BC_SOCKS5_DOMAIN || !a->length) return 0;
    for (unsigned i = 0; i < a->length; ++i)
        if (a->address[i] <= 32 || a->address[i] >= 127) return 0;
    return 1;
}
static bc_status encode(const bc_socks5_address *a, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (!out || !valid(a)) return BC_INVALID_ARGUMENT;
    uint32_t n = 1u + a->length + 2u + (a->type == BC_SOCKS5_DOMAIN);
    if (capacity < n) return BC_LIMIT_EXCEEDED;
    uint32_t offset = 0;
    out[offset++] = a->type;
    if (a->type == BC_SOCKS5_DOMAIN) out[offset++] = a->length;
    memcpy(out + offset, a->address, a->length); offset += a->length;
    bc_wire_write_be(out + offset, a->port, 2);
    *written = n;
    return BC_OK;
}
static bc_status decode(const uint8_t *data, uint32_t size, bc_socks5_address *a, uint32_t *consumed) {
    *consumed = 0;
    memset(a, 0, sizeof(*a));
    if (!size) return BC_OK;
    uint32_t offset = 1, length;
    switch (data[0]) {
    case BC_SOCKS5_IPV4: length = 4; break;
    case BC_SOCKS5_IPV6: length = 16; break;
    case BC_SOCKS5_DOMAIN:
        if (size < 2) return BC_OK;
        length = data[1]; offset = 2;
        if (!length) return BC_PROTOCOL_ERROR;
        break;
    default: return BC_PROTOCOL_ERROR;
    }
    if (size < offset + length + 2) return BC_OK;
    bc_socks5_address result = {0};
    result.type = data[0]; result.length = (uint8_t)length;
    memcpy(result.address, data + offset, length);
    result.port = (uint16_t)bc_wire_read_be(data + offset + length, 2);
    if (!valid(&result)) return BC_PROTOCOL_ERROR;
    *a = result; *consumed = offset + length + 2;
    return BC_OK;
}
bc_status bc_socks5_request(uint8_t command, const bc_socks5_address *a,
    uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (!out || !valid(a) || (command != BC_SOCKS5_CONNECT && command != BC_SOCKS5_UDP_ASSOCIATE))
        return BC_INVALID_ARGUMENT;
    if (capacity < 3) return BC_LIMIT_EXCEEDED;
    bc_status s = encode(a, out + 3, capacity - 3, written);
    if (s == BC_OK) { out[0] = 5; out[1] = command; out[2] = 0; *written += 3; }
    return s;
}
bc_status bc_socks5_reply(const uint8_t *data, uint32_t size, bc_socks5_address *a,
    uint8_t *reply, uint32_t *consumed) {
    if (!a || !reply || !consumed) return BC_INVALID_ARGUMENT;
    *consumed = 0; *reply = 255; memset(a, 0, sizeof(*a));
    if (!data && size) return BC_INVALID_ARGUMENT;
    if (size && data[0] != 5) return BC_PROTOCOL_ERROR;
    if (size < 3) return BC_OK;
    if (data[2] != 0) return BC_PROTOCOL_ERROR;
    bc_status s = decode(data + 3, size - 3, a, consumed);
    if (s == BC_OK && *consumed) { *consumed += 3; *reply = data[1]; }
    return s;
}
bc_status bc_socks5_auth(bc_string user, bc_string password, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (!out || !user.data || !password.data || !user.length || !password.length ||
        user.length > 255 || password.length > 255) return BC_INVALID_ARGUMENT;
    uint32_t n = 3u + (uint32_t)user.length + (uint32_t)password.length;
    if (capacity < n) return BC_LIMIT_EXCEEDED;
    out[0] = 1; out[1] = (uint8_t)user.length;
    memcpy(out + 2, user.data, (size_t)user.length);
    out[2 + user.length] = (uint8_t)password.length;
    memcpy(out + 3 + user.length, password.data, (size_t)password.length);
    *written = n; return BC_OK;
}
bc_status bc_socks5_udp_header(const bc_socks5_address *a, uint8_t *out, uint32_t capacity, uint32_t *written) {
    bc_status s = bc_socks5_request(BC_SOCKS5_UDP_ASSOCIATE, a, out, capacity, written);
    if (s == BC_OK) memset(out, 0, 3);
    return s;
}
bc_status bc_socks5_udp_parse(const uint8_t *data, uint32_t size, bc_socks5_address *a, uint32_t *offset) {
    if (!a || !offset) return BC_INVALID_ARGUMENT;
    *offset = 0; memset(a, 0, sizeof(*a));
    if (!data) return BC_INVALID_ARGUMENT;
    if (size < 3 || data[0] || data[1]) return BC_PROTOCOL_ERROR;
    if (data[2]) return BC_UNSUPPORTED;
    bc_status s = decode(data + 3, size - 3, a, offset);
    if (s != BC_OK) return s;
    if (!*offset) return BC_PROTOCOL_ERROR;
    *offset += 3; return BC_OK;
}

bc_status bc_socks5_negotiate(uint8_t command, const bc_socks5_address *target,
    bc_string username, bc_string password, bc_socks5_read_fn read_fn,
    bc_socks5_write_fn write_fn, void *user, bc_socks5_address *bound, uint8_t *reply) {
    if (!bound || !reply) return BC_INVALID_ARGUMENT;
    memset(bound, 0, sizeof(*bound)); *reply = 255;
    if (!read_fn || !write_fn || !valid(target) ||
        (command != BC_SOCKS5_CONNECT && command != BC_SOCKS5_UDP_ASSOCIATE)) return BC_INVALID_ARGUMENT;
    uint8_t buf[513], request[262]; uint32_t n = 0;
    int authenticated = username.length || password.length;
    if (authenticated) {
        bc_status s = bc_socks5_auth(username, password, buf, sizeof(buf), &n);
        volatile uint8_t *erase = buf;
        for (uint32_t i = 0; i < sizeof(buf); ++i) erase[i] = 0;
        if (s != BC_OK) return s;
    }
    uint8_t method = authenticated ? 2 : 0;
    uint8_t greeting[3] = {5, 1, method};
    bc_status s = write_fn(user, greeting, sizeof(greeting));
    if (s != BC_OK) return s;
    s = read_fn(user, buf, 2);
    if (s != BC_OK) return s;
    if (buf[0] != 5) return BC_PROTOCOL_ERROR;
    if (buf[1] != method) return BC_AUTHENTICATION_FAILED;
    if (authenticated) {
        s = bc_socks5_auth(username, password, buf, sizeof(buf), &n);
        if (s == BC_OK) s = write_fn(user, buf, n);
        volatile uint8_t *erase = buf;
        for (uint32_t i = 0; i < sizeof(buf); ++i) erase[i] = 0;
        if (s != BC_OK) return s;
        s = read_fn(user, buf, 2);
        if (s != BC_OK) return s;
        if (buf[0] != 1) return BC_PROTOCOL_ERROR;
        if (buf[1]) return BC_AUTHENTICATION_FAILED;
    }
    s = bc_socks5_request(command, target, request, sizeof(request), &n);
    if (s != BC_OK) return s;
    s = write_fn(user, request, n);
    if (s != BC_OK) return s;
    s = read_fn(user, buf, 4);
    if (s != BC_OK) return s;
    if (buf[0] != 5 || buf[2]) return BC_PROTOCOL_ERROR;
    uint32_t extra = 0, prefix = 4;
    switch (buf[3]) {
    case BC_SOCKS5_IPV4: extra = 6; break;
    case BC_SOCKS5_IPV6: extra = 18; break;
    case BC_SOCKS5_DOMAIN:
        s = read_fn(user, buf + 4, 1);
        if (s != BC_OK) return s;
        if (!buf[4]) return BC_PROTOCOL_ERROR;
        extra = (uint32_t)buf[4] + 2; prefix = 5; break;
    default: return BC_PROTOCOL_ERROR;
    }
    s = read_fn(user, buf + prefix, extra);
    if (s != BC_OK) return s;
    s = bc_socks5_reply(buf, prefix + extra, bound, reply, &n);
    if (s != BC_OK) return s;
    return *reply == 0 ? BC_OK : *reply == 7 || *reply == 8 ? BC_UNSUPPORTED : BC_IO_ERROR;
}

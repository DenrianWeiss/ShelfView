#define OPENSSL_SUPPRESS_DEPRECATED
#include "bcontrol/ilom.h"
#include "bcontrol/serial_provider.h"
#include "bcontrol/serial_transport.h"
#include <stdio.h>
#include "bcontrol/wire.h"
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

int bc_ilom_serial_fallback_allowed(bc_status status, uint8_t completion) {
    return status == BC_UNSUPPORTED &&
        (completion == 0 || completion == 0x80 || completion == 0x81 || completion == 0xc1);
}

struct bc_ilom_serial {
    bc_kvm_transport *auth, *stream;
    uint8_t rx[65560];
    uint32_t used, target, timeout;
    uint8_t writable, started;
    BF_KEY key;
};
static bc_status exact(bc_kvm_transport *transport, uint8_t *out, uint32_t length, uint32_t timeout) {
    uint32_t offset = 0;
    while (offset < length) {
        uint32_t n = 0;
        bc_status status = bc_kvm_transport_recv(transport, out + offset, length - offset, &n, timeout);
        if (status != BC_OK) return status;
        if (!n) return BC_IO_ERROR;
        offset += n;
    }
    return BC_OK;
}
static bc_status send_packet(bc_ilom_serial *s, uint16_t command, const uint8_t *data, uint32_t length, int encrypted) {
    uint8_t packet[128] = {0};
    if (length > sizeof(packet) - 24) return BC_LIMIT_EXCEEDED;
    memcpy(packet, "REDIRECT", 8);
    bc_wire_write_le(packet + 8, 24, 2); bc_wire_write_le(packet + 10, length, 4);
    bc_wire_write_le(packet + 14, command, 2); packet[18] = 1; packet[21] = (uint8_t)encrypted;
    if (length) memcpy(packet + 24, data, length);
    bc_status status = bc_kvm_transport_send(s->stream, packet, 24 + length);
    OPENSSL_cleanse(packet, sizeof(packet));
    return status;
}
static bc_status receive_packet(bc_ilom_serial *s, uint16_t *command, uint8_t **data, uint32_t *length, uint32_t timeout) {
    if (!s->target) s->target = 24;
    while (s->used < s->target) {
        uint32_t n = 0;
        bc_status status = bc_kvm_transport_recv(s->stream, s->rx + s->used, s->target - s->used, &n, timeout);
        if (status != BC_OK) return status;
        if (!n) return BC_IO_ERROR;
        s->used += n;
        if (s->used == 24) {
            if (memcmp(s->rx, "REDIRECT", 8)) return BC_PROTOCOL_ERROR;
            uint32_t payload;
            if (bc_wire_read_le(s->rx + 8, 2) == 24) payload = (uint32_t)bc_wire_read_le(s->rx + 10, 4);
            /* The initial ILOM device-capability reply has big-endian lengths. */
            else if (bc_wire_read_be(s->rx + 8, 2) == 24 && bc_wire_read_le(s->rx + 14, 2) == 6)
                payload = (uint32_t)bc_wire_read_be(s->rx + 10, 4);
            else return BC_PROTOCOL_ERROR;
            if (payload > sizeof(s->rx) - 24) return BC_LIMIT_EXCEEDED;
            s->target = 24 + payload;
        }
    }
    *command = (uint16_t)bc_wire_read_le(s->rx + 14, 2);
    *length = s->target - 24; *data = s->rx + 24;
    s->used = s->target = 0;
    return bc_wire_read_le(s->rx + 16, 2) ? BC_AUTHENTICATION_FAILED : BC_OK;
}
static bc_status exchange(bc_ilom_serial *s, uint16_t cmd, const uint8_t *request, uint32_t size,
    uint8_t **response, uint32_t expected) {
    bc_status status = send_packet(s, cmd, request, size, 0);
    uint16_t reply = 0; uint32_t length = 0;
    if (status == BC_OK) status = receive_packet(s, &reply, response, &length, s->timeout);
    if (status == BC_OK && (reply != cmd || length != expected)) status = BC_PROTOCOL_ERROR;
    return status;
}
static void md5crypt(const char *password, const uint8_t salt[8], uint8_t out[34]) {
    size_t n = strlen(password); uint8_t digest[16]; MD5_CTX ctx, alt;
    MD5_Init(&ctx); MD5_Update(&ctx, password, n); MD5_Update(&ctx, "$1$", 3); MD5_Update(&ctx, salt, 8);
    MD5_Init(&alt); MD5_Update(&alt, password, n); MD5_Update(&alt, salt, 8); MD5_Update(&alt, password, n); MD5_Final(digest, &alt);
    for (size_t i = n; i; i -= i > 16 ? 16 : i) MD5_Update(&ctx, digest, i > 16 ? 16 : i);
    uint8_t zero = 0;
    for (size_t i = n; i; i >>= 1) MD5_Update(&ctx, i & 1 ? (const void *)&zero : (const void *)password, 1);
    MD5_Final(digest, &ctx);
    for (unsigned i = 0; i < 1000; ++i) {
        MD5_Init(&ctx); MD5_Update(&ctx, i & 1 ? (const void *)password : (const void *)digest, i & 1 ? n : 16);
        if (i % 3) MD5_Update(&ctx, salt, 8);
        if (i % 7) MD5_Update(&ctx, password, n);
        MD5_Update(&ctx, i & 1 ? (const void *)digest : (const void *)password, i & 1 ? 16 : n); MD5_Final(digest, &ctx);
    }
    static const char alphabet[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static const uint8_t order[6][3] = {{0,6,12},{1,7,13},{2,8,14},{3,9,15},{4,10,5},{0,0,11}};
    memcpy(out, "$1$", 3); memcpy(out + 3, salt, 8); out[11] = '$'; unsigned at = 12;
    for (unsigned i = 0; i < 6; ++i) {
        uint32_t value = i == 5 ? digest[11] : ((uint32_t)digest[order[i][0]] << 16) | ((uint32_t)digest[order[i][1]] << 8) | digest[order[i][2]];
        for (unsigned j = 0; j < (i == 5 ? 2u : 4u); ++j) { out[at++] = (uint8_t)alphabet[value & 63]; value >>= 6; }
    }
    OPENSSL_cleanse(digest, sizeof(digest)); OPENSSL_cleanse(&ctx, sizeof(ctx)); OPENSSL_cleanse(&alt, sizeof(alt));
}
static bc_status challenge_digest(const char *password, const uint8_t *salt, const uint8_t challenge[32], uint8_t out[16]) {
    uint8_t hashed[34] = {0};
    if (!memcmp(salt, "$1$", 3)) md5crypt(password, salt + 3, hashed);
    else {
        char encoded[14], des_salt[3] = {(char)(salt[0] ? salt[0] : '.'), (char)(salt[1] ? salt[1] : '.'), 0};
        if (!DES_fcrypt(password, des_salt, encoded)) return BC_UNSUPPORTED;
        memcpy(hashed, encoded, 13); hashed[0] = salt[0]; hashed[1] = salt[1]; OPENSSL_cleanse(encoded, sizeof(encoded));
    }
    MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx, hashed, sizeof(hashed)); MD5_Update(&ctx, challenge, 32); MD5_Final(out, &ctx);
    OPENSSL_cleanse(hashed, sizeof(hashed)); OPENSSL_cleanse(&ctx, sizeof(ctx)); return BC_OK;
}
bc_status bc_ilom_serial_open(const bc_kvm_transport_options *options, bc_string serial_url, bc_ilom_serial **out) {
    return bc_ilom_serial_open_proxy(options, serial_url, NULL, out);
}
bc_status bc_ilom_serial_open_proxy(const bc_kvm_transport_options *options, bc_string serial_url,
    const bc_socks5_proxy *proxy, bc_ilom_serial **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        !options->url.data || !options->username.data || !options->username.length || options->username.length > 16 ||
        !options->password.data || options->password.length > 32 || !serial_url.data ||
        memchr(options->username.data, 0, (size_t)options->username.length) ||
        memchr(options->password.data, 0, (size_t)options->password.length)) return BC_INVALID_ARGUMENT;
    /* Explicit paired service URLs cannot redirect credentials to a different host. */
    if (options->url.length < 12 || options->url.length > 2048 || serial_url.length != options->url.length ||
        memcmp(options->url.data, "tls://", 6) || memcmp(serial_url.data, "tcp://", 6) ||
        memcmp(options->url.data + options->url.length - 5, ":5556", 5) ||
        memcmp(serial_url.data + serial_url.length - 5, ":7579", 5) ||
        memcmp(options->url.data + 6, serial_url.data + 6, (size_t)serial_url.length - 11)) return BC_INVALID_ARGUMENT;
    bc_ilom_serial *s = calloc(1, sizeof(*s)); if (!s) return BC_NO_MEMORY;
    s->timeout = options->timeout_ms ? options->timeout_ms : 5000;
    bc_kvm_transport_options transport = *options;
    transport.username = (bc_string){0}; transport.password = (bc_string){0};
    if (transport.tls_min && transport.tls_min < BC_TLS_1_2) transport.flags |= BC_KVM_TRANSPORT_LEGACY_TLS;
    bc_status status = bc_kvm_transport_connect_proxy(&transport, proxy, &s->auth);
    uint8_t credentials[48] = {0}, request[96] = {0}, *response = NULL, token[20], key[16];
    char username[17] = {0}; memcpy(username, options->username.data, (size_t)options->username.length);
    memcpy(credentials, username, (size_t)options->username.length);
    memcpy(credentials + 16, options->password.data, (size_t)options->password.length);
    if (status == BC_OK) status = bc_kvm_transport_send(s->auth, credentials, sizeof(credentials));
    OPENSSL_cleanse(credentials, sizeof(credentials));
    if (status == BC_OK) status = exact(s->auth, request, 1, s->timeout);
    if (status == BC_OK && request[0] != 1) status = BC_AUTHENTICATION_FAILED;
    transport.url = serial_url; transport.flags = 0;
    if (status == BC_OK) status = bc_kvm_transport_connect_proxy(&transport, proxy, &s->stream);
    memset(request, 0, sizeof(request));
    if (status == BC_OK) status = exchange(s, 6, request, 4, &response, 4);
    if (status == BC_OK && (response[2] != 0 || response[3] != 1)) status = BC_UNSUPPORTED;
    request[0] = request[1] = 255;
    if (status == BC_OK) status = exchange(s, 7, request, 8, &response, 8);
    if (status == BC_OK && (s->rx[19] != 2 || s->rx[20] != 2 || response[4] != 0 || response[5] != 0)) status = BC_UNSUPPORTED;
    request[0] = 1;
    if (status == BC_OK) status = bc_kvm_transport_send(s->auth, request, 1);
    if (status == BC_OK) status = exact(s->auth, token, sizeof(token), s->timeout);
    if (status == BC_OK) status = exchange(s, 23, token, sizeof(token), &response, 20);
    memset(request, 0, sizeof(request)); memcpy(request, username, strlen(username));
    if (status == BC_OK) status = exchange(s, 1, request, 60, &response, 60);
    if (status == BC_OK) status = challenge_digest("token", response + 16, response + 28, request + 16);
    if (status == BC_OK) status = exchange(s, 2, request, 32, &response, 0);
    memset(request + 16, 0, sizeof(request) - 16);
    if (status == BC_OK) status = exchange(s, 24, request, 60, &response, 60);
    if (status == BC_OK) {
        request[0] = 2; memcpy(request + 1, response + 28, 4);
        status = bc_kvm_transport_send(s->auth, request, 5);
    }
    if (status == BC_OK) status = exact(s->auth, request, 32, s->timeout);
    if (status == BC_OK) status = challenge_digest(username, (const uint8_t *)"$1$A17c6z5w$", request, key);
    if (status == BC_OK) BF_set_key(&s->key, sizeof(key), key);
    memset(request, 0, sizeof(request));
    if (status == BC_OK) status = send_packet(s, 3, request, 12, 0);
    if (status == BC_OK) { s->started = 1; request[0] = 1; status = send_packet(s, 21, request, 5, 0); }
    OPENSSL_cleanse(request, sizeof(request)); OPENSSL_cleanse(token, sizeof(token)); OPENSSL_cleanse(key, sizeof(key));
    if (status != BC_OK) { bc_ilom_serial_destroy(s); return status; }
    *out = s; return BC_OK;
}
bc_status bc_ilom_serial_read(bc_ilom_serial *s, uint8_t *out, uint32_t capacity, uint32_t *received, uint32_t timeout) {
    if (!s || !out || !received || !s->started) return BC_INVALID_ARGUMENT;
    *received = 0; uint16_t cmd; uint8_t *data; uint32_t n;
    bc_status status = receive_packet(s, &cmd, &data, &n, timeout); if (status != BC_OK) return status;
    if (cmd == 19) {
        if (n < 6 || bc_wire_read_le(data, 4) != n - 6) return BC_PROTOCOL_ERROR;
        if (n - 6 > capacity) return BC_LIMIT_EXCEEDED;
        memcpy(out, data + 6, n - 6); *received = n - 6;
    } else if (cmd == 22) {
        if (n != 21 || data[0] > 2) return BC_PROTOCOL_ERROR;
        s->writable = data[0] == 1;
    } else if (cmd != 8) return BC_PROTOCOL_ERROR;
    return BC_OK;
}
bc_status bc_ilom_serial_write(bc_ilom_serial *s, const uint8_t *data, uint32_t length) {
    if (!s || (!data && length) || length > 4096) return BC_INVALID_ARGUMENT;
    if (!s->started || !s->writable) return BC_BUSY;
    for (uint32_t i = 0; i < length; ++i) {
        uint8_t plain[8] = {0,0,data[i],5,5,5,5,5}, payload[9] = {1};
        BF_ecb_encrypt(plain, payload + 1, &s->key, BF_ENCRYPT);
        bc_status status = send_packet(s, 20, payload, sizeof(payload), 1);
        OPENSSL_cleanse(plain, sizeof(plain)); OPENSSL_cleanse(payload, sizeof(payload));
        if (status != BC_OK) return BC_OUTCOME_UNKNOWN;
    }
    return BC_OK;
}
int bc_ilom_serial_writable(const bc_ilom_serial *s) { return s && s->started && s->writable; }
bc_status bc_ilom_serial_close(bc_ilom_serial *s) {
    if (!s) return BC_INVALID_ARGUMENT;
    bc_status status = BC_OK; uint8_t empty[5] = {0};
    if (s->stream && s->started) {
        if (s->writable) status = send_packet(s, 21, empty, 5, 0);
        bc_status stop = send_packet(s, 5, empty, 4, 0); if (status == BC_OK) status = stop;
    }
    s->started = s->writable = 0;
    bc_kvm_transport_destroy(s->stream); s->stream = NULL;
    bc_kvm_transport_destroy(s->auth); s->auth = NULL;
    return status;
}
void bc_ilom_serial_destroy(bc_ilom_serial *s) {
    if (!s) return;
    bc_ilom_serial_close(s); OPENSSL_cleanse(s, sizeof(*s)); free(s);
}

static bc_status stream_read(void *context, uint64_t now, uint32_t timeout,
    uint8_t *data, uint32_t capacity, uint32_t *length) {
    (void)now;
    return bc_ilom_serial_read(context, data, capacity, length, timeout);
}
static bc_status stream_write(void *context, bc_bytes bytes, uint32_t *accepted) {
    bc_status status = bc_ilom_serial_write(context, bytes.data, (uint32_t)bytes.length);
    if (status == BC_OK) *accepted = (uint32_t)bytes.length;
    return status;
}
static bc_status stream_info(const void *context, bc_serial_info *out) {
    const bc_ilom_serial *serial = context;
    *out = (bc_serial_info){sizeof(*out), serial->started ? BC_SERIAL_ACTIVE : BC_SERIAL_CLOSED,
        BC_SERIAL_READ | (bc_ilom_serial_writable(serial) ? BC_SERIAL_WRITE : 0), BC_OK, BC_OK, 0, 0, 0, 7579};
    return BC_OK;
}
static bc_status stream_close(void *context) { return bc_ilom_serial_close(context); }
static void stream_destroy(void *context) { bc_ilom_serial_destroy(context); }
bc_status bc_ilom_serial_stream(bc_ilom_serial *serial, bc_serial_stream **out) {
    static const bc_serial_provider provider = {sizeof(provider), stream_read, stream_write, NULL, stream_info, stream_close, stream_destroy};
    return bc_serial_wrap(&provider, serial, out);
}

int bc_serial_fallback_allowed(bc_status status,uint8_t completion) {return bc_ilom_serial_fallback_allowed(status,completion);}
bc_status bc_serial_open(const bc_serial_open_options *options,bc_serial_stream **out) {
    if(!out)return BC_INVALID_ARGUMENT;*out=NULL;
    if(!options||options->struct_size!=sizeof(*options)||options->abi_version!=BC_ABI_VERSION||
        !options->host.data||!options->host.length||options->host.length>253)return BC_INVALID_ARGUMENT;
    for(uint64_t i=0;i<options->host.length;++i){unsigned char c=(unsigned char)options->host.data[i];if(c<=32||c>=127||strchr("/@?#[]\\",c))return BC_INVALID_ARGUMENT;}
    char auth[320],serial[320];int ipv6=memchr(options->host.data,':',(size_t)options->host.length)!=NULL;
    snprintf(auth,sizeof(auth),"tls://%s%.*s%s:5556",ipv6?"[":"",(int)options->host.length,options->host.data,ipv6?"]":"");
    snprintf(serial,sizeof(serial),"tcp://%s%.*s%s:7579",ipv6?"[":"",(int)options->host.length,options->host.data,ipv6?"]":"");
    bc_kvm_transport_options transport={0};transport.struct_size=sizeof(transport);transport.abi_version=BC_ABI_VERSION;
    transport.url=(bc_string){auth,strlen(auth)};transport.username=options->username;transport.password=options->password;transport.ca_file=options->ca_file;
    transport.cert_policy=options->cert_policy;transport.tls_min=options->tls_min;transport.tls_max=options->tls_max;transport.timeout_ms=options->timeout_ms;
    bc_ilom_serial *protocol=NULL;bc_string destination={serial,strlen(serial)};
    bc_status status=options->proxy?bc_ilom_serial_open_proxy(&transport,destination,options->proxy,&protocol):bc_ilom_serial_open(&transport,destination,&protocol);
    if(status==BC_OK)status=bc_ilom_serial_stream(protocol,out);
    if(status==BC_OK)bc_serial_own(*out);else bc_ilom_serial_destroy(protocol);
    return status;
}

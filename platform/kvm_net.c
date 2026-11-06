#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "bcontrol/kvm_transport.h"
#include "bcontrol/wire.h"
#include "monotonic.h"
#include "resolver.h"
#include "../core/log_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define SHUT_RDWR SD_BOTH
#else
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#endif
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#ifdef _WIN32
#include <wincrypt.h>
static void load_windows_roots(SSL_CTX *context) {
    HCERTSTORE roots = CertOpenSystemStoreA(0, "ROOT");
    if (!roots) return;
    PCCERT_CONTEXT certificate = NULL;
    while ((certificate = CertEnumCertificatesInStore(roots, certificate)) != NULL) {
        const unsigned char *encoded = certificate->pbCertEncoded;
        X509 *decoded = d2i_X509(NULL, &encoded, (long)certificate->cbCertEncoded);
        if (decoded) {
            (void)X509_STORE_add_cert(SSL_CTX_get_cert_store(context), decoded);
            X509_free(decoded);
        }
        ERR_clear_error();
    }
    CertCloseStore(roots, 0);
}
#endif
#ifdef BC_KVM_NET_ZLIB
#include <zlib.h>
#endif

#define WS_MESSAGE_LIMIT (16u * 1024u * 1024u)
#define WS_HEADER_LIMIT 16384u
struct bc_kvm_transport {
    uint32_t kind;
    char peer_host[256];
    socket_t socket;
    SSL_CTX *tls;
    SSL *ssl;
    BIO_METHOD *socket_bio_method;
    uint32_t timeout_ms;
    uint64_t connect_deadline;
    uint8_t *message;
    size_t message_length, message_offset;
    uint8_t *fragments;
    size_t fragment_length;
    uint8_t fragment_opcode;
    uint8_t *raw;
    size_t raw_length, raw_offset;
    uint32_t flags;
    int deflate, compressed;
    uint32_t subprotocol;
    int handshake_done;
};
static uint32_t remaining_timeout(const bc_kvm_transport *transport, uint32_t requested) {
    if (!transport->connect_deadline) return requested;
    uint64_t now = bc_monotonic_ms();
    if (now >= transport->connect_deadline) return 0;
    uint64_t remaining = transport->connect_deadline - now;
    return remaining < requested ? (uint32_t)remaining : requested;
}
static int is_ws(uint32_t kind) { return kind == BC_KVM_TRANSPORT_WS || kind == BC_KVM_TRANSPORT_WSS; }
static int is_tls(uint32_t kind) { return kind == BC_KVM_TRANSPORT_TLS || kind == BC_KVM_TRANSPORT_WSS; }
static void close_socket(socket_t fd) {
#ifdef _WIN32
    if (fd != INVALID_SOCKET) closesocket(fd);
#else
    if (fd >= 0) close(fd);
#endif
}
static int socket_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}
static int socket_nonblocking(socket_t fd, int enabled) {
#ifdef _WIN32
    u_long value = enabled != 0;
    return ioctlsocket(fd, FIONBIO, &value) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) == 0;
#endif
}
static int socket_would_block(void) {
#ifdef _WIN32
    return socket_error() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}
static int wait_socket(socket_t fd, int writing, uint32_t timeout_ms) {
#ifdef _WIN32
    WSAPOLLFD entry = {fd, writing ? POLLOUT : POLLIN, 0};
    int result = WSAPoll(&entry, 1, (int)timeout_ms);
#else
    struct pollfd entry = {fd, writing ? POLLOUT : POLLIN, 0};
    int result = poll(&entry, 1, (int)timeout_ms);
#endif
    return result > 0 ? 1 : result == 0 ? 0 : -1;
}
static int parse_url(const char *url, uint32_t *kind, char *host, size_t host_size, uint16_t *port, char *path, size_t path_size) {
    const char *rest;
    uint32_t mode;
    if (!strncmp(url, "tcp://", 6)) { mode = BC_KVM_TRANSPORT_TCP; rest = url + 6; }
    else if (!strncmp(url, "tls://", 6)) { mode = BC_KVM_TRANSPORT_TLS; rest = url + 6; }
    else if (!strncmp(url, "ws://", 5)) { mode = BC_KVM_TRANSPORT_WS; rest = url + 5; }
    else if (!strncmp(url, "wss://", 6)) { mode = BC_KVM_TRANSPORT_WSS; rest = url + 6; }
    else return 0;
    const char *slash = strchr(rest, '/');
    size_t authority = slash ? (size_t)(slash - rest) : strlen(rest);
    const char *colon = NULL;
    for (size_t i = authority; i > 0; --i) if (rest[i - 1] == ':') { colon = rest + i - 1; break; }
    size_t host_length = colon ? (size_t)(colon - rest) : authority;
    if (!host_length || host_length >= host_size) return 0;
    if (rest[0] == '[') {
        if (host_length < 3 || rest[host_length - 1] != ']') return 0;
        memcpy(host, rest + 1, host_length - 2); host[host_length - 2] = 0;
    } else {
        memcpy(host, rest, host_length); host[host_length] = 0;
    }
    *port = (uint16_t)(mode == BC_KVM_TRANSPORT_WS ? 80 : mode == BC_KVM_TRANSPORT_WSS ? 443 : 5900);
    if (colon) {
        char number[8]; size_t n = authority - host_length - 1;
        if (!n || n >= sizeof(number)) return 0;
        memcpy(number, colon + 1, n); number[n] = 0;
        char *end = NULL;
        unsigned long value = strtoul(number, &end, 10);
        if (!*number || *end || !value || value > 65535) return 0;
        *port = (uint16_t)value;
    }
    if (slash) {
        size_t length = strlen(slash);
        if (length >= path_size) return 0;
        memcpy(path, slash, length + 1);
    } else strcpy(path, "/");
    *kind = mode;
    return 1;
}
static void set_socket_timeout(socket_t fd, uint32_t timeout_ms) {
#ifdef _WIN32
    DWORD value = timeout_ms;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&value, sizeof(value));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&value, sizeof(value));
#else
    struct timeval value = {(time_t)(timeout_ms / 1000), (suseconds_t)(timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value));
#endif
}
static socket_t connect_tcp(const char *host, uint16_t port, uint32_t timeout_ms, bc_status *status) {
    *status = BC_IO_ERROR;
    uint64_t started = bc_monotonic_ms();
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return INVALID_SOCKET;
#endif
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char service[8];
    snprintf(service, sizeof(service), "%u", port);
    struct addrinfo *list = NULL;
    *status = bc_net_resolve(host, service, &hints, timeout_ms, &list);
    if (*status != BC_OK) return INVALID_SOCKET;
    *status = BC_IO_ERROR;
    socket_t fd = INVALID_SOCKET;
    for (struct addrinfo *item = list; item; item = item->ai_next) {
        uint64_t now = bc_monotonic_ms();
        if (now < started || now - started >= timeout_ms) break;
        fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (fd == INVALID_SOCKET) continue;
#ifdef SO_NOSIGPIPE
        int no_sigpipe = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe))) {
            close_socket(fd); fd = INVALID_SOCKET; continue;
        }
#endif
#ifdef _WIN32
        u_long nonblocking = 1;
        ioctlsocket(fd, FIONBIO, &nonblocking);
#else
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
        int result = connect(fd, item->ai_addr, (int)item->ai_addrlen);
#ifdef _WIN32
        int pending = result && socket_error() == WSAEWOULDBLOCK;
#else
        int pending = result && socket_error() == EINPROGRESS;
#endif
        if (result && !pending) { close_socket(fd); fd = INVALID_SOCKET; continue; }
        now = bc_monotonic_ms();
        if (now < started || now - started >= timeout_ms) {
            close_socket(fd); fd = INVALID_SOCKET; break;
        }
        uint32_t remaining = timeout_ms - (uint32_t)(now - started);
        if (!result || wait_socket(fd, 1, remaining) == 1) {
            int error = 0;
            socklen_t length = sizeof(error);
            if (!getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &length) && !error) {
#ifdef _WIN32
                nonblocking = 0; ioctlsocket(fd, FIONBIO, &nonblocking);
#else
                fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
#endif
                break;
            }
        }
        close_socket(fd); fd = INVALID_SOCKET;
    }
    freeaddrinfo(list);
    if (fd != INVALID_SOCKET) set_socket_timeout(fd, timeout_ms);
    return fd;
}
static long min_version(uint32_t version) {
    switch (version) {
    case BC_TLS_1_0: return TLS1_VERSION;
    case BC_TLS_1_1: return TLS1_1_VERSION;
    case BC_TLS_1_3: return TLS1_3_VERSION;
    default: return TLS1_2_VERSION;
    }
}
static long max_version(uint32_t version) {
    switch (version) {
    case BC_TLS_1_0: return TLS1_VERSION;
    case BC_TLS_1_1: return TLS1_1_VERSION;
    case BC_TLS_1_2: return TLS1_2_VERSION;
    default: return TLS1_3_VERSION;
    }
}
#ifdef MSG_NOSIGNAL
static int socket_bio_write(BIO *bio, const char *data, int length) {
    BIO_clear_retry_flags(bio);
    if (!data || length < 0) { errno = EINVAL; return -1; }
    int fd = BIO_get_fd(BIO_next(bio), NULL);
    int result = (int)send(fd, data, (size_t)length, MSG_NOSIGNAL);
    if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
        BIO_set_retry_write(bio);
    return result;
}
static int socket_bio_puts(BIO *bio, const char *value) {
    size_t length = strlen(value);
    if (length > INT_MAX) { errno = EINVAL; return -1; }
    return socket_bio_write(bio, value, (int)length);
}
static int socket_bio_read(BIO *bio, char *data, int length) {
    BIO_clear_retry_flags(bio);
    int result = BIO_read(BIO_next(bio), data, length);
    BIO_copy_next_retry(bio);
    return result;
}
static long socket_bio_ctrl(BIO *bio, int command, long argument, void *pointer) {
    if (command == BIO_CTRL_DUP) return 0;
    return BIO_ctrl(BIO_next(bio), command, argument, pointer);
}
static int socket_bio_create(BIO *bio) { BIO_set_init(bio, 1); return 1; }
#endif
static int tls_set_socket(bc_kvm_transport *transport) {
#ifdef MSG_NOSIGNAL
    transport->socket_bio_method = BIO_meth_new(BIO_TYPE_FILTER | BIO_TYPE_DESCRIPTOR, "bControl socket output");
    BIO_METHOD *method = transport->socket_bio_method;
    if (!method || !BIO_meth_set_write(method, socket_bio_write) ||
        !BIO_meth_set_puts(method, socket_bio_puts) || !BIO_meth_set_read(method, socket_bio_read) ||
        !BIO_meth_set_ctrl(method, socket_bio_ctrl) || !BIO_meth_set_create(method, socket_bio_create)) return 0;
    BIO *filter = BIO_new(method), *socket = BIO_new_socket((int)transport->socket, BIO_NOCLOSE);
    if (!filter || !socket) { BIO_free(filter); BIO_free(socket); return 0; }
    BIO_push(filter, socket);
    SSL_set_bio(transport->ssl, filter, filter);
    return 1;
#else
    return SSL_set_fd(transport->ssl, (int)transport->socket);
#endif
}
static void free_tls(bc_kvm_transport *transport) {
    SSL_free(transport->ssl); transport->ssl = NULL;
    SSL_CTX_free(transport->tls); transport->tls = NULL;
    BIO_meth_free(transport->socket_bio_method); transport->socket_bio_method = NULL;
}
static int numeric_host(const char *host) {
    uint8_t address[16];
    return inet_pton(AF_INET, host, address) == 1 || inet_pton(AF_INET6, host, address) == 1;
}
static int set_peer_identity(X509_VERIFY_PARAM *param, const char *host) {
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    return numeric_host(host) ? X509_VERIFY_PARAM_set1_ip_asc(param, host) : X509_VERIFY_PARAM_set1_host(param, host, 0);
}
static int tls_connect_identity(bc_kvm_transport *, const char *, const bc_kvm_transport_options *, X509 *, EVP_PKEY *);
static int tls_connect(bc_kvm_transport *transport, const char *host, const bc_kvm_transport_options *options) {
    return tls_connect_identity(transport, host, options, NULL, NULL);
}
static int tls_connect_identity(bc_kvm_transport *transport, const char *host, const bc_kvm_transport_options *options, X509 *certificate, EVP_PKEY *key) {
    snprintf(transport->peer_host, sizeof(transport->peer_host), "%s", host);
    transport->tls = SSL_CTX_new(TLS_client_method());
    if (!transport->tls) return 0;
    if (certificate && (SSL_CTX_use_certificate(transport->tls, certificate) != 1 ||
        SSL_CTX_use_PrivateKey(transport->tls, key) != 1 || SSL_CTX_check_private_key(transport->tls) != 1)) return 0;
    if ((options->flags & BC_KVM_TRANSPORT_LEGACY_TLS) && options->tls_min && options->tls_min < BC_TLS_1_2) {
        SSL_CTX_set_options(transport->tls, SSL_OP_LEGACY_SERVER_CONNECT);
        SSL_CTX_set_security_level(transport->tls, 0);
    }
    if ((options->flags & BC_KVM_TRANSPORT_NO_DHE) &&
        SSL_CTX_set_cipher_list(transport->tls, "DEFAULT:!DH") != 1) return 0;
    SSL_CTX_set_min_proto_version(transport->tls, min_version(options->tls_min ? options->tls_min : BC_TLS_1_2));
    SSL_CTX_set_max_proto_version(transport->tls, max_version(options->tls_max ? options->tls_max : BC_TLS_1_3));
    if (options->ca_file.length && !SSL_CTX_load_verify_locations(transport->tls, options->ca_file.data, NULL)) return 0;
    else if (!options->ca_file.length) {
        SSL_CTX_set_default_verify_paths(transport->tls);
#ifdef _WIN32
        load_windows_roots(transport->tls);
#endif
    }
    if (options->cert_policy == BC_CERT_STRICT) SSL_CTX_set_verify(transport->tls, SSL_VERIFY_PEER, NULL);
    else SSL_CTX_set_verify(transport->tls, SSL_VERIFY_NONE, NULL);
    transport->ssl = SSL_new(transport->tls);
    if (!transport->ssl) return 0;
    if (!tls_set_socket(transport)) return 0;
    SSL_set_tlsext_host_name(transport->ssl, host);
    if (options->cert_policy != BC_CERT_SKIP_ALL) {
        X509_VERIFY_PARAM *param = SSL_get0_param(transport->ssl);
        if (!set_peer_identity(param, host)) return 0;
    }
    for (;;) {
        uint32_t remaining = remaining_timeout(transport, transport->timeout_ms);
        if (!remaining) return 0;
        int result = SSL_connect(transport->ssl);
        if (result == 1) {
            if (options->cert_policy == BC_CERT_SKIP_CHAIN) {
                X509 *peer = SSL_get1_peer_certificate(transport->ssl);
                int matches = peer && (numeric_host(host) ? X509_check_ip_asc(peer, host, 0) :
                    X509_check_host(peer, host, 0, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, NULL)) == 1;
                X509_free(peer);
                if (!matches) return 0;
            }
            const SSL_CIPHER *cipher = SSL_get_current_cipher(transport->ssl);
            BC_LOG_INFO(BC_LOG_CATEGORY_TLS, "kvm.tls", "tls=%s cipher=%s verify_result=%ld cert_policy=%u",
                SSL_get_version(transport->ssl), cipher ? SSL_CIPHER_get_name(cipher) : "-",
                SSL_get_verify_result(transport->ssl), options->cert_policy);
            return 1;
        }
        int error = SSL_get_error(transport->ssl, result);
        if (error == SSL_ERROR_WANT_READ) { if (wait_socket(transport->socket, 0, remaining) != 1) return 0; }
        else if (error == SSL_ERROR_WANT_WRITE) { if (wait_socket(transport->socket, 1, remaining) != 1) return 0; }
        else {
            BC_LOG_ERROR(BC_LOG_CATEGORY_TLS, "kvm.tls_failed", "ssl_error=%d cert_policy=%u tls_min=%u tls_max=%u",
                error, options->cert_policy, options->tls_min, options->tls_max);
            return 0;
        }
    }
}
static int base64_encode(const uint8_t *data, size_t length, char *out, size_t capacity) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t needed = 4 * ((length + 2) / 3);
    if (needed + 1 > capacity) return 0;
    size_t at = 0;
    for (size_t i = 0; i < length; i += 3) {
        uint32_t value = (uint32_t)data[i] << 16;
        if (i + 1 < length) value |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < length) value |= data[i + 2];
        out[at++] = alphabet[(value >> 18) & 63];
        out[at++] = alphabet[(value >> 12) & 63];
        out[at++] = i + 1 < length ? alphabet[(value >> 6) & 63] : '=';
        out[at++] = i + 2 < length ? alphabet[value & 63] : '=';
    }
    out[at] = 0;
    return 1;
}
static int write_all(bc_kvm_transport *transport, const uint8_t *data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        uint32_t remaining = remaining_timeout(transport, transport->timeout_ms);
        if (!remaining) return 0;
        int n;
        if (transport->ssl) {
            int result = SSL_write(transport->ssl, data + sent, (int)(length - sent));
            if (result <= 0) {
                int error = SSL_get_error(transport->ssl, result);
                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                    if (wait_socket(transport->socket, error == SSL_ERROR_WANT_WRITE, remaining) != 1) return 0;
                    continue;
                }
                return 0;
            }
            n = result;
        } else {
#ifdef MSG_NOSIGNAL
            int flags = MSG_NOSIGNAL;
#else
            int flags = 0;
#endif
            n = (int)send(transport->socket, (const char *)data + sent, (int)(length - sent), flags);
            if (n <= 0) {
                if (socket_error() == EINTR) continue;
                if (socket_would_block() && wait_socket(transport->socket, 1, remaining) == 1) continue;
                return 0;
            }
        }
        sent += (size_t)n;
    }
    return 1;
}
static int read_some(bc_kvm_transport *transport, uint8_t *data, size_t length, uint32_t timeout_ms) {
    timeout_ms = remaining_timeout(transport, timeout_ms);
    if (transport->connect_deadline && !timeout_ms) return 0;
    uint64_t deadline = bc_monotonic_ms() + timeout_ms;
    if (!transport->ssl || SSL_pending(transport->ssl) <= 0) {
        int ready = wait_socket(transport->socket, 0, timeout_ms);
        if (ready != 1) return ready;
    }
    for (;;) {
        int n;
        if (transport->ssl) {
            n = SSL_read(transport->ssl, data, (int)length);
            if (n > 0) return n;
            int error = SSL_get_error(transport->ssl, n);
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                uint64_t now = bc_monotonic_ms();
                if (now >= deadline || wait_socket(transport->socket, error == SSL_ERROR_WANT_WRITE, (uint32_t)(deadline - now)) != 1) return 0;
                continue;
            }
            return -1;
        }
        n = (int)recv(transport->socket, (char *)data, (int)length, 0);
        if (n > 0) return n;
        if (n < 0 && socket_error() == EINTR) continue;
        if (n < 0 && socket_would_block()) return 0;
        return -1;
    }
}
static int read_exact(bc_kvm_transport *transport, uint8_t *data, size_t length) {
    size_t got = 0;
    if (transport->raw_offset < transport->raw_length) {
        size_t available = transport->raw_length - transport->raw_offset;
        size_t count = available < length ? available : length;
        memcpy(data, transport->raw + transport->raw_offset, count);
        transport->raw_offset += count; got = count;
    }
    return got == length;
}
static int header_value(const char *headers, const char *name, char *value, size_t capacity) {
    size_t name_length = strlen(name);
    const char *line = headers;
    while (*line) {
        const char *end = strstr(line, "\r\n");
        if (!end) end = line + strlen(line);
        const char *colon = memchr(line, ':', (size_t)(end - line));
        if (colon && (size_t)(colon - line) == name_length) {
            size_t i = 0;
            while (i < name_length && (line[i] | 32) == (name[i] | 32)) ++i;
            if (i == name_length) {
                const char *start = colon + 1;
                while (start < end && (*start == ' ' || *start == '\t')) ++start;
                const char *finish = end;
                while (finish > start && (finish[-1] == ' ' || finish[-1] == '\t')) --finish;
                size_t length = (size_t)(finish - start);
                if (length >= capacity) return 0;
                memcpy(value, start, length); value[length] = 0;
                return 1;
            }
        }
        line = *end ? end + 2 : end;
    }
    return 0;
}
static int ws_handshake(bc_kvm_transport *transport, const bc_kvm_transport_options *options, const char *host, uint16_t port, const char *path) {
    uint8_t nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return 0;
    char key[32], accept[64];
    if (!base64_encode(nonce, sizeof(nonce), key, sizeof(key))) return 0;
    char expected[64];
    size_t expected_length = (size_t)snprintf(expected, sizeof(expected), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned digest_length = 0;
    if (!EVP_Digest(expected, expected_length, digest, &digest_length, EVP_sha1(), NULL) ||
        !base64_encode(digest, digest_length, accept, sizeof(accept))) return 0;
    char request[2048];
    size_t at = 0;
    if ((is_tls(transport->kind) && port == 443) || (!is_tls(transport->kind) && port == 80))
        at += (size_t)snprintf(request + at, sizeof(request) - at,
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", path, host, key);
    else
        at += (size_t)snprintf(request + at, sizeof(request) - at,
            "GET %s HTTP/1.1\r\nHost: %s:%u\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", path, host, port, key);
#ifdef BC_KVM_NET_ZLIB
    if (options->flags & BC_KVM_TRANSPORT_DEFLATE) {
        static const char extension[] = "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; "
            "server_no_context_takeover\r\n";
        if (at + sizeof(extension) - 1 >= sizeof(request)) return 0;
        memcpy(request + at, extension, sizeof(extension) - 1);
        at += sizeof(extension) - 1;
    }
#else
    if (options->flags & BC_KVM_TRANSPORT_DEFLATE) return 0;
#endif
    if (options->username.length) {
        char *basic = malloc((size_t)options->username.length + options->password.length + 2);
        if (!basic) return 0;
        memcpy(basic, options->username.data, (size_t)options->username.length);
        basic[options->username.length] = ':';
        memcpy(basic + options->username.length + 1, options->password.data, (size_t)options->password.length);
        size_t raw_length = (size_t)(options->username.length + 1 + options->password.length);
        char encoded[512];
        int ok = raw_length < 384 && base64_encode((const uint8_t *)basic, raw_length, encoded, sizeof(encoded));
        memset(basic, 0, raw_length); free(basic);
        if (!ok) return 0;
        at += (size_t)snprintf(request + at, sizeof(request) - at, "Authorization: Basic %s\r\n", encoded);
    }
    if (options->subprotocols.length) {
        char line[160];
        int length = snprintf(line, sizeof(line), "Sec-WebSocket-Protocol: %.*s\r\n",
            (int)options->subprotocols.length, options->subprotocols.data);
        if (length <= 0 || (size_t)length >= sizeof(line) || at + (size_t)length >= sizeof(request)) return 0;
        memcpy(request + at, line, (size_t)length); at += (size_t)length;
    }
    for (uint32_t i = 0; i < options->header_count; ++i) {
        bc_string header = options->headers[i];
        if (header.length + at + 2 >= sizeof(request) || memchr(header.data, '\r', (size_t)header.length) ||
            memchr(header.data, '\n', (size_t)header.length)) return 0;
        memcpy(request + at, header.data, (size_t)header.length); at += (size_t)header.length;
        memcpy(request + at, "\r\n", 2); at += 2;
    }
    memcpy(request + at, "\r\n", 2); at += 2;
    if (!write_all(transport, (const uint8_t *)request, at)) return 0;
    char response[WS_HEADER_LIMIT + 1];
    size_t got = 0;
    while (got < WS_HEADER_LIMIT) {
        int n = read_some(transport, (uint8_t *)response + got, WS_HEADER_LIMIT - got, transport->timeout_ms);
        if (n <= 0) return 0;
        got += (size_t)n;
        response[got] = 0;
        if (strstr(response, "\r\n\r\n")) break;
    }
    response[got] = 0;
    if (!strstr(response, "\r\n\r\n") || strncmp(response, "HTTP/1.1 101", 12)) return 0;
    char *end = strstr(response, "\r\n");
    if (!end) return 0;
    char value[512];
    if (!header_value(end + 2, "sec-websocket-accept", value, sizeof(value)) || strcmp(value, accept)) return 0;
    if (header_value(end + 2, "sec-websocket-protocol", value, sizeof(value))) {
        if (!strcmp(value, "binary")) transport->subprotocol = BC_KVM_TRANSPORT_SUBPROTOCOL_BINARY;
        else if (!strcmp(value, "base64")) transport->subprotocol = BC_KVM_TRANSPORT_SUBPROTOCOL_BASE64;
        else return 0;
    }
    if (options->flags & BC_KVM_TRANSPORT_DEFLATE) {
#ifdef BC_KVM_NET_ZLIB
        if (!header_value(end + 2, "sec-websocket-extensions", value, sizeof(value)) ||
            !strstr(value, "permessage-deflate") || !strstr(value, "server_no_context_takeover")) return 0;
        transport->deflate = 1;
#else
        return 0;
#endif
    }
    size_t header_length = (size_t)(strstr(response, "\r\n\r\n") + 4 - response);
    if (got > header_length) {
        size_t extra = got - header_length;
        transport->raw = malloc(extra);
        if (!transport->raw) return 0;
        memcpy(transport->raw, response + header_length, extra);
        transport->raw_length = extra;
        transport->raw_offset = 0;
    }
    return 1;
}
static int ws_send_frame(bc_kvm_transport *transport, uint8_t opcode, const uint8_t *payload, size_t length) {
    uint8_t header[14];
    size_t header_length = 2;
    header[0] = (uint8_t)(0x80 | opcode);
    if (length < 126) header[1] = (uint8_t)(0x80 | length);
    else if (length <= 65535) {
        header[1] = 0x80 | 126;
        bc_wire_write_be(header + 2, length, 2);
        header_length = 4;
    } else {
        header[1] = 0x80 | 127;
        bc_wire_write_be(header + 2, length, 8);
        header_length = 10;
    }
    uint8_t mask[4];
    if (RAND_bytes(mask, sizeof(mask)) != 1) return 0;
    memcpy(header + header_length, mask, 4);
    header_length += 4;
    if (length <= 4096) {
        /* Keep small control frames (RFB handshake, key2, vendor replies) in one
         * TCP write; some BMC WebSocket endpoints are sensitive to split frames. */
        uint8_t single[14 + 4096];
        memcpy(single, header, header_length);
        for (size_t i = 0; i < length; ++i) single[header_length + i] = payload[i] ^ mask[i % 4];
        return write_all(transport, single, header_length + length);
    }
    if (!write_all(transport, header, header_length)) return 0;
    uint8_t block[4096];
    size_t sent = 0;
    while (sent < length) {
        size_t chunk = length - sent < sizeof(block) ? length - sent : sizeof(block);
        for (size_t i = 0; i < chunk; ++i) block[i] = payload[sent + i] ^ mask[(sent + i) % 4];
        if (!write_all(transport, block, chunk)) return 0;
        sent += chunk;
    }
    return 1;
}
#ifdef BC_KVM_NET_ZLIB
static int ws_set_message(bc_kvm_transport *transport, const uint8_t *data, size_t length, uint8_t opcode);
static int ws_inflate_message(bc_kvm_transport *transport, const uint8_t *data, size_t length) {
    if (!transport->deflate || length > WS_MESSAGE_LIMIT) return 0;
    uint8_t *input = malloc(length + 4);
    if (!input) return 0;
    memcpy(input, data, length);
    memcpy(input + length, "\x00\x00\xff\xff", 4);
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, -15) != Z_OK) { free(input); return 0; }
    stream.next_in = input; stream.avail_in = (uInt)(length + 4);
    size_t capacity = length * 4 + 65536, used = 0;
    if (capacity > WS_MESSAGE_LIMIT) capacity = WS_MESSAGE_LIMIT;
    uint8_t *output = malloc(capacity);
    int ok = output != NULL;
    while (ok) {
        stream.next_out = output + used; stream.avail_out = (uInt)(capacity - used);
        int result = inflate(&stream, Z_SYNC_FLUSH);
        used = capacity - stream.avail_out;
        if (result == Z_STREAM_END) break;
        if (result != Z_OK && result != Z_BUF_ERROR) { ok = 0; break; }
        if (stream.avail_out == 0) {
            if (capacity >= WS_MESSAGE_LIMIT) { ok = 0; break; }
            size_t grown = capacity * 2 > WS_MESSAGE_LIMIT ? WS_MESSAGE_LIMIT : capacity * 2;
            uint8_t *next = realloc(output, grown);
            if (!next) { ok = 0; break; }
            output = next; capacity = grown;
        } else if (stream.avail_in == 0) break;
    }
    inflateEnd(&stream);
    free(input);
    if (ok) ok = ws_set_message(transport, output, used, 0x2);
    free(output);
    return ok;
}
#endif
static int ws_set_message(bc_kvm_transport *transport, const uint8_t *data, size_t length, uint8_t opcode) {
    if (length > WS_MESSAGE_LIMIT) return 0;
    uint8_t *copy = malloc(length ? length : 1);
    if (!copy) return 0;
    memcpy(copy, data, length);
    free(transport->message);
    transport->message = copy;
    transport->message_length = length;
    transport->message_offset = 0;
    (void)opcode;
    return 1;
}
static int ws_append_fragment(bc_kvm_transport *transport, const uint8_t *data, size_t length, int final) {
    if (transport->fragment_length + length > WS_MESSAGE_LIMIT) return 0;
    uint8_t *grown = realloc(transport->fragments, transport->fragment_length + length ? transport->fragment_length + length : 1);
    if (!grown) return 0;
    transport->fragments = grown;
    memcpy(transport->fragments + transport->fragment_length, data, length);
    transport->fragment_length += length;
    if (!final) return 1;
    int ok = ws_set_message(transport, transport->fragments, transport->fragment_length, transport->fragment_opcode);
    free(transport->fragments);
    transport->fragments = NULL;
    transport->fragment_length = 0;
    transport->fragment_opcode = 0;
    return ok;
}
static int ws_read_frame(bc_kvm_transport *transport) {
    for (;;) {
        uint8_t header[2];
        if (!read_exact(transport, header, 2)) return 0;
        int final = header[0] & 0x80;
        int compressed = header[0] & 0x40;
        uint8_t opcode = header[0] & 0x0f;
        if (opcode == 1 && (transport->flags & BC_KVM_TRANSPORT_BINARY_ONLY)) return 0;
        if ((header[0] & 0x30) || (!transport->deflate && compressed) || (opcode >= 8 && compressed)) return 0;
        int masked = header[1] & 0x80;
        uint64_t length = header[1] & 0x7f;
        if (opcode >= 8 && (!final || length > 125)) return 0;
        if (length == 126) {
            uint8_t extended[2];
            if (!read_exact(transport, extended, 2)) return 0;
            length = bc_wire_read_be(extended, 2);
        } else if (length == 127) {
            uint8_t extended[8];
            if (!read_exact(transport, extended, 8)) return 0;
            length = bc_wire_read_be(extended, 8);
        }
        if (masked) return 0;
        if (length > WS_MESSAGE_LIMIT) return 0;
        uint8_t *payload = malloc((size_t)length ? (size_t)length : 1);
        if (!payload) return 0;
        int ok = read_exact(transport, payload, (size_t)length);
        if (!ok) { free(payload); return 0; }
        if (opcode == 0x9) {
            ok = ws_send_frame(transport, 0xA, payload, (size_t)length);
            free(payload);
            if (!ok) return 0;
            return 1;
        }
        if (opcode == 0xA) { free(payload); return 1; }
        if (opcode == 0x8) {
            ws_send_frame(transport, 0x8, payload, (size_t)length);
            free(payload);
            return 0;
        }
        if (opcode == 0x1 || opcode == 0x2) {
            if (transport->fragment_opcode) { free(payload); return 0; }
#ifdef BC_KVM_NET_ZLIB
            if (compressed && !transport->deflate) { free(payload); return 0; }
#endif
            if (!final) {
                transport->fragment_opcode = opcode;
                transport->compressed = compressed;
                if (!ws_append_fragment(transport, payload, (size_t)length, 0)) { free(payload); return 0; }
                free(payload);
                return 1;
            }
#ifdef BC_KVM_NET_ZLIB
            ok = compressed ? ws_inflate_message(transport, payload, (size_t)length) :
                ws_set_message(transport, payload, (size_t)length, opcode);
#else
            ok = ws_set_message(transport, payload, (size_t)length, opcode);
#endif
            free(payload);
            return ok;
        }
        if (opcode == 0x0) {
            if (!transport->fragment_opcode || compressed) { free(payload); return 0; }
            if (!final) {
                ok = ws_append_fragment(transport, payload, (size_t)length, 0);
                free(payload);
                return ok;
            }
#ifdef BC_KVM_NET_ZLIB
            if (transport->compressed) {
                if (!ws_append_fragment(transport, payload, (size_t)length, 0)) { free(payload); return 0; }
                ok = ws_inflate_message(transport, transport->fragments, transport->fragment_length);
                free(transport->fragments);
                transport->fragments = NULL;
                transport->fragment_length = 0;
                transport->fragment_opcode = 0;
                transport->compressed = 0;
                free(payload);
                return ok;
            }
#endif
            ok = ws_append_fragment(transport, payload, (size_t)length, final);
            free(payload);
            return ok;
        }
        free(payload);
        return 0;
    }
}
static int validate_headers(const bc_kvm_transport_options *options) {
    if (options->header_count > 16 || (options->header_count && !options->headers)) return 0;
    for (uint32_t i = 0; i < options->header_count; ++i) {
        bc_string header = options->headers[i];
        if (header.length < 3 || header.length > 2048 || !header.data ||
            memchr(header.data, '\r', (size_t)header.length) || memchr(header.data, '\n', (size_t)header.length) ||
            memchr(header.data, 0, (size_t)header.length)) return 0;
    }
    return 1;
}
typedef struct { bc_kvm_transport *transport; uint64_t deadline; } socks_io;
static bc_status socks_read(void *user, uint8_t *data, uint32_t length) {
    socks_io *io = user;
    while (length) {
        uint64_t now = bc_monotonic_ms();
        if (now >= io->deadline) return BC_TIMEOUT;
        uint32_t remaining = (uint32_t)(io->deadline - now);
        set_socket_timeout(io->transport->socket, remaining);
        int n = read_some(io->transport, data, length, remaining);
        if (n <= 0) return n == 0 ? BC_TIMEOUT : BC_IO_ERROR;
        data += n; length -= (uint32_t)n;
    }
    return BC_OK;
}
static bc_status socks_write(void *user, const uint8_t *data, uint32_t length) {
    socks_io *io = user;
    uint64_t now = bc_monotonic_ms();
    if (now >= io->deadline) return BC_TIMEOUT;
    set_socket_timeout(io->transport->socket, (uint32_t)(io->deadline - now));
    return write_all(io->transport, data, length) ? BC_OK : BC_IO_ERROR;
}
bc_status bc_kvm_transport_connect(const bc_kvm_transport_options *options, bc_kvm_transport **out) {
    return bc_kvm_transport_connect_proxy(options, NULL, out);
}
bc_status bc_kvm_transport_connect_proxy(const bc_kvm_transport_options *options,
    const bc_socks5_proxy *proxy, bc_kvm_transport **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        !options->url.length || !validate_headers(options) || options->cert_policy > BC_CERT_SKIP_ALL ||
        options->tls_min > BC_TLS_1_3 || options->tls_max > BC_TLS_1_3 ||
        (options->tls_min && options->tls_max && options->tls_max < options->tls_min) ||
        (options->flags & ~(BC_KVM_TRANSPORT_DEFLATE | BC_KVM_TRANSPORT_LEGACY_TLS | BC_KVM_TRANSPORT_BINARY_ONLY | BC_KVM_TRANSPORT_NO_DHE)) || options->reserved || options->subprotocols.length > 64) return BC_INVALID_ARGUMENT;
    for (uint64_t i = 0; i < options->subprotocols.length; ++i) {
        unsigned char c = (unsigned char)options->subprotocols.data[i];
        if (c < 32 || c == 127) return BC_INVALID_ARGUMENT;
    }
    char *url = malloc((size_t)options->url.length + 1);
    if (!url) return BC_NO_MEMORY;
    memcpy(url, options->url.data, (size_t)options->url.length);
    url[options->url.length] = 0;
    char host[256], path[1024];
    uint16_t port = 0;
    uint32_t kind = 0;
    int parsed = parse_url(url, &kind, host, sizeof(host), &port, path, sizeof(path));
    free(url);
    if (!parsed) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_KVM, "kvm.transport.connect", "status=invalid_argument");
        return BC_INVALID_ARGUMENT;
    }
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_DEBUG
    char log_path[BC_LOG_PATH_MAX];
    uint32_t query = bc_log_path(log_path, sizeof(log_path), path, strlen(path));
    BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "kvm.transport.connect",
        "kind=%u host_len=%zu port=%u path=%s query=%u timeout_ms=%u tls_min=%u tls_max=%u cert_policy=%u deflate=%u",
        kind, strlen(host), port, log_path, query, options->timeout_ms ? options->timeout_ms : 5000,
        options->tls_min, options->tls_max, options->cert_policy, (options->flags & BC_KVM_TRANSPORT_DEFLATE) != 0);
#endif
    bc_kvm_transport *transport = calloc(1, sizeof(*transport));
    if (!transport) return BC_NO_MEMORY;
    transport->kind = kind;
    memcpy(transport->peer_host, host, strlen(host) + 1);
    transport->flags = options->flags;
    transport->timeout_ms = options->timeout_ms ? options->timeout_ms : 5000;
    char proxy_host[256];
    if (proxy) {
        if (proxy->struct_size != sizeof(*proxy) || !proxy->host.data || !proxy->host.length ||
            proxy->host.length >= sizeof(proxy_host) || !proxy->port || proxy->port > 65535 ||
            memchr(proxy->host.data, 0, (size_t)proxy->host.length)) { free(transport); return BC_INVALID_ARGUMENT; }
        memcpy(proxy_host, proxy->host.data, (size_t)proxy->host.length);
        proxy_host[proxy->host.length] = 0;
    }
    uint64_t socks_start = bc_monotonic_ms();
    transport->connect_deadline = socks_start + transport->timeout_ms;
    bc_status connection_status;
    transport->socket = connect_tcp(proxy ? proxy_host : host, proxy ? (uint16_t)proxy->port : port, transport->timeout_ms, &connection_status);
    if (transport->socket == INVALID_SOCKET) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_KVM, "kvm.transport.connect", "status=io_error stage=tcp host_len=%zu port=%u",
            strlen(host), port);
        bc_status failure = remaining_timeout(transport, transport->timeout_ms) ? connection_status : BC_TIMEOUT;
        free(transport); return failure;
    }
    if (!socket_nonblocking(transport->socket, 1)) {
        close_socket(transport->socket); free(transport); return BC_IO_ERROR;
    }
    if (proxy) {
        bc_socks5_address target = {0}, bound;
        target.type = BC_SOCKS5_DOMAIN; target.length = (uint8_t)strlen(host); target.port = port;
        memcpy(target.address, host, target.length);
        if (inet_pton(AF_INET, host, target.address) == 1) { target.type = BC_SOCKS5_IPV4; target.length = 4; }
        else if (inet_pton(AF_INET6, host, target.address) == 1) { target.type = BC_SOCKS5_IPV6; target.length = 16; }
        socks_io io = {transport, socks_start + transport->timeout_ms};
        uint8_t reply;
        bc_status status = bc_socks5_negotiate(BC_SOCKS5_CONNECT, &target,
            proxy->username, proxy->password, socks_read, socks_write, &io, &bound, &reply);
        if (status != BC_OK) { close_socket(transport->socket); free(transport); return status; }
        set_socket_timeout(transport->socket, transport->timeout_ms);
    }
    if (is_tls(kind) && !tls_connect(transport, host, options)) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_KVM, "kvm.transport.connect", "status=tls_error stage=tls host_len=%zu port=%u",
            strlen(host), port);
        bc_status failure = remaining_timeout(transport, transport->timeout_ms) ? BC_TLS_ERROR : BC_TIMEOUT;
        free_tls(transport); close_socket(transport->socket); free(transport); return failure;
    }
    if (is_ws(kind) && !ws_handshake(transport, options, host, port, path)) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_KVM, "kvm.transport.connect", "status=protocol_error stage=websocket host_len=%zu port=%u",
            strlen(host), port);
        bc_status failure = remaining_timeout(transport, transport->timeout_ms) ? BC_PROTOCOL_ERROR : BC_TIMEOUT;
        bc_kvm_transport_destroy(transport);
        return failure;
    }
    if (!remaining_timeout(transport, transport->timeout_ms)) {
        bc_kvm_transport_destroy(transport); return BC_TIMEOUT;
    }
    if (!socket_nonblocking(transport->socket, 0)) {
        bc_kvm_transport_destroy(transport); return BC_IO_ERROR;
    }
    transport->connect_deadline = 0;
    transport->handshake_done = 1;
    *out = transport;
    BC_LOG_INFO(BC_LOG_CATEGORY_KVM, "kvm.transport.connect", "status=ok kind=%u port=%u deflate=%u",
        kind, port, transport->deflate);
    return BC_OK;
}
static bc_status start_tls(bc_kvm_transport *transport, const bc_kvm_tls_options *options, X509 *certificate, EVP_PKEY *key, X509 *pin) {
    if (!transport || !options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        options->cert_policy > BC_CERT_SKIP_ALL || options->tls_min > BC_TLS_1_3 || options->tls_max > BC_TLS_1_3 ||
        (options->tls_min && options->tls_max && options->tls_max < options->tls_min) ||
        (options->flags & ~BC_KVM_TRANSPORT_LEGACY_TLS) || options->ca_file.length > 32768 ||
        (options->ca_file.length && (!options->ca_file.data || memchr(options->ca_file.data, 0, (size_t)options->ca_file.length))))
        return BC_INVALID_ARGUMENT;
    if (transport->kind != BC_KVM_TRANSPORT_TCP || transport->ssl || transport->tls ||
        transport->socket == INVALID_SOCKET || !transport->handshake_done) return BC_BUSY;
    char host[sizeof(transport->peer_host)]; memcpy(host, transport->peer_host, sizeof(host));
    char *ca = NULL;
    if (options->ca_file.length) {
        ca = malloc((size_t)options->ca_file.length + 1);
        if (!ca) return BC_NO_MEMORY;
        memcpy(ca, options->ca_file.data, (size_t)options->ca_file.length); ca[options->ca_file.length] = 0;
    }
    bc_kvm_transport_options tls = {0};
    tls.cert_policy = options->cert_policy; tls.tls_min = options->tls_min; tls.tls_max = options->tls_max;
    tls.flags = options->flags; tls.ca_file = (bc_string){ca, options->ca_file.length};
    uint32_t previous_timeout = transport->timeout_ms;
    transport->timeout_ms = options->timeout_ms ? options->timeout_ms : previous_timeout;
    transport->connect_deadline = bc_monotonic_ms() + transport->timeout_ms;
    bc_status status = BC_OK;
    if (!socket_nonblocking(transport->socket, 1)) status = BC_IO_ERROR;
    else if (!tls_connect_identity(transport, host, &tls, certificate, key))
        status = remaining_timeout(transport, transport->timeout_ms) ? BC_TLS_ERROR : BC_TIMEOUT;
    else if (!socket_nonblocking(transport->socket, 0)) status = BC_IO_ERROR;
    if (status == BC_OK && pin) {
        X509 *peer = SSL_get1_peer_certificate(transport->ssl);
        if (!peer || X509_cmp(peer, pin) || X509_cmp_current_time(X509_get0_notBefore(peer)) >= 0 ||
            X509_cmp_current_time(X509_get0_notAfter(peer)) <= 0) status = BC_TLS_ERROR;
        X509_free(peer);
    }
    free(ca);
    transport->timeout_ms = previous_timeout; transport->connect_deadline = 0;
    if (status == BC_OK) transport->kind = BC_KVM_TRANSPORT_TLS;
    else {
        free_tls(transport); close_socket(transport->socket);
        transport->socket = INVALID_SOCKET; transport->handshake_done = 0;
    }
    return status;
}
bc_status bc_kvm_transport_start_tls(bc_kvm_transport *transport, const bc_kvm_tls_options *options) {
    return start_tls(transport, options, NULL, NULL, NULL);
}
static int no_password(char *buffer, int size, int writing, void *user) {
    (void)buffer; (void)size; (void)writing; (void)user; return 0;
}
bc_status bc_kvm_transport_start_tls_identity(bc_kvm_transport *transport, const bc_kvm_tls_options *options,
    bc_string certificate_pem, bc_string private_key_pem) {
    if (!certificate_pem.data || !private_key_pem.data || !certificate_pem.length || !private_key_pem.length ||
        certificate_pem.length > 65536 || private_key_pem.length > 65536) return BC_INVALID_ARGUMENT;
    BIO *cert_bio = BIO_new_mem_buf(certificate_pem.data, (int)certificate_pem.length);
    BIO *key_bio = BIO_new_mem_buf(private_key_pem.data, (int)private_key_pem.length);
    X509 *certificate = cert_bio ? PEM_read_bio_X509(cert_bio, NULL, NULL, NULL) : NULL;
    EVP_PKEY *key = key_bio ? PEM_read_bio_PrivateKey(key_bio, NULL, no_password, NULL) : NULL;
    bc_status status = BC_PROTOCOL_ERROR;
    if (certificate && key && X509_check_private_key(certificate, key) == 1)
        status = start_tls(transport, options, certificate, key, NULL);
    X509_free(certificate); EVP_PKEY_free(key); BIO_free(cert_bio); BIO_free(key_bio);
    ERR_clear_error(); return status;
}
bc_status bc_kvm_transport_start_tls_pinned(bc_kvm_transport *transport, const bc_kvm_tls_options *options,
    bc_string peer_pem) {
    if (!options || options->struct_size != sizeof(*options) || options->cert_policy > BC_CERT_SKIP_ALL ||
        !peer_pem.data || !peer_pem.length || peer_pem.length > 65536) return BC_INVALID_ARGUMENT;
    BIO *bio = BIO_new_mem_buf(peer_pem.data, (int)peer_pem.length);
    if (!bio) return BC_NO_MEMORY;
    X509 *pin = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    bc_kvm_tls_options pinned = *options;
    pinned.cert_policy = BC_CERT_SKIP_ALL;
    pinned.ca_file = (bc_string){0};
    bc_status status = pin ? start_tls(transport, &pinned, NULL, NULL, pin) : BC_PROTOCOL_ERROR;
    X509_free(pin); BIO_free(bio); ERR_clear_error();
    return status;
}
static int ws_buffer(bc_kvm_transport *transport, size_t needed, uint64_t deadline) {
    size_t available = transport->raw_length - transport->raw_offset;
    if (available >= needed) return 1;
    if (transport->raw_offset) memmove(transport->raw, transport->raw + transport->raw_offset, available);
    transport->raw_length = available; transport->raw_offset = 0;
    uint8_t *grown = realloc(transport->raw, needed);
    if (!grown) return -1;
    transport->raw = grown;
    while (transport->raw_length < needed) {
        uint64_t now = bc_monotonic_ms();
        int n = read_some(transport, transport->raw + transport->raw_length, needed - transport->raw_length,
            now < deadline ? (uint32_t)(deadline - now) : 0);
        if (n <= 0) return n;
        transport->raw_length += (size_t)n;
        if (transport->raw_length < needed && bc_monotonic_ms() >= deadline) return 0;
    }
    return 1;
}
static int ws_buffer_frame(bc_kvm_transport *transport, uint64_t deadline) {
    int result = ws_buffer(transport, 2, deadline);
    if (result != 1) return result;
    const uint8_t *data = transport->raw + transport->raw_offset;
    if (data[1] & 0x80) return -1;
    size_t header = (data[1] & 127) == 126 ? 4 : (data[1] & 127) == 127 ? 10 : 2;
    result = ws_buffer(transport, header, deadline);
    if (result != 1) return result;
    data = transport->raw + transport->raw_offset;
    uint64_t length = header == 2 ? data[1] & 127 : bc_wire_read_be(data + 2, header - 2);
    if (length > WS_MESSAGE_LIMIT) return -1;
    return ws_buffer(transport, header + (size_t)length, deadline);
}
static bc_status receive(bc_kvm_transport *transport, uint8_t *data, uint32_t capacity, uint32_t *received, uint32_t timeout_ms) {
    uint64_t deadline = bc_monotonic_ms() + timeout_ms;
    for (;;) {
        if (transport->message_offset < transport->message_length) {
            size_t available = transport->message_length - transport->message_offset;
            size_t count = available < capacity ? available : capacity;
            memcpy(data, transport->message + transport->message_offset, count);
            transport->message_offset += count;
            *received = (uint32_t)count;
            return BC_OK;
        }
        if (!is_ws(transport->kind)) {
            int n = read_some(transport, data, capacity, timeout_ms);
            if (n < 0) return BC_IO_ERROR;
            if (!n) return BC_TIMEOUT;
            *received = (uint32_t)n; return BC_OK;
        }
        int ready = ws_buffer_frame(transport, deadline);
        if (ready <= 0) return ready == 0 ? BC_TIMEOUT : BC_IO_ERROR;
        if (!ws_read_frame(transport)) return BC_IO_ERROR;
        if (transport->message_offset == transport->message_length && bc_monotonic_ms() >= deadline) return BC_TIMEOUT;
    }
}
bc_status bc_kvm_transport_recv(bc_kvm_transport *transport, uint8_t *data, uint32_t capacity, uint32_t *received, uint32_t timeout_ms) {
    if (!transport || !received || (capacity && !data)) return BC_INVALID_ARGUMENT;
    *received = 0;
    if (!transport->handshake_done) return BC_PROTOCOL_ERROR;
    if (!capacity) return BC_OK;
    if (!socket_nonblocking(transport->socket, 1)) return BC_IO_ERROR;
    bc_status status = receive(transport, data, capacity, received, timeout_ms);
    if (!socket_nonblocking(transport->socket, 0)) return BC_IO_ERROR;
    return status;
}
bc_status bc_kvm_transport_send(bc_kvm_transport *transport, const uint8_t *data, uint32_t length) {
    if (!transport || (length && !data)) return BC_INVALID_ARGUMENT;
    if (!is_ws(transport->kind)) return write_all(transport, data, length) ? BC_OK : BC_IO_ERROR;
    return ws_send_frame(transport, 0x2, data, length) ? BC_OK : BC_IO_ERROR;
}
bc_status bc_kvm_transport_local_address(const bc_kvm_transport *transport, char *out, uint32_t capacity) {
    if (!transport || !out || !capacity || transport->socket == INVALID_SOCKET) return BC_INVALID_ARGUMENT;
    struct sockaddr_storage address;
#ifdef _WIN32
    int length = sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif
    if (getsockname(transport->socket, (struct sockaddr *)&address, &length)) return BC_IO_ERROR;
    return getnameinfo((struct sockaddr *)&address, length, out, capacity, NULL, 0, NI_NUMERICHOST) ? BC_IO_ERROR : BC_OK;
}
uint32_t bc_kvm_transport_kind(const bc_kvm_transport *transport) { return transport ? transport->kind : 0; }
uint32_t bc_kvm_transport_subprotocol(const bc_kvm_transport *transport) {
    return transport ? transport->subprotocol : BC_KVM_TRANSPORT_SUBPROTOCOL_NONE;
}
static int peer_name(X509_NAME *name, char *out, size_t capacity) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return 0;
    int ok = X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) >= 0;
    char *data = NULL; long length = BIO_get_mem_data(bio, &data);
    if (!ok || length < 0 || (size_t)length >= capacity) ok = 0;
    if (ok) { memcpy(out, data, (size_t)length); out[length] = 0; }
    BIO_free(bio); return ok;
}
static int peer_date(const ASN1_TIME *value, char out[21]) {
    struct tm time = {0};
    if (!ASN1_TIME_to_tm(value, &time)) return 0;
    return snprintf(out, 21, "%04d-%02d-%02dT%02d:%02d:%02dZ", time.tm_year + 1900,
        time.tm_mon + 1, time.tm_mday, time.tm_hour, time.tm_min, time.tm_sec) == 20;
}
bc_status bc_kvm_transport_peer_info(const bc_kvm_transport *transport, bc_tls_peer_info *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->abi_version = BC_ABI_VERSION;
    if (!transport || !transport->ssl || !transport->handshake_done) return BC_UNSUPPORTED;
    ERR_clear_error();
    X509 *certificate = SSL_get1_peer_certificate(transport->ssl);
    if (!certificate) return BC_TLS_ERROR;
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
    bc_status status = BC_OK;
    if (!peer_name(X509_get_subject_name(certificate), out->subject, sizeof(out->subject)) ||
        !peer_name(X509_get_issuer_name(certificate), out->issuer, sizeof(out->issuer)) ||
        !peer_date(X509_get0_notBefore(certificate), out->not_before) ||
        !peer_date(X509_get0_notAfter(certificate), out->not_after) ||
        !X509_digest(certificate, EVP_sha256(), digest, &length) || length != 32) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) {
        snprintf(out->version, sizeof(out->version), "%s", SSL_get_version(transport->ssl));
        snprintf(out->cipher, sizeof(out->cipher), "%s", SSL_get_cipher_name(transport->ssl));
        for (unsigned i = 0; i < length; ++i) snprintf(out->sha256 + i * 2, 3, "%02X", digest[i]);
        X509_STORE_CTX *verify = X509_STORE_CTX_new();
        if (!verify) status = BC_NO_MEMORY;
        else {
            if (X509_STORE_CTX_init(verify, SSL_CTX_get_cert_store(transport->tls), certificate,
                    SSL_get_peer_cert_chain(transport->ssl)) != 1 || X509_STORE_CTX_set_default(verify, "ssl_server") != 1) status = BC_TLS_ERROR;
            else {
                X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(verify);
                X509_VERIFY_PARAM_set_auth_level(param, 2);
                int bound = set_peer_identity(param, transport->peer_host);
                if (!bound) status = BC_TLS_ERROR;
                else out->trusted = X509_verify_cert(verify) == 1;
            }
            X509_STORE_CTX_free(verify);
        }
    }
    X509_free(certificate); ERR_clear_error();
    if (status != BC_OK) { memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out); out->abi_version = BC_ABI_VERSION; }
    return status;
}
void bc_kvm_transport_interrupt(bc_kvm_transport *transport) {
    if (transport && transport->socket != INVALID_SOCKET) shutdown(transport->socket, SHUT_RDWR);
}
void bc_kvm_transport_close(bc_kvm_transport *transport) {
    if (!transport) return;
    if (transport->ssl) SSL_shutdown(transport->ssl);
    free_tls(transport);
    close_socket(transport->socket);
    transport->socket = INVALID_SOCKET;
    transport->handshake_done = 0;
}
void bc_kvm_transport_destroy(bc_kvm_transport *transport) {
    if (!transport) return;
    bc_kvm_transport_close(transport);
    free(transport->message);
    free(transport->fragments);
    free(transport->raw);
    free(transport);
}

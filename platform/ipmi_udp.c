#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "bcontrol/ipmi_platform.h"
#include "resolver.h"
#include "../core/log_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET udp_socket;
#define UDP_INVALID INVALID_SOCKET
#define UDP_CONNECT(fd, address, length) connect(fd, address, (int)(length))
#else
#include <errno.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int udp_socket;
#define UDP_INVALID (-1)
#define UDP_CONNECT(fd, address, length) connect(fd, address, (socklen_t)(length))
#endif

typedef struct {
    bc_ipmi_io api;
    udp_socket socket;
} udp_transport;

static int socket_valid(udp_socket socket) { return socket != UDP_INVALID; }

static void socket_close(udp_socket socket) {
    if (!socket_valid(socket)) return;
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

static bc_status udp_send(void *userdata, const uint8_t *data, uint32_t length) {
    udp_transport *udp = userdata;
    if (!data || !length) return BC_INVALID_ARGUMENT;
#ifdef _WIN32
    int sent = send(udp->socket, (const char *)data, (int)length, 0);
    if (sent != (int)length) BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.udp_send", "len=%u status=io_error", length);
    return sent == (int)length ? BC_OK : BC_IO_ERROR;
#else
    ssize_t written;
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    do written = send(udp->socket, data, length, flags); while (written < 0 && errno == EINTR);
    if (written != (ssize_t)length) BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.udp_send", "len=%u status=io_error errno=%d",
        length, errno);
    return written == (ssize_t)length ? BC_OK : BC_IO_ERROR;
#endif
}

static bc_status udp_receive(void *userdata, uint8_t *buffer, uint32_t capacity, uint32_t *length, uint32_t timeout_ms) {
    udp_transport *udp = userdata;
    if (!buffer || !capacity || !length) return BC_INVALID_ARGUMENT;
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(udp->socket, &readable);
    struct timeval timeout = {(time_t)(timeout_ms / 1000), (long)((timeout_ms % 1000) * 1000)};
#ifdef _WIN32
    int ready = select(0, &readable, NULL, NULL, &timeout);
#else
    int ready = select(udp->socket + 1, &readable, NULL, NULL, &timeout);
#endif
    if (ready == 0) return BC_TIMEOUT;
#ifndef _WIN32
    if (ready < 0 && errno == EINTR) return BC_TIMEOUT;
#endif
    if (ready < 0) {
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.udp_receive", "status=io_error stage=select");
        return BC_IO_ERROR;
    }
    int received = (int)recv(udp->socket, (char *)buffer, (int)(capacity > 0x7fffffffu ? 0x7fffffffu : capacity), 0);
    if (received < 0) {
        BC_LOG_WARN(BC_LOG_CATEGORY_IPMI, "ipmi.udp_receive", "status=io_error stage=recv");
        return BC_IO_ERROR;
    }
    *length = (uint32_t)received;
    BC_LOG_TRACE(BC_LOG_CATEGORY_IPMI, "ipmi.udp_receive", "len=%u", *length);
    return BC_OK;
}

bc_status bc_ipmi_udp_create_timeout(bc_string host, uint16_t port, uint32_t timeout_ms, bc_ipmi_io **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!host.data || !host.length || host.length > 253 || !port || !timeout_ms || memchr(host.data, 0, (size_t)host.length)) return BC_INVALID_ARGUMENT;
    char name[256];
    memcpy(name, host.data, (size_t)host.length);
    name[host.length] = 0;
    char service[8];
    snprintf(service, sizeof(service), "%u", (unsigned)port);
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return BC_IO_ERROR;
#endif
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *addresses = NULL;
    bc_status resolved = bc_net_resolve(name, service, &hints, timeout_ms, &addresses);
    if (resolved != BC_OK) {
#ifdef _WIN32
        WSACleanup();
#endif
        BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.udp_create", "status=io_error stage=resolve host_len=%" PRIu64 " port=%u",
            host.length, port);
        return resolved;
    }
    udp_socket handle = UDP_INVALID;
    for (const struct addrinfo *address = addresses; address; address = address->ai_next) {
        handle = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
#ifdef SO_NOSIGPIPE
        int enabled = 1;
        if (socket_valid(handle) && setsockopt(handle, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled))) {
            socket_close(handle);
            handle = UDP_INVALID;
            continue;
        }
#endif
        if (socket_valid(handle) && UDP_CONNECT(handle, address->ai_addr, address->ai_addrlen) == 0) break;
        socket_close(handle);
        handle = UDP_INVALID;
    }
    freeaddrinfo(addresses);
    if (!socket_valid(handle)) {
#ifdef _WIN32
        WSACleanup();
#endif
        BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.udp_create", "status=io_error stage=connect host_len=%" PRIu64 " port=%u",
            host.length, port);
        return BC_IO_ERROR;
    }
    udp_transport *udp = calloc(1, sizeof(*udp));
    if (!udp) {
        socket_close(handle);
#ifdef _WIN32
        WSACleanup();
#endif
        return BC_NO_MEMORY;
    }
    udp->socket = handle;
    udp->api = (bc_ipmi_io){sizeof(bc_ipmi_io), BC_ABI_VERSION, udp, udp_send, udp_receive};
    *out = &udp->api;
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.udp_create", "status=ok host_len=%" PRIu64 " port=%u", host.length, port);
    return BC_OK;
}

void bc_ipmi_udp_destroy(bc_ipmi_io *io) {
    if (!io) return;
    udp_transport *udp = io->userdata;
    BC_LOG_INFO(BC_LOG_CATEGORY_IPMI, "ipmi.udp_destroy", "status=ok");
    socket_close(udp->socket);
#ifdef _WIN32
    WSACleanup();
#endif
    free(udp);
}

bc_status bc_ipmi_udp_create(bc_string host, uint16_t port, bc_ipmi_io **out) {
    return bc_ipmi_udp_create_timeout(host, port, 5000, out);
}

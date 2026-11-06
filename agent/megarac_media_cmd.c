#define _POSIX_C_SOURCE 200809L
#include "megarac_cmd.h"
#include "megarac.h"
#include "server.h"
#include "bcontrol/kvm_transport.h"
#include "bcontrol/wire.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t stopped;
static void stop(int number) { (void)number; stopped = 1; }
static bc_string text(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
static bc_status source_read(void *userdata, uint64_t offset, uint32_t length, uint8_t *out) {
    FILE *file = userdata;
#ifdef _WIN32
    if (offset > INT64_MAX || _fseeki64(file, (int64_t)offset, SEEK_SET)) return BC_IO_ERROR;
#else
    if ((uint64_t)(off_t)offset != offset || fseeko(file, (off_t)offset, SEEK_SET)) return BC_IO_ERROR;
#endif
    return fread(out, 1, length, file) == length ? BC_OK : BC_IO_ERROR;
}
static bc_status open_tunnel(bc_kvm_transport *transport, const bc_megarac_kvm_info *info) {
    uint8_t data[1024]; uint32_t length = 0;
    bc_status status = bc_megarac_tunnel_request(info, BC_MEGARAC_TUNNEL_CD, data, sizeof(data), &length);
    if (status == BC_OK) status = bc_kvm_transport_send(transport, data, length);
    memset(data, 0, sizeof(data));
    uint64_t deadline = bc_agent_now_ms() + 5000;
    length = 0;
    while (status == BC_OK && length < 255 && bc_agent_now_ms() < deadline) {
        uint32_t count = 0, consumed = 0;
        status = bc_kvm_transport_recv(transport, data + length, 1, &count, 200);
        if (status == BC_TIMEOUT) { status = BC_OK; continue; }
        if (status != BC_OK) return status;
        if (!count) return BC_PROTOCOL_ERROR;
        length += count;
        status = bc_megarac_tunnel_response(data, length, &consumed);
        if (status == BC_OK) return BC_OK;
        if (status == BC_BUSY) status = BC_OK;
    }
    return status != BC_OK ? status : length == 255 ? BC_LIMIT_EXCEEDED : BC_TIMEOUT;
}
static bc_status media_send(void *user, const uint8_t *data, uint32_t length) {
    return bc_kvm_transport_send(user, data, length);
}
static bc_status media_recv(void *user, uint8_t *data, uint32_t capacity, uint32_t *received, uint32_t timeout) {
    return bc_kvm_transport_recv(user, data, capacity, received, timeout);
}
static uint64_t media_clock(void *user) { (void)user; return bc_agent_now_ms(); }
static int number(const char *s, uint32_t *out) {
    char *end = NULL; errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || !*s || *s == '-' || *end || n > UINT32_MAX) return 0;
    *out = (uint32_t)n; return 1;
}
int bc_agent_megarac_media(int argc, char **argv) {
    const char *url = NULL, *path = NULL, *ca = NULL, *token = getenv("BC_KVM_TOKEN");
    const char *tunnel_host = NULL, *cookie = getenv("BC_WEB_COOKIE");
    uint32_t seconds = 30, instance = 0, policy = BC_CERT_STRICT, header_count = 0;
    bc_string headers[8];
    for (int i = 1; i < argc; ++i) {
        if (i + 1 >= argc) goto usage;
        const char *key = argv[i], *value = argv[++i];
        if (!strcmp(key, "--url")) url = value;
        else if (!strcmp(key, "--single-port-host")) tunnel_host = value;
        else if (!strcmp(key, "--file")) path = value;
        else if (!strcmp(key, "--ca")) ca = value;
        else if (!strcmp(key, "--header")) { if (header_count == 8) goto usage; headers[header_count++] = text(value); }
        else if (!strcmp(key, "--cert-policy")) {
            if (!strcmp(value, "skip-all")) policy = BC_CERT_SKIP_ALL;
            else if (!strcmp(value, "skip-chain")) policy = BC_CERT_SKIP_CHAIN;
            else if (strcmp(value, "strict")) goto usage;
        }
        else if (!strcmp(key, "--seconds")) { if (!number(value, &seconds) || !seconds || seconds > 3600) goto usage; }
        else if (!strcmp(key, "--instance")) { if (!number(value, &instance) || instance > 255) goto usage; }
        else goto usage;
    }
    if (!url || !path || !token || !*token || (strncmp(url, "tcp://", 6) && strncmp(url, "tls://", 6) && strncmp(url, "wss://", 6))) goto usage;
    bc_megarac_kvm_info tunnel = {0};
    if (tunnel_host) {
        const char *port = strrchr(url, ':');
        if (!cookie || !*cookie || strlen(cookie) >= sizeof(tunnel.cookie) ||
            strlen(tunnel_host) >= sizeof(tunnel.host) || !port || !number(port + 1, &tunnel.port) ||
            !tunnel.port || tunnel.port > 65535 || !strncmp(url, "wss://", 6)) goto usage;
        tunnel.struct_size = sizeof(tunnel); tunnel.single_port = 1;
        tunnel.secure = !strncmp(url, "tls://", 6);
        strcpy(tunnel.host, tunnel_host); strcpy(tunnel.cookie, cookie);
        char expected[256];
        snprintf(expected, sizeof(expected), "%s://%s%s%s:%u", tunnel.secure ? "tls" : "tcp",
            strchr(tunnel_host, ':') ? "[" : "", tunnel_host, strchr(tunnel_host, ':') ? "]" : "", tunnel.port);
        if (strcmp(url, expected)) goto usage;
    }
    FILE *file = fopen(path, "rb");
    bc_status status = file ? BC_OK : BC_IO_ERROR;
    uint64_t size = 0;
    if (file) {
#ifdef _WIN32
        if (_fseeki64(file, 0, SEEK_END) || _ftelli64(file) < 0) status = BC_IO_ERROR;
        else size = (uint64_t)_ftelli64(file);
#else
        if (fseeko(file, 0, SEEK_END) || ftello(file) < 0) status = BC_IO_ERROR;
        else size = (uint64_t)ftello(file);
#endif
        if (status == BC_OK && (!size || size % 2048)) status = BC_INVALID_ARGUMENT;
    }
    bc_kvm_transport *transport = NULL;
    bc_kvm_transport_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.headers = headers; options.header_count = header_count; options.cert_policy = policy;
    if (!strncmp(url, "wss://", 6)) options.subprotocols = text("binary");
    options.url = text(url); options.ca_file = text(ca); options.timeout_ms = 1000;
    if (status == BC_OK) status = bc_kvm_transport_connect(&options, &transport);
    if (status == BC_OK && tunnel_host) status = open_tunnel(transport, &tunnel);
    memset(&tunnel, 0, sizeof(tunnel));
    bc_megarac_cd_source source = {sizeof(source), file, size, source_read};
    bc_megarac_media_service_options media_options = {sizeof(media_options), BC_ABI_VERSION,
        &source, text(token), (tunnel_host ? BC_MEGARAC_MEDIA_TUNNEL_PREFIX : 0) |
        (tunnel_host || !strncmp(url, "wss://", 6) ? BC_MEGARAC_MEDIA_SEND_DISCONNECT : 0), instance, 5000};
    bc_megarac_media_io io = {transport, media_send, media_recv, media_clock};
    bc_megarac_media_service *media = NULL;
    if (status == BC_OK) status = bc_megarac_media_service_create(&media_options, &io, &media);
    if (status == BC_OK) status = bc_megarac_media_service_start(media);
    signal(SIGINT, stop); signal(SIGTERM, stop);
    uint64_t deadline = bc_agent_now_ms() + (uint64_t)seconds * 1000;
    bc_megarac_media_service_info info = {0};
    while (status == BC_OK && !stopped && bc_agent_now_ms() < deadline) {
        status = bc_megarac_media_service_poll(media, 200);
        bc_megarac_media_service_info_get(media, &info);
        if (status == BC_TIMEOUT && info.state != BC_MEGARAC_STATE_ERROR) status = BC_OK;
    }
    if (status == BC_OK && !(info.flags & BC_MEGARAC_MEDIA_AUTHENTICATED)) status = BC_TIMEOUT;
    if (stopped && status == BC_OK) status = BC_CANCELLED;
    if (media) {
        bc_status closed = bc_megarac_media_service_close(media);
        if (status == BC_OK && closed != BC_OK) status = closed;
        bc_megarac_media_service_destroy(media);
    }
    if (transport) { bc_kvm_transport_close(transport); bc_kvm_transport_destroy(transport); }
    if (file) fclose(file);
    printf("{\"status\":\"%s\",\"authenticated\":%s,\"requests\":%llu,\"bytes\":%llu,\"transport_closed\":true}\n",
        bc_status_string(status), info.flags & BC_MEGARAC_MEDIA_AUTHENTICATED ? "true" : "false",
        (unsigned long long)info.requests, (unsigned long long)info.bytes);
    return status == BC_OK ? 0 : 1;
usage:
    fputs("bcontrol-agent megarac-media --url tcp://host:5120 --file image.iso [--instance 0] [--seconds 30] [--ca file]\n"
          "Uses BC_KVM_TOKEN; --single-port-host HOST uses BC_WEB_COOKIE for CDMEDIA. Also accepts wss:// with --header and --cert-policy.\n"
          "Read-only CD session; remote removal requires device confirmation.\n", stderr);
    return 2;
}

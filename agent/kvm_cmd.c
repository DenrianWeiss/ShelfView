#include "kvm_cmd.h"
#include "bcontrol/bcontrol.h"
#include "bcontrol/kvm.h"
#include "bcontrol/kvm_transport.h"
#include "yyjson.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t interrupted;
static void stop_signal(int number) { (void)number; interrupted = 1; }
static bc_string text(const char *value) { return (bc_string){value, value ? strlen(value) : 0}; }
static int parse_u32(const char *value, uint32_t *out) {
    char *end = NULL;
    errno = 0;
    unsigned long n = strtoul(value, &end, 10);
    if (errno || !*value || *value == '-' || *end || n > UINT32_MAX) return 0;
    *out = (uint32_t)n;
    return 1;
}
static int write_ppm(const char *path, const bc_kvm_frame *frame) {
    FILE *file = fopen(path, "wb");
    if (!file) return 0;
    int ok = fprintf(file, "P6\n%u %u\n255\n", frame->width, frame->height) > 0;
    for (uint32_t y = 0; ok && y < frame->height; ++y) {
        const uint8_t *row = frame->pixels + (size_t)y * frame->stride;
        for (uint32_t x = 0; ok && x < frame->width; ++x) {
            uint8_t rgb[3] = {row[x * 4], row[x * 4 + 1], row[x * 4 + 2]};
            ok = fwrite(rgb, 1, sizeof(rgb), file) == sizeof(rgb);
        }
    }
    fclose(file);
    return ok;
}
static void usage(void) {
    fputs("bcontrol-agent kvm --url URL [--ca FILE] [--cert-policy strict|skip-chain|skip-all]\n"
          "  [--tls-min 1.0|1.1|1.2|1.3] [--tls-max VERSION] [--timeout-ms n] [--seconds n]\n"
          "  [--header 'Name: Value']... [--deflate] [--out FILE.ppm]\n"
          "URL: tcp://, tls://, ws:// or wss://; raw defaults to port 5900.\n"
          "Credentials: BC_BMC_USERNAME and BC_BMC_PASSWORD (Basic, WebSocket only).\n", stderr);
}
int bc_agent_kvm(int argc, char **argv) {
    const char *url = NULL, *ca = NULL, *out_path = NULL;
    bc_string headers[8];
    uint32_t header_count = 0, cert_policy = BC_CERT_STRICT, tls_min = BC_TLS_DEFAULT, tls_max = BC_TLS_DEFAULT;
    uint32_t timeout_ms = 5000, seconds = 10, flags = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--deflate")) { flags |= BC_KVM_TRANSPORT_DEFLATE; continue; }
        if (i + 1 >= argc) { usage(); return 2; }
        const char *option = argv[i], *value = argv[++i];
        if (!strcmp(option, "--url")) url = value;
        else if (!strcmp(option, "--ca")) ca = value;
        else if (!strcmp(option, "--out")) out_path = value;
        else if (!strcmp(option, "--header")) {
            if (header_count >= 8 || strlen(value) > 2048) { usage(); return 2; }
            headers[header_count++] = text(value);
        } else if (!strcmp(option, "--cert-policy")) {
            if (!strcmp(value, "skip-chain")) cert_policy = BC_CERT_SKIP_CHAIN;
            else if (!strcmp(value, "skip-all")) cert_policy = BC_CERT_SKIP_ALL;
            else if (strcmp(value, "strict")) { usage(); return 2; }
        } else if (!strcmp(option, "--tls-min") || !strcmp(option, "--tls-max")) {
            uint32_t version;
            if (!strcmp(value, "1.0")) version = BC_TLS_1_0;
            else if (!strcmp(value, "1.1")) version = BC_TLS_1_1;
            else if (!strcmp(value, "1.2")) version = BC_TLS_1_2;
            else if (!strcmp(value, "1.3")) version = BC_TLS_1_3;
            else { usage(); return 2; }
            if (!strcmp(option, "--tls-min")) tls_min = version; else tls_max = version;
        } else if (!strcmp(option, "--timeout-ms")) { if (!parse_u32(value, &timeout_ms)) { usage(); return 2; } }
        else if (!strcmp(option, "--seconds")) { if (!parse_u32(value, &seconds)) { usage(); return 2; } }
        else { usage(); return 2; }
    }
    if (!url) { usage(); return 2; }
    signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal);
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return 2;
    yyjson_mut_val *root = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, root);
    bc_kvm_transport_options transport_options = {0};
    transport_options.struct_size = sizeof(transport_options); transport_options.abi_version = BC_ABI_VERSION;
    transport_options.url = text(url); transport_options.ca_file = text(ca);
    transport_options.username = text(getenv("BC_BMC_USERNAME")); transport_options.password = text(getenv("BC_BMC_PASSWORD"));
    transport_options.headers = headers; transport_options.header_count = header_count;
    transport_options.cert_policy = cert_policy; transport_options.tls_min = tls_min; transport_options.tls_max = tls_max;
    transport_options.timeout_ms = timeout_ms;
    transport_options.flags = flags;
    bc_kvm_transport *transport = NULL;
    bc_status status = bc_kvm_transport_connect(&transport_options, &transport);
    bc_kvm *kvm = NULL;
    uint32_t frames = 0;
    if (status == BC_OK) {
        bc_kvm_options options = {.struct_size = sizeof(options), .abi_version = BC_ABI_VERSION};
        status = bc_kvm_create(&options, &kvm);
    }
    uint8_t input[65536], output[65536];
    uint64_t deadline = (uint64_t)time(NULL) + seconds;
    while (status == BC_OK && !interrupted && (uint64_t)time(NULL) <= deadline) {
        uint32_t received = 0;
        status = bc_kvm_transport_recv(transport, input, sizeof(input), &received, 250);
        if (status == BC_TIMEOUT) { status = BC_OK; }
        else if (status != BC_OK) break;
        if (received) {
            status = bc_kvm_feed(kvm, input, received);
            if (status != BC_OK) break;
        }
        for (;;) {
            uint32_t written = 0;
            bc_status drain = bc_kvm_output(kvm, output, sizeof(output), &written);
            if (drain != BC_OK || !written) break;
            status = bc_kvm_transport_send(transport, output, written);
            if (status != BC_OK) break;
        }
        const bc_kvm_frame *frame = bc_kvm_frame_get(kvm);
        if (frame && (frame->flags & BC_KVM_FRAME_READY)) {
            ++frames;
            if (out_path && !write_ppm(out_path, frame)) status = BC_IO_ERROR;
            yyjson_mut_obj_add_uint(doc, root, "width", frame->width);
            yyjson_mut_obj_add_uint(doc, root, "height", frame->height);
            yyjson_mut_obj_add_strncpy(doc, root, "name", frame->name.data ? frame->name.data : "", (size_t)frame->name.length);
            bc_kvm_ack_frame(kvm);
            break;
        }
    }
    yyjson_mut_obj_add_str(doc, root, "status", bc_status_string(status));
    yyjson_mut_obj_add_uint(doc, root, "transport", bc_kvm_transport_kind(transport));
    yyjson_mut_obj_add_uint(doc, root, "frames", frames);
    if (out_path) yyjson_mut_obj_add_str(doc, root, "output", out_path);
    char *json = yyjson_mut_write(doc, 0, NULL);
    if (json) { puts(json); free(json); }
    yyjson_mut_doc_free(doc);
    if (transport) bc_kvm_transport_close(transport);
    bc_kvm_destroy(kvm);
    bc_kvm_transport_destroy(transport);
    return status == BC_OK && frames ? 0 : 1;
}

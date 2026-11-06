#define _POSIX_C_SOURCE 200809L
#include "media_map.h"
#include "media_pull.h"
#include "bcontrol/bcontrol.h"
#include "bcontrol/redfish.h"
#include "bcontrol/redfish_auth.h"
#include "bcontrol/transport.h"
#include "yyjson.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <time.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

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
static void usage(void) {
    fputs("bcontrol-agent media-map --endpoint https://BMC --media-uri PATH (--file IMAGE | --image-url URL) "
          "[--transfer-method METHOD] [--transfer-protocol PROTOCOL] "
          "--listen ADDR:PORT --advertise http://HOST:PORT\n"
          "  [--auth basic|auto|session] [--ca FILE] [--cert-policy strict|skip-chain|skip-all]\n"
          "  [--tls-min VERSION] [--tls-max VERSION] [--timeout-ms n] [--serve-ms n] [--write-protected]\n"
          "Credentials: BC_BMC_USERNAME and BC_BMC_PASSWORD environment variables.\n", stderr);
}
static void emit(yyjson_mut_doc *doc, int exit_code) {
    char *json = yyjson_mut_write(doc, 0, NULL);
    if (json) { puts(json); free(json); }
    yyjson_mut_doc_free(doc);
    exit(exit_code);
}
static void auth_completed(bc_redfish_auth_operation *operation, const bc_redfish_auth_result *result, void *userdata) {
    (void)operation; (void)result; (void)userdata;
}
static void media_completed(bc_redfish_operation *operation, const bc_redfish_result *result, void *userdata) {
    (void)operation; (void)result; (void)userdata;
}
static void sleep_ms(uint32_t ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec delay = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
#endif
}
int bc_agent_media_map(int argc, char **argv) {
    const char *endpoint = NULL, *media_uri = NULL, *file_path = NULL, *image_url = NULL, *listen = NULL, *advertise = NULL, *ca = NULL;
    const char *transfer_method = NULL, *transfer_protocol = NULL;
    uint32_t auth_mode = BC_REDFISH_LOGIN_AUTO, cert_policy = BC_CERT_STRICT, tls_min = BC_TLS_DEFAULT, tls_max = BC_TLS_DEFAULT;
    uint32_t timeout_ms = 5000, serve_ms = 0, write_protected = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--write-protected")) { write_protected = 1; continue; }
        if (i + 1 >= argc) { usage(); return 2; }
        const char *option = argv[i], *value = argv[++i];
        if (!strcmp(option, "--endpoint")) endpoint = value;
        else if (!strcmp(option, "--media-uri")) media_uri = value;
        else if (!strcmp(option, "--file")) file_path = value;
        else if (!strcmp(option, "--image-url")) image_url = value;
        else if (!strcmp(option, "--transfer-method")) transfer_method = value;
        else if (!strcmp(option, "--transfer-protocol")) transfer_protocol = value;
        else if (!strcmp(option, "--listen")) listen = value;
        else if (!strcmp(option, "--advertise")) advertise = value;
        else if (!strcmp(option, "--ca")) ca = value;
        else if (!strcmp(option, "--auth")) {
            if (!strcmp(value, "basic")) auth_mode = BC_REDFISH_LOGIN_BASIC;
            else if (!strcmp(value, "session")) auth_mode = BC_REDFISH_LOGIN_SESSION;
            else if (strcmp(value, "auto")) { usage(); return 2; }
        } else if (!strcmp(option, "--cert-policy")) {
            if (!strcmp(value, "skip-chain")) cert_policy = BC_CERT_SKIP_CHAIN;
            else if (!strcmp(value, "skip-all")) cert_policy = BC_CERT_SKIP_ALL;
            else if (strcmp(value, "strict")) { usage(); return 2; }
        } else if (!strcmp(option, "--tls-min") || !strcmp(option, "--tls-max")) {
            uint32_t version;
            if (!strcmp(value, "1.0")) version = BC_TLS_1_0;
            else if (!strcmp(value, "1.2")) version = BC_TLS_1_2;
            else if (!strcmp(value, "1.3")) version = BC_TLS_1_3;
            else if (strcmp(value, "1.1")) { usage(); return 2; } else version = BC_TLS_1_1;
            if (!strcmp(option, "--tls-min")) tls_min = version; else tls_max = version;
        } else if (!strcmp(option, "--timeout-ms")) { if (!parse_u32(value, &timeout_ms)) { usage(); return 2; } }
        else if (!strcmp(option, "--serve-ms")) { if (!parse_u32(value, &serve_ms)) { usage(); return 2; } }
        else { usage(); return 2; }
    }
    int direct = image_url && *image_url;
    if (!endpoint || !media_uri || direct == (file_path != NULL)) { usage(); return 2; }
    if (!direct && (!listen || !advertise || strncmp(advertise, "http://", 7))) { usage(); return 2; }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return 2;
    yyjson_mut_val *out = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, out);
    bc_media_pull *pull = NULL;
    char token[65] = {0}, url[1024] = {0};
    uint64_t file_size = 0;
    if (direct) {
        if (strlen(image_url) >= sizeof(url)) { yyjson_mut_obj_add_strcpy(doc, out, "status", "invalid_argument"); emit(doc, 1); }
        strcpy(url, image_url);
    } else if (!(pull = bc_media_pull_create(listen, advertise)) ||
               !bc_media_pull_add(pull, file_path, token, url, sizeof(url), &file_size)) {
        yyjson_mut_obj_add_strcpy(doc, out, "status", "media_source_failed");
        if (pull) bc_media_pull_destroy(pull);
        emit(doc, 1);
    }
    yyjson_mut_obj_add_strcpy(doc, out, "url", url);
    bc_transport *transport = NULL;
    bc_context *context = NULL;
    bc_endpoint *base = NULL, *endpoint_used = NULL;
    bc_redfish_connection *connection = NULL;
    bc_redfish_auth_operation *login = NULL;
    bc_redfish_operation *media = NULL;
    bc_status status = bc_curl_transport_create(&transport);
    bc_context_options context_options = {sizeof(context_options), BC_ABI_VERSION, transport, 1024u * 1024u, 4, 0};
    if (status == BC_OK) status = bc_context_create(&context_options, &context);
    bc_endpoint_options endpoint_options = {0};
    endpoint_options.struct_size = sizeof(endpoint_options); endpoint_options.abi_version = BC_ABI_VERSION;
    endpoint_options.device_id = text("media-map"); endpoint_options.endpoint_id = text("redfish");
    endpoint_options.origin = text(endpoint); endpoint_options.ca_file = text(ca);
    endpoint_options.username = text(getenv("BC_BMC_USERNAME")); endpoint_options.password = text(getenv("BC_BMC_PASSWORD"));
    endpoint_options.cert_policy = cert_policy; endpoint_options.tls_min = tls_min; endpoint_options.tls_max = tls_max;
    if (status == BC_OK) status = bc_endpoint_create(context, &endpoint_options, &base);
    if (status == BC_OK && auth_mode != BC_REDFISH_LOGIN_BASIC) {
        bc_redfish_login_options login_options = {sizeof(login_options), BC_ABI_VERSION, auth_mode, timeout_ms,
            endpoint_options.username, endpoint_options.password};
        status = bc_redfish_login(base, &login_options, auth_completed, NULL, &login);
        while (status == BC_OK && login && !bc_redfish_auth_result_get(login)) status = bc_context_poll(context, 50);
        const bc_redfish_auth_result *result = bc_redfish_auth_result_get(login);
        if (status == BC_OK && result) {
            status = result->status;
            if (status == BC_OK) { connection = result->connection; bc_redfish_connection_retain(connection); }
        }
    }
    endpoint_used = connection ? bc_redfish_connection_endpoint(connection) : base;
    if (status == BC_OK) {
        bc_redfish_virtual_media_insert_options insert = {0};
        insert.struct_size = sizeof(insert);
        insert.image = text(url);
        if (transfer_method) insert.transfer_method = text(transfer_method);
        if (transfer_protocol) insert.transfer_protocol_type = text(transfer_protocol);
        insert.flags = write_protected ? BC_REDFISH_VM_WRITE_PROTECTED_SET : 0;
        insert.write_protected = write_protected;
        bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, timeout_ms, 0};
        status = bc_redfish_virtual_media_insert(endpoint_used, text(media_uri), &insert, &options, media_completed, NULL, &media);
        while (status == BC_OK && media && !bc_redfish_result_get(media)) status = bc_context_poll(context, 50);
    }
    const bc_redfish_result *result = media ? bc_redfish_result_get(media) : NULL;
    if (status == BC_OK && result) {
        yyjson_mut_obj_add_uint(doc, out, "http_status", result->http_status);
        yyjson_mut_obj_add_uint(doc, out, "flags", result->flags);
        status = result->status;
    }
    yyjson_mut_obj_add_strcpy(doc, out, "status", bc_status_string(status));
    if (file_path) yyjson_mut_obj_add_uint(doc, out, "file_size", file_size);
    if (status != BC_OK) { if (pull) bc_media_pull_destroy(pull); }
    int exit_code = status == BC_OK ? 0 : 1;
    if (status == BC_OK && direct) {
        if (serve_ms) {
            signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal);
            uint32_t elapsed = 0;
            while (!interrupted && elapsed < serve_ms) { sleep_ms(100); elapsed += 100; }
            bc_redfish_operation *eject = NULL;
            bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, timeout_ms, 0};
            bc_status eject_status = bc_redfish_virtual_media_eject(endpoint_used, text(media_uri), &options, media_completed, NULL, &eject);
            while (eject_status == BC_OK && eject && !bc_redfish_result_get(eject)) eject_status = bc_context_poll(context, 50);
            yyjson_mut_obj_add_strcpy(doc, out, "eject", bc_status_string(eject_status));
            bc_redfish_release(eject);
        }
    } else if (status == BC_OK) {
        signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal);
        uint32_t elapsed = 0;
        while (!interrupted && (!serve_ms || elapsed < serve_ms)) { sleep_ms(100); elapsed += 100; }
        bc_redfish_operation *eject = NULL;
        bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, timeout_ms, 0};
        bc_status eject_status = bc_redfish_virtual_media_eject(endpoint_used, text(media_uri), &options, media_completed, NULL, &eject);
        while (eject_status == BC_OK && eject && !bc_redfish_result_get(eject)) eject_status = bc_context_poll(context, 50);
        yyjson_mut_obj_add_strcpy(doc, out, "eject", bc_status_string(eject_status));
        bc_redfish_release(eject);
        if (pull) bc_media_pull_destroy(pull);
    }
    if (media) bc_redfish_release(media);
    if (login) bc_redfish_auth_release(login);
    if (connection) bc_redfish_connection_release(connection);
    if (base) bc_endpoint_release(base);
    if (context) { bc_context_shutdown(context); bc_context_poll(context, 0); bc_context_destroy(context); }
    if (transport) bc_curl_transport_destroy(transport);
    emit(doc, exit_code);
    return exit_code;
}

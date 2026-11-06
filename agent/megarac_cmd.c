#include "megarac_cmd.h"
#include "server.h"
#include "megarac.h"
#include "bcontrol/zte.h"
#include "bcontrol/bcontrol.h"
#include "bcontrol/kvm_transport.h"
#include "bcontrol/transport.h"
#include "yyjson.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FRAME_CAPACITY (16u * 1024u * 1024u)
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
static int endpoint_parts(const char *url, char *scheme, size_t scheme_size, char *host, size_t host_size, uint16_t *port) {
    const char *rest;
    if (!strncmp(url, "https://", 8)) { snprintf(scheme, scheme_size, "https"); rest = url + 8; *port = 443; }
    else if (!strncmp(url, "http://", 7)) { snprintf(scheme, scheme_size, "http"); rest = url + 7; *port = 80; }
    else return 0;
    const char *slash = strchr(rest, '/');
    size_t length = slash ? (size_t)(slash - rest) : strlen(rest);
    const char *colon = memchr(rest, ':', length);
    size_t host_length = colon ? (size_t)(colon - rest) : length;
    if (!host_length || host_length >= host_size) return 0;
    memcpy(host, rest, host_length); host[host_length] = 0;
    if (colon) {
        char number[8]; size_t n = length - host_length - 1;
        if (!n || n >= sizeof(number)) return 0;
        memcpy(number, colon + 1, n); number[n] = 0;
        char *end = NULL;
        unsigned long value = strtoul(number, &end, 10);
        if (!*number || *end || !value || value > 65535) return 0;
        *port = (uint16_t)value;
    }
    return 1;
}
static void probe_completed(bc_megarac_probe *probe, const bc_megarac_probe_result *result, void *userdata) {
    (void)probe; (void)result; (void)userdata;
}
static void read_completed(bc_request *request, const bc_response *response, void *user) {
    (void)request; (void)response; *(int *)user = 1;
}
static bc_status read_resource(bc_context *context, bc_endpoint *endpoint, const char *path,
    uint32_t timeout, bc_request **out) {
    int done = 0;
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.method = BC_HTTP_GET; options.path = text(path); options.timeout_ms = timeout;
    bc_status status = bc_http_submit(endpoint, &options, read_completed, &done, out);
    while (status == BC_OK && !done) status = bc_context_poll(context, 20);
    const bc_response *r = bc_request_response(*out);
    if (status == BC_OK) status = r ? r->status : BC_PROTOCOL_ERROR;
    if (status == BC_OK && r->http_status != 200)
        status = r->http_status == 401 || r->http_status == 403 ? BC_AUTHENTICATION_FAILED : BC_HTTP_ERROR;
    return status;
}
static bc_status zte_probe(bc_context *context, bc_endpoint *endpoint,
    const bc_megarac_probe_options *options, bc_megarac_probe **out, int *matched) {
    bc_request *root = NULL, *managers = NULL, *service = NULL;
    bc_endpoint *authenticated = NULL;
    bc_status status = read_resource(context, endpoint, "/redfish/v1/", options->timeout_ms, &root);
    const bc_response *r = bc_request_response(root);
    *matched = status == BC_OK && r->body.length <= UINT32_MAX &&
        bc_zte_service_root_matches(r->body.data, (uint32_t)r->body.length);
    if (!*matched) { bc_request_release(root); return BC_UNSUPPORTED; }
    yyjson_doc *doc = yyjson_read((const char *)r->body.data, (size_t)r->body.length, 0);
    const char *path = doc ? yyjson_get_str(yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(doc), "Managers"), "@odata.id")) : NULL;
    bc_auth_options auth = {0}; auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION;
    auth.mode = BC_AUTH_BASIC; auth.username = options->username; auth.password = options->password;
    status = path && !strcmp(path, "/redfish/v1/Managers") ?
        bc_endpoint_with_auth(endpoint, &auth, &authenticated) : BC_UNSUPPORTED;
    if (status == BC_OK) status = read_resource(context, authenticated, path, options->timeout_ms, &managers);
    if (doc) yyjson_doc_free(doc);
    r = bc_request_response(managers);
    doc = status == BC_OK ? yyjson_read((const char *)r->body.data, (size_t)r->body.length, 0) : NULL;
    yyjson_val *members = doc ? yyjson_obj_get(yyjson_doc_get_root(doc), "Members") : NULL;
    path = yyjson_arr_size(members) == 1 ? yyjson_get_str(yyjson_obj_get(yyjson_arr_get_first(members), "@odata.id")) : NULL;
    char target[1024];
    if (status == BC_OK) {
        if (!path || strncmp(path, "/redfish/v1/Managers/", 21) || !path[21] ||
            strpbrk(path + 21, "/?#%\\") || strlen(path) > sizeof(target) - 12) status = BC_UNSUPPORTED;
        else {
            snprintf(target, sizeof(target), "%s/KvmService", path);
            status = read_resource(context, authenticated, target, options->timeout_ms, &service);
        }
    }
    if (doc) yyjson_doc_free(doc);
    r = bc_request_response(service);
    if (status == BC_OK) status = r->body.length > UINT32_MAX ? BC_LIMIT_EXCEEDED :
        bc_zte_kvm_probe_start(endpoint, options, r->body.data, (uint32_t)r->body.length, probe_completed, NULL, out);
    bc_request_release(service); bc_request_release(managers); bc_request_release(root);
    bc_endpoint_release(authenticated);
    return status;
}
static bc_status http_cleanup(bc_megarac_probe *probe, bc_endpoint *endpoint, bc_context *context, bc_transport *transport) {
    bc_status status = BC_OK;
    const bc_megarac_probe_result *result = probe ? bc_megarac_probe_result_get(probe) : NULL;
    if (result && result->status == BC_OK) {
        status = bc_megarac_probe_logout(probe, probe_completed, NULL);
        while (status == BC_OK && !bc_megarac_probe_result_get(probe)) status = bc_context_poll(context, 50);
        result = bc_megarac_probe_result_get(probe);
        if (status == BC_OK && result) status = result->status;
    } else if (result && result->cleanup_status != BC_CANCELLED) status = result->cleanup_status;
    bc_megarac_probe_release(probe); bc_endpoint_release(endpoint);
    if (context) { bc_context_shutdown(context); bc_context_poll(context, 0); bc_context_destroy(context); }
    if (transport) bc_curl_transport_destroy(transport);
    return status;
}
static int write_ppm(const char *path, const uint8_t *rgba, uint32_t width, uint32_t height) {
    FILE *file = fopen(path, "wb");
    if (!file) return 0;
    int ok = fprintf(file, "P6\n%u %u\n255\n", width, height) > 0;
    for (uint32_t y = 0; ok && y < height; ++y)
        for (uint32_t x = 0; ok && x < width; ++x)
            ok = fwrite(rgba + ((size_t)y * width + x) * 4, 1, 3, file) == 3;
    fclose(file);
    return ok;
}
static int hid_usage(char value, uint8_t *modifiers) {
    if (value >= 'a' && value <= 'z') return 0x04 + value - 'a';
    if (value >= 'A' && value <= 'Z') { *modifiers |= 2; return 0x04 + value - 'A'; }
    if (value >= '1' && value <= '9') return 0x1e + value - '1';
    if (value == '0') return 0x27;
    switch (value) {
    case ' ': return 0x2c; case '\n': case '\r': return 0x28; case '\t': return 0x2b;
    case 0x1b: return 0x29; case 0x7f: case 0x08: return 0x2a;
    case '-': return 0x2d; case '=': return 0x2e; case '[': return 0x2f; case ']': return 0x30;
    case '\\': return 0x31; case ';': return 0x33; case '\'': return 0x34; case '`': return 0x35;
    case ',': return 0x36; case '.': return 0x37; case '/': return 0x38;
    case '_': *modifiers |= 2; return 0x2d; case '+': *modifiers |= 2; return 0x2e;
    case '{': *modifiers |= 2; return 0x2f; case '}': *modifiers |= 2; return 0x30;
    case '|': *modifiers |= 2; return 0x31; case ':': *modifiers |= 2; return 0x33;
    case '"': *modifiers |= 2; return 0x34; case '~': *modifiers |= 2; return 0x35;
    case '<': *modifiers |= 2; return 0x36; case '>': *modifiers |= 2; return 0x37;
    case '?': *modifiers |= 2; return 0x38;
    case '!': *modifiers |= 2; return 0x1e; case '@': *modifiers |= 2; return 0x1f;
    case '#': *modifiers |= 2; return 0x20; case '$': *modifiers |= 2; return 0x21;
    case '%': *modifiers |= 2; return 0x22; case '^': *modifiers |= 2; return 0x23;
    case '&': *modifiers |= 2; return 0x24; case '*': *modifiers |= 2; return 0x25;
    case '(': *modifiers |= 2; return 0x26; case ')': *modifiers |= 2; return 0x27;
    default: return 0;
    }
}
static bc_status flush_session(bc_megarac_session *session, bc_kvm_transport *transport) {
    uint8_t output[8192];
    for (;;) {
        uint32_t written = 0;
        bc_status status = bc_megarac_session_output(session, output, sizeof(output), &written);
        if (status != BC_OK || !written) return status;
        status = bc_kvm_transport_send(transport, output, written);
        if (status != BC_OK) return status;
    }
}
static void usage(void) {
    fputs("bcontrol-agent megarac-kvm (--url URL | --endpoint URL) --kind h5|jviewer|jviewer195 --token TOKEN\n"
          "  --client-ip IP --username USER [--password PASSWORD] [--server-ip IP] [--mac MAC]\n"
          "  [--cookie 'name=value'] [--header 'Name: Value']... [--deflate]\n"
          "  [--ca FILE] [--cert-policy ...] [--tls-min VERSION] [--tls-max VERSION]\n"
          "  [--timeout-ms n] [--seconds n] [--out FRAME.bin] [--ppm IMAGE.ppm]\n"
          "  [--key CHAR] [--mouse X,Y] [--frames n]\n"
          "Credentials may use BC_BMC_USERNAME, BC_BMC_PASSWORD and BC_KVM_TOKEN environment variables.\n"
          "With --endpoint, logs in automatically and logs out its HTTP session after KVM closes.\n"
          "Captures AST or legacy SoC frames; --ppm decodes supported formats.\n", stderr);
}
int bc_agent_megarac_kvm(int argc, char **argv) {
    const char *url = NULL, *endpoint = NULL, *kind_name = "h5", *token = getenv("BC_KVM_TOKEN"), *client_ip = NULL, *username = getenv("BC_BMC_USERNAME");
    const char *password = getenv("BC_BMC_PASSWORD"), *server_ip = NULL, *mac = "", *cookie = NULL, *ca = NULL, *out_path = NULL, *ppm_path = NULL;
    const char *key_text = NULL, *mouse_text = NULL;
    bc_string extra_headers[8];
    uint32_t extra_count = 0, cert_policy = BC_CERT_STRICT, tls_min = BC_TLS_DEFAULT, tls_max = BC_TLS_DEFAULT;
    uint32_t timeout_ms = 5000, seconds = 10, flags = 0, max_frames = 1;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--deflate")) { flags |= BC_KVM_TRANSPORT_DEFLATE; continue; }
        if (i + 1 >= argc) { usage(); return 2; }
        const char *option = argv[i], *value = argv[++i];
        if (!strcmp(option, "--url")) url = value;
        else if (!strcmp(option, "--endpoint")) endpoint = value;
        else if (!strcmp(option, "--password")) password = value;
        else if (!strcmp(option, "--kind")) kind_name = value;
        else if (!strcmp(option, "--token")) token = value;
        else if (!strcmp(option, "--client-ip")) client_ip = value;
        else if (!strcmp(option, "--username")) username = value;
        else if (!strcmp(option, "--server-ip")) server_ip = value;
        else if (!strcmp(option, "--mac")) mac = value;
        else if (!strcmp(option, "--cookie")) cookie = value;
        else if (!strcmp(option, "--header")) { if (extra_count >= 8 || strlen(value) > 2048) { usage(); return 2; } extra_headers[extra_count++] = text(value); }
        else if (!strcmp(option, "--ca")) ca = value;
        else if (!strcmp(option, "--out")) out_path = value;
        else if (!strcmp(option, "--ppm")) ppm_path = value;
        else if (!strcmp(option, "--key")) key_text = value;
        else if (!strcmp(option, "--mouse")) mouse_text = value;
        else if (!strcmp(option, "--cert-policy")) {
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
        else if (!strcmp(option, "--frames")) { if (!parse_u32(value, &max_frames) || !max_frames || max_frames > 300) { usage(); return 2; } }
        else { usage(); return 2; }
    }
    uint32_t kind = !strcmp(kind_name, "h5") ? BC_MEGARAC_KVM_H5VIEWER :
        !strcmp(kind_name, "jviewer") ? BC_MEGARAC_KVM_JVIEWER :
        !strcmp(kind_name, "jviewer195") ? BC_MEGARAC_KVM_JVIEWER_195 : 0;
    if (!kind) { usage(); return 2; }
    char derived_url[512], derived_cookie[4096] = {0}, derived_token[BC_MEGARAC_MAX_TOKEN] = {0};
    char derived_client[BC_MEGARAC_MAX_IP] = {0}, derived_server[BC_MEGARAC_MAX_IP] = {0};
    bc_transport *http_transport = NULL; bc_context *http_context = NULL; bc_endpoint *http_endpoint = NULL;
    bc_megarac_kvm_info discovered_info = {0};
    bc_megarac_probe *probe = NULL;
    bc_status probe_status = BC_OK;
    if (endpoint) {
        if (!username || !password) { usage(); return 2; }
        bc_status status = bc_curl_transport_create(&http_transport);
        bc_context_options context_options = {sizeof(context_options), BC_ABI_VERSION, http_transport, 4u * 1024u * 1024u, 4, 0};
        if (status == BC_OK) status = bc_context_create(&context_options, &http_context);
        bc_endpoint_options endpoint_options = {0};
        endpoint_options.struct_size = sizeof(endpoint_options); endpoint_options.abi_version = BC_ABI_VERSION;
        endpoint_options.device_id = text("megarac-probe"); endpoint_options.endpoint_id = text("kvm");
        endpoint_options.origin = text(endpoint); endpoint_options.ca_file = text(ca);
        endpoint_options.cert_policy = cert_policy; endpoint_options.flags = BC_ENDPOINT_COOKIE_JAR;
        endpoint_options.tls_min = tls_min; endpoint_options.tls_max = tls_max;
        if (status == BC_OK) status = bc_endpoint_create(http_context, &endpoint_options, &http_endpoint);
        char scheme[8], host[256]; uint16_t port = 0;
        bc_megarac_probe_options probe_options = {0};
        uint32_t random_id = 0; char client_id[9];
        if (status == BC_OK && RAND_bytes((unsigned char *)&random_id, sizeof(random_id)) != 1) status = BC_IO_ERROR;
        snprintf(client_id, sizeof(client_id), "%08u", (unsigned)(random_id % 100000000));
        probe_options.client_id = text(client_id);
        probe_options.struct_size = sizeof(probe_options); probe_options.abi_version = BC_ABI_VERSION;
        if (status == BC_OK && !endpoint_parts(endpoint, scheme, sizeof(scheme), host, sizeof(host), &port)) status = BC_INVALID_ARGUMENT;
        if (status == BC_OK) {
            probe_options.host = text(host); probe_options.username = text(username); probe_options.password = text(password);
            probe_options.timeout_ms = timeout_ms;
            int matched = 0;
            status = zte_probe(http_context, http_endpoint, &probe_options, &probe, &matched);
            if (!matched) status = bc_megarac_probe_start(http_endpoint, &probe_options, probe_completed, NULL, &probe);
        }
        while (status == BC_OK && probe && !bc_megarac_probe_result_get(probe)) status = bc_context_poll(http_context, 50);
        const bc_megarac_probe_result *result = probe ? bc_megarac_probe_result_get(probe) : NULL;
        if (status == BC_OK && result) status = result->status;
        const char *address = status == BC_OK && result && result->info.server_ip[0] ? result->info.server_ip : host;
        if (status == BC_OK && result && BC_MEGARAC_IS_H5(result->info.kind) && strlen(address) >= sizeof(derived_server))
            status = BC_LIMIT_EXCEEDED;
        if (status == BC_OK) {
            discovered_info = result->info;
            snprintf(discovered_info.host, sizeof(discovered_info.host), "%s", host);
            kind = result->info.kind;
            snprintf(derived_token, sizeof(derived_token), "%s", result->info.token);
            snprintf(derived_client, sizeof(derived_client), "%s", result->info.client_ip);
            if (BC_MEGARAC_IS_H5(kind)) memcpy(derived_server, address, strlen(address) + 1);
            if (result->cookie.length && result->cookie.length < sizeof(derived_cookie))
                memcpy(derived_cookie, result->cookie.data, result->cookie.length);
            if (!url) {
                if (BC_MEGARAC_IS_H5(kind)) {
                    snprintf(derived_url, sizeof(derived_url), "%s://%s:%u/kvm",
                        strcmp(scheme, "https") ? "ws" : "wss", host, port);
                } else {
                    uint16_t kvm_port = result->info.port ? (uint16_t)result->info.port : 7582;
                    snprintf(derived_url, sizeof(derived_url), "%s://%s:%u", result->info.secure ? "tls" : "tcp", host, kvm_port);
                }
                url = derived_url;
            }
            if (!token) token = derived_token;
            if (!client_ip && derived_client[0]) client_ip = derived_client;
            if (!server_ip && BC_MEGARAC_IS_H5(kind)) server_ip = derived_server;
            if (!cookie && derived_cookie[0]) cookie = derived_cookie;
        } else probe_status = status;
    }
    if (probe_status != BC_OK) {
        const bc_megarac_probe_result *failed = probe ? bc_megarac_probe_result_get(probe) : NULL;
        uint32_t failed_http = failed ? failed->http_status : 0;
        bc_status cleanup = http_cleanup(probe, http_endpoint, http_context, http_transport);
        yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *root = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, root);
        yyjson_mut_obj_add_str(doc, root, "status", bc_status_string(probe_status));
        yyjson_mut_obj_add_uint(doc, root, "http_status", failed_http);
        yyjson_mut_obj_add_str(doc, root, "logout", bc_status_string(cleanup));
        char *json = yyjson_mut_write(doc, 0, NULL); if (json) { puts(json); free(json); }
        yyjson_mut_doc_free(doc); return 1;
    }
    if (!url || !token || !*token || !username || (BC_MEGARAC_IS_H5(kind) && !server_ip)) { http_cleanup(probe, http_endpoint, http_context, http_transport); usage(); return 2; }
    signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal);
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) { http_cleanup(probe, http_endpoint, http_context, http_transport); return 2; }
    yyjson_mut_val *root = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, root);
    char origin_header[1100];
    bc_string headers[10];
    uint32_t header_count = 0;
    if (cookie) {
        size_t length = strlen(cookie) + 16;
        char *line = malloc(length);
        if (!line) { http_cleanup(probe, http_endpoint, http_context, http_transport); yyjson_mut_doc_free(doc); return 2; }
        snprintf(line, length, "Cookie: %s", cookie);
        headers[header_count++] = text(line);
    }
    for (uint32_t i = 0; i < extra_count; ++i) headers[header_count++] = extra_headers[i];
    if (endpoint && BC_MEGARAC_IS_H5(kind)) {
        snprintf(origin_header, sizeof(origin_header), "Origin: %s", endpoint);
        headers[header_count++] = text(origin_header);
    }
    bc_kvm_transport_options transport_options = {0};
    transport_options.struct_size = sizeof(transport_options); transport_options.abi_version = BC_ABI_VERSION;
    transport_options.url = text(url); transport_options.ca_file = text(ca);
    transport_options.headers = headers; transport_options.header_count = header_count;
    transport_options.subprotocols = text("binary, base64");
    transport_options.cert_policy = cert_policy; transport_options.tls_min = tls_min; transport_options.tls_max = tls_max;
    transport_options.timeout_ms = timeout_ms; transport_options.flags = flags;
    bc_kvm_transport *transport = NULL;
    bc_status status = bc_kvm_transport_connect(&transport_options, &transport);
    if (status == BC_OK && !client_ip) {
        status = bc_kvm_transport_local_address(transport, derived_client, sizeof(derived_client));
        if (status == BC_OK) client_ip = derived_client;
    }
    if (status == BC_OK && bc_kvm_transport_subprotocol(transport) == BC_KVM_TRANSPORT_SUBPROTOCOL_BASE64)
        status = BC_UNSUPPORTED;
    bc_megarac_kvm_info info = discovered_info;
    info.struct_size = sizeof(info); info.kind = kind;
    snprintf(info.token, sizeof(info.token), "%s", token);
    if (server_ip) snprintf(info.server_ip, sizeof(info.server_ip), "%s", server_ip);
    bc_megarac_session_options session_options = {0};
    uint8_t *frame_buffer = NULL;
    bc_megarac_session *session = NULL;
    if (status == BC_OK) {
        frame_buffer = malloc(FRAME_CAPACITY);
        if (!frame_buffer) status = BC_NO_MEMORY;
    }
    if (status == BC_OK) {
        session_options.struct_size = sizeof(session_options);
        session_options.kind = kind; session_options.info = &info;
        session_options.client_ip = client_ip; session_options.username = username;
        session_options.client_mac = mac; session_options.frame_buffer = frame_buffer;
        session_options.frame_capacity = FRAME_CAPACITY;
        status = bc_megarac_session_create(&session_options, &session);
        if (status == BC_OK) status = bc_megarac_session_keyboard_mode(session, bc_megarac_probe_keyboard_mode(probe));
    }
    uint8_t input[65536];
    uint64_t deadline = (uint64_t)time(NULL) + seconds;
    if (status == BC_OK) status = bc_megarac_session_start(session);
    uint32_t captured_frames = 0;
    int input_sent = 0;
    uint8_t *soc_rgba = NULL;
    uint32_t soc_width = 0, soc_height = 0;
    bc_megarac_soc_video *soc_video = NULL;
    bc_megarac_video *ast_video = NULL;
    uint8_t *ast_rgba = NULL;
    uint32_t ast_width = 0, ast_height = 0;
    uint16_t mouse_x = 0, mouse_y = 0;
    int have_mouse = 0;
    if (mouse_text) {
        char *end = NULL;
        unsigned long x = strtoul(mouse_text, &end, 10);
        if (end && *end == ',') {
            unsigned long y = strtoul(end + 1, NULL, 10);
            mouse_x = (uint16_t)(x > 65535 ? 65535 : x); mouse_y = (uint16_t)(y > 65535 ? 65535 : y); have_mouse = 1;
        }
    }
    uint32_t received = 0, input_offset = 0;
    while (status == BC_OK && captured_frames < max_frames && !interrupted && (uint64_t)time(NULL) <= deadline) {
        status = bc_megarac_session_tick(session, bc_agent_now_ms());
        if (status != BC_OK) break;
        status = flush_session(session, transport);
        if (status != BC_OK) break;
        if (input_offset == received) {
            input_offset = received = 0;
            status = bc_kvm_transport_recv(transport, input, sizeof(input), &received, 200);
            if (status == BC_TIMEOUT) { status = BC_OK; continue; }
            if (status != BC_OK) break;
        }
        uint32_t consumed = 0;
        if (received) status = bc_megarac_session_feed_frame(session, input + input_offset, received - input_offset, &consumed);
        input_offset += consumed;
        if (status != BC_OK) break;
        if (!input_sent && bc_megarac_session_state(session) == BC_MEGARAC_STATE_STREAMING) {
            if (key_text && *key_text) {
                uint8_t modifiers = 0, usages[6] = {0};
                usages[0] = (uint8_t)hid_usage(*key_text, &modifiers);
                if (usages[0]) {
                    status = bc_megarac_session_keyboard(session, modifiers, usages);
                    if (status == BC_OK) { memset(usages, 0, sizeof(usages)); status = bc_megarac_session_keyboard(session, 0, usages); }
                }
            }
            if (status == BC_OK && have_mouse) status = bc_megarac_session_mouse(session, 0, mouse_x, mouse_y, 0);
            if (status == BC_OK) status = flush_session(session, transport);
            input_sent = 1;
        }
        if (status != BC_OK) break;
        const bc_megarac_video_header *captured = bc_megarac_session_frame(session);
        if (!captured) continue;
        ++captured_frames;
        char frame_path[1088];
        const char *destination = ppm_path;
        if (ppm_path && max_frames > 1) {
            const char *dot = strrchr(ppm_path, '.');
            size_t base = dot ? (size_t)(dot - ppm_path) : strlen(ppm_path);
            snprintf(frame_path, sizeof(frame_path), "%.*s-%03u.ppm", (int)base, ppm_path, captured_frames - 1);
            destination = frame_path;
        }
        {
        yyjson_mut_obj_add_uint(doc, root, "width", captured->width);
        yyjson_mut_obj_add_uint(doc, root, "height", captured->height);
        yyjson_mut_obj_add_uint(doc, root, "source_width", captured->source_width);
        yyjson_mut_obj_add_uint(doc, root, "source_height", captured->source_height);
        yyjson_mut_obj_add_uint(doc, root, "compressed_size", captured->compressed_size);
        yyjson_mut_obj_add_uint(doc, root, "frame_flags", captured->flags);
        if (destination && (captured->flags & BC_MEGARAC_VIDEO_SOC)) {
            uint32_t width = 0, height = 0;
            const uint8_t *frame_data = bc_megarac_session_pixels(session);
            bc_status decoded = bc_megarac_soc_frame_size(frame_data, captured->compressed_size, &width, &height);
            uint32_t capacity = width * height * 4;
            if (decoded == BC_OK && (soc_width != width || soc_height != height)) {
                free(soc_rgba); soc_rgba = calloc(1, capacity);
                soc_width = width; soc_height = height;
            }
            if (decoded == BC_OK && !soc_video) decoded = bc_megarac_soc_video_create(&soc_video);
            if (decoded == BC_OK) decoded = soc_rgba ? bc_megarac_soc_video_decode(soc_video, frame_data,
                captured->compressed_size, soc_rgba, capacity, &width, &height) : BC_NO_MEMORY;
            if (decoded == BC_OK && !write_ppm(destination, soc_rgba, width, height)) decoded = BC_IO_ERROR;
            yyjson_mut_obj_add_str(doc, root, "decode_status", bc_status_string(decoded));
            if (decoded == BC_OK) {
                yyjson_mut_obj_add_uint(doc, root, "decoded_width", width);
                yyjson_mut_obj_add_uint(doc, root, "decoded_height", height);
            }
        }
        if (destination && !(captured->flags & BC_MEGARAC_VIDEO_SOC)) {
            uint32_t decoded_width = 0, decoded_height = 0;
            bc_status decode_status = BC_OK;
            uint32_t capacity = captured->width * captured->height * 4u;
            if (ast_width != captured->width || ast_height != captured->height) {
                free(ast_rgba);
                ast_rgba = calloc(1, capacity);
                ast_width = captured->width; ast_height = captured->height;
            }
            if (!ast_video) decode_status = bc_megarac_video_create(&ast_video);
            if (decode_status == BC_OK) decode_status = ast_rgba ?
                bc_megarac_video_decode_payload(ast_video, captured, bc_megarac_session_pixels(session),
                    captured->compressed_size, ast_rgba, capacity, &decoded_width, &decoded_height) : BC_NO_MEMORY;
            if (decode_status == BC_OK && !write_ppm(destination, ast_rgba, decoded_width, decoded_height))
                decode_status = BC_IO_ERROR;
            yyjson_mut_obj_add_strcpy(doc, root, "decode", bc_status_string(decode_status));
            if (decode_status == BC_OK) {
                yyjson_mut_obj_add_uint(doc, root, "decoded_width", decoded_width);
                yyjson_mut_obj_add_uint(doc, root, "decoded_height", decoded_height);
                yyjson_mut_obj_add_strcpy(doc, root, "ppm", destination);
            }
        }
        if (out_path) {
            char raw_path[1088];
            const char *raw_destination = out_path;
            if (max_frames > 1) {
                const char *dot = strrchr(out_path, '.');
                size_t base = dot ? (size_t)(dot - out_path) : strlen(out_path);
                snprintf(raw_path, sizeof(raw_path), "%.*s-%03u.bin", (int)base, out_path, captured_frames - 1);
                raw_destination = raw_path;
            }
            FILE *file = fopen(raw_destination, "wb");
            const uint8_t *data = bc_megarac_session_pixels(session);
            if (!file || fwrite(data, 1, captured->compressed_size, file) != captured->compressed_size) status = BC_IO_ERROR;
            if (file) fclose(file);
            yyjson_mut_obj_add_strcpy(doc, root, "output", raw_destination);
        }
        bc_megarac_session_ack_frame(session);
        }
    }
    if (status == BC_OK && !captured_frames) status = BC_TIMEOUT;
    yyjson_mut_obj_add_bool(doc, root, "keyboard_autobreak", (bc_megarac_session_flags(session) & BC_MEGARAC_KEYBOARD_AUTOBREAK) != 0);
    yyjson_mut_obj_add_bool(doc, root, "blank", (bc_megarac_session_flags(session) & BC_MEGARAC_BLANK) != 0);
    if (transport && session && bc_megarac_session_state(session) == BC_MEGARAC_STATE_STREAMING) {
        if (bc_megarac_session_close(session) == BC_OK) (void)flush_session(session, transport);
    }
    if (transport) bc_kvm_transport_close(transport);
    bc_status logout_status = http_cleanup(probe, http_endpoint, http_context, http_transport);
    if (endpoint) yyjson_mut_obj_add_str(doc, root, "logout", bc_status_string(logout_status));
    yyjson_mut_obj_add_str(doc, root, "status", bc_status_string(status));
    yyjson_mut_obj_add_uint(doc, root, "transport", bc_kvm_transport_kind(transport));
    yyjson_mut_obj_add_uint(doc, root, "frames", captured_frames);
    yyjson_mut_obj_add_uint(doc, root, "kind", kind);
    yyjson_mut_obj_add_bool(doc, root, "cookie", cookie && *cookie);
    if (input_sent && (key_text || have_mouse)) yyjson_mut_obj_add_bool(doc, root, "input", true);
    yyjson_mut_obj_add_uint(doc, root, "subprotocol", bc_kvm_transport_subprotocol(transport));
    char *json = yyjson_mut_write(doc, 0, NULL);
    if (json) { puts(json); free(json); }
    yyjson_mut_doc_free(doc);
    bc_megarac_session_destroy(session);
    if (transport) bc_kvm_transport_close(transport);
    bc_kvm_transport_destroy(transport);
    free(ast_rgba);
    bc_megarac_video_destroy(ast_video);
    free(soc_rgba);
    bc_megarac_soc_video_destroy(soc_video);
    free(frame_buffer);
    if (cookie && header_count) free((void *)headers[0].data);
    return status == BC_OK && captured_frames && logout_status == BC_OK ? 0 : 1;
}

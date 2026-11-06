#include "bcontrol/bcontrol.h"
#include "bcontrol/transport.h"
#include "yyjson.h"
#include "log.h"
#include "server.h"
#include "media_map.h"
#include "kvm_cmd.h"
#include "megarac_cmd.h"
#ifdef BC_AGENT_IPMI
#include "ipmi_cmd.h"
#endif
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t interrupted;
static void on_signal(int signal_number) { (void)signal_number; interrupted = 1; }
static bc_string str(const char *p) { return (bc_string){p, p ? strlen(p) : 0}; }
static const char *mode_name(uint32_t mode) {
    return mode == BC_CERT_STRICT ? "strict" : mode == BC_CERT_SKIP_CHAIN ? "skip-chain" : "skip-all";
}
static int parse_u32(const char *text, uint32_t *value) {
    char *end; errno = 0;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || !*text || *text == '-' || *end || n > UINT32_MAX) return 0;
    *value = (uint32_t)n; return 1;
}
static int parse_tls(const char *text, uint32_t *value) {
    if (!strcmp(text, "1.0")) *value = BC_TLS_1_0;
    else if (!strcmp(text, "1.1")) *value = BC_TLS_1_1;
    else if (!strcmp(text, "1.2")) *value = BC_TLS_1_2;
    else if (!strcmp(text, "1.3")) *value = BC_TLS_1_3;
    else return 0;
    return 1;
}
typedef struct { int done; bc_status status; yyjson_mut_doc *doc; yyjson_mut_val *results; } run_state;
static void completed(bc_request *request, const bc_response *r, void *userdata) {
    (void)request;
    run_state *state = userdata;
    yyjson_mut_doc *doc = state->doc;
    yyjson_mut_val *row = yyjson_mut_obj(doc);
    char revision[32]; snprintf(revision, sizeof(revision), "%" PRIu64, r->endpoint_revision);
    yyjson_mut_obj_add_strcpy(doc, row, "status", bc_status_string(r->status));
    yyjson_mut_obj_add_strcpy(doc, row, "endpoint_revision", revision);
    yyjson_mut_obj_add_uint(doc, row, "http_status", r->http_status);
    yyjson_mut_obj_add_strcpy(doc, row, "cert_policy", mode_name(r->cert_policy));
    yyjson_mut_obj_add_strcpy(doc, row, "verification", r->peer_verified ? "verified" : "not_verified");
    yyjson_mut_obj_add_strncpy(doc, row, "tls_version", r->tls_version.data ? r->tls_version.data : "", (size_t)r->tls_version.length);
    yyjson_mut_obj_add_strncpy(doc, row, "cipher", r->cipher.data ? r->cipher.data : "", (size_t)r->cipher.length);
    /* Backend diagnostics stay in the C API, avoiding credentials in output. */
    if (r->status != BC_OK) yyjson_mut_obj_add_strcpy(doc, row, "error", bc_status_string(r->status));
    if (r->body.length) {
        yyjson_doc *body = yyjson_read((const char *)r->body.data, (size_t)r->body.length, 0);
        if (body) {
            yyjson_mut_val *copy = yyjson_val_mut_copy(doc, yyjson_doc_get_root(body));
            yyjson_mut_obj_add_val(doc, row, "body", copy); yyjson_doc_free(body);
        } else {
            yyjson_mut_obj_add_strcpy(doc, row, "body_format", "non_json");
            yyjson_mut_obj_add_uint(doc, row, "body_bytes", r->body.length);
        }
    }
    yyjson_mut_arr_append(state->results, row);
    state->status = r->status; state->done = 1;
}
static void usage(void) {
    fputs("Global options: --log-level off|error|warn|info|debug|trace|verbose\n"
          "  --log-categories all|none|lifecycle,http,tls,redfish,ipmi,kvm,media,vendor\n"
          "  Logs go to stderr and are disabled by default; verbose adds sanitized request details.\n"
          "bcontrol-agent inspect --endpoint https://host[:port] [--path /redfish/v1/]\n"
          "  [--cert-policy strict|skip-chain|skip-all] [--ca file]\n"
          "  [--tls-min 1.0|1.1|1.2|1.3] [--tls-max version]\n"
          "  [--timeout-ms n] [--max-response n] [--then-strict]\n"
          "Credentials: BC_BMC_USERNAME and BC_BMC_PASSWORD environment variables.\n"
          "This initial diagnostic mode is not the paired HTTP/WebSocket service.\n", stderr);
#ifdef BC_AGENT_IPMI
    fputs("bcontrol-agent ipmi --host HOST [--port 623] [--allow-suite3] [--confirm-suite3]\n", stderr);
    fputs("bcontrol-agent sol --host HOST [--port 623] [--confirm-suite3]\n", stderr);
#endif
}
int main(int argc, char **argv) {
    if (bc_agent_log_options(&argc, argv)) { usage(); return 2; }
    if (argc > 1 && !strcmp(argv[1], "serve")) return bc_agent_serve(argc - 1, argv + 1);
    if (argc > 1 && !strcmp(argv[1], "media-map")) return bc_agent_media_map(argc - 1, argv + 1);
    if (argc > 1 && !strcmp(argv[1], "kvm")) return bc_agent_kvm(argc - 1, argv + 1);
    if (argc > 1 && !strcmp(argv[1], "megarac-media")) return bc_agent_megarac_media(argc - 1, argv + 1);
    if (argc > 1 && !strcmp(argv[1], "megarac-kvm")) return bc_agent_megarac_kvm(argc - 1, argv + 1);
#ifdef BC_AGENT_IPMI
    if (argc > 1 && !strcmp(argv[1], "ipmi")) return bc_agent_ipmi_inspect(argc - 1, argv + 1);
    if (argc > 1 && !strcmp(argv[1], "sol")) return bc_agent_ipmi_inspect(argc - 1, argv + 1);
#endif
    if (argc == 2 && !strcmp(argv[1], "--version")) { puts("bControl 0.2.0 ABI 1"); return 0; }
    if (argc < 2 || strcmp(argv[1], "inspect")) { usage(); return 2; }
    bc_endpoint_options endpoint = {0};
    endpoint.struct_size = sizeof(endpoint); endpoint.abi_version = BC_ABI_VERSION;
    endpoint.device_id = str("inspect"); endpoint.endpoint_id = str("redfish");
    endpoint.username = str(getenv("BC_BMC_USERNAME")); endpoint.password = str(getenv("BC_BMC_PASSWORD"));
    bc_http_options request = {0}; request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION;
    request.path = str("/redfish/v1/");
    uint32_t max_response = 1024u * 1024u;
    int then_strict = 0;
    for (int i = 2; i < argc; ++i) {
        const char *arg = argv[i];
        if (!strcmp(arg, "--then-strict")) { then_strict = 1; continue; }
        if (i + 1 >= argc) { usage(); return 2; }
        const char *value = argv[++i];
        if (!strcmp(arg, "--endpoint")) endpoint.origin = str(value);
        else if (!strcmp(arg, "--path")) request.path = str(value);
        else if (!strcmp(arg, "--ca")) endpoint.ca_file = str(value);
        else if (!strcmp(arg, "--cert-policy")) {
            if (!strcmp(value, "strict")) endpoint.cert_policy = BC_CERT_STRICT;
            else if (!strcmp(value, "skip-chain")) endpoint.cert_policy = BC_CERT_SKIP_CHAIN;
            else if (!strcmp(value, "skip-all")) endpoint.cert_policy = BC_CERT_SKIP_ALL;
            else { usage(); return 2; }
        } else if (!strcmp(arg, "--tls-min")) { if (!parse_tls(value, &endpoint.tls_min)) return 2; }
        else if (!strcmp(arg, "--tls-max")) { if (!parse_tls(value, &endpoint.tls_max)) return 2; }
        else if (!strcmp(arg, "--timeout-ms")) { if (!parse_u32(value, &request.timeout_ms) || !request.timeout_ms) return 2; }
        else if (!strcmp(arg, "--max-response")) { if (!parse_u32(value, &max_response) || !max_response) return 2; }
        else { usage(); return 2; }
    }
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
    bc_transport *transport = NULL; bc_context *context = NULL;
    bc_status status = bc_curl_transport_create(&transport);
    if (status != BC_OK) goto error;
    bc_context_options options = {sizeof(options), BC_ABI_VERSION, transport, max_response, 8, 0};
    status = bc_context_create(&options, &context);
    if (status != BC_OK) goto error;
    run_state state = {0}; state.doc = yyjson_mut_doc_new(NULL);
    if (!state.doc) { status = BC_NO_MEMORY; goto error; }
    state.results = yyjson_mut_arr(state.doc); yyjson_mut_doc_set_root(state.doc, state.results);
    int exit_code = 0;
    bc_endpoint *retained_endpoints[2] = {NULL, NULL};
    for (int pass = 0; pass < (then_strict ? 2 : 1); ++pass) {
        bc_endpoint *e = NULL; bc_request *r = NULL;
        if (pass) endpoint.cert_policy = BC_CERT_STRICT;
        status = bc_endpoint_create(context, &endpoint, &e);
        if (status != BC_OK) { exit_code = 2; break; }
        retained_endpoints[pass] = e;
        state.done = 0;
        status = bc_http_submit(e, &request, completed, &state, &r);
        if (status != BC_OK) { exit_code = 2; break; }
        while (!state.done) {
            if (interrupted) bc_request_cancel(r);
            status = bc_context_poll(context, 50);
            if (status != BC_OK) { bc_context_shutdown(context); bc_context_poll(context, 0); break; }
        }
        if (state.status != BC_OK) exit_code = 1;
        bc_request_release(r);
    }
    for (int i = 0; i < 2; ++i) bc_endpoint_release(retained_endpoints[i]);
    char *json = yyjson_mut_write(state.doc, YYJSON_WRITE_PRETTY, NULL);
    if (json) { puts(json); free(json); } else exit_code = 2;
    yyjson_mut_doc_free(state.doc);
    if (status != BC_OK) fprintf(stderr, "bcontrol-agent: %s\n", bc_status_string(status));
    bc_context_destroy(context); bc_curl_transport_destroy(transport);
    return exit_code;
error:
    fprintf(stderr, "bcontrol-agent: %s\n", bc_status_string(status));
    if (context) bc_context_destroy(context);
    if (transport) bc_curl_transport_destroy(transport);
    return 2;
}

#include "megarac.h"
#include "bcontrol/bcontrol.h"
#include "bcontrol/transport.h"
#include "yyjson.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct { int done; } state;
static void completed(bc_megarac_probe *probe, const bc_megarac_probe_result *result, void *userdata) {
    (void)probe; (void)result; ((state *)userdata)->done = 1;
}
int main(int argc, char **argv) {
    if (argc < 6) return 2;
    bc_transport *transport = NULL;
    bc_context *context = NULL;
    bc_endpoint *endpoint = NULL;
    bc_status status = bc_curl_transport_create(&transport);
    bc_context_options context_options = {sizeof(context_options), BC_ABI_VERSION, transport, 4u * 1024u * 1024u, 4, 0};
    if (status == BC_OK) status = bc_context_create(&context_options, &context);
    bc_endpoint_options endpoint_options = {0};
    endpoint_options.struct_size = sizeof(endpoint_options); endpoint_options.abi_version = BC_ABI_VERSION;
    endpoint_options.device_id = (bc_string){"megarac", 7}; endpoint_options.endpoint_id = (bc_string){"kvm", 3};
    endpoint_options.origin = (bc_string){argv[1], strlen(argv[1])};
    endpoint_options.ca_file = (bc_string){argv[2], strlen(argv[2])};
    endpoint_options.cert_policy = BC_CERT_SKIP_ALL;
    endpoint_options.flags = BC_ENDPOINT_COOKIE_JAR;
    if (status == BC_OK) status = bc_endpoint_create(context, &endpoint_options, &endpoint);
    bc_megarac_probe_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.host = (bc_string){argv[5], strlen(argv[5])};
    options.username = (bc_string){argv[3], strlen(argv[3])};
    options.password = (bc_string){argv[4], strlen(argv[4])};
    options.timeout_ms = 5000; options.client_id = (bc_string){"12345678", 8};
    state state = {0};
    bc_megarac_probe *probe = NULL;
    if (status == BC_OK && argc > 6) {
        bc_service_profile selected = {sizeof(selected), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC,
            BC_SERVICE_MEGARAC_KVM_JVIEWER_195, BC_SERVICE_EVIDENCE_MANUAL};
        if (!strcmp(argv[6], "373")) selected.variant = BC_SERVICE_MEGARAC_KVM_H5_373;
        if (!strcmp(argv[6], "438")) selected.variant = BC_SERVICE_MEGARAC_KVM_H5_438;
        if (!strcmp(argv[6], "inspur-rpc")) {
            status = bc_inspur_rpc_kvm_probe_start(endpoint, &options, completed, &state, &probe);
        } else if (!strcmp(argv[6], "login-nec") || !strcmp(argv[6], "login-basic") || !strcmp(argv[6], "login-h5")) {
            bc_megarac_login_contract login = {sizeof(login),
                !strcmp(argv[6], "login-h5") ? BC_MEGARAC_LOGIN_H5_SESSION : BC_MEGARAC_LOGIN_LEGACY_RPC,
                !strcmp(argv[6], "login-nec") ? 7u : 0u};
            status = bc_megarac_probe_start_with_login(endpoint, &options, &login, completed, &state, &probe);
        } else status = bc_megarac_probe_start_discovery(endpoint, &options,
            (!strcmp(argv[6], "195") || !strcmp(argv[6], "373") || !strcmp(argv[6], "438")) ? &selected : NULL, completed, &state, &probe);
    } else if (status == BC_OK) status = bc_megarac_probe_start(endpoint, &options, completed, &state, &probe);
    while (status == BC_OK && !state.done) status = bc_context_poll(context, 50);
    const bc_megarac_probe_result *result = probe ? bc_megarac_probe_result_get(probe) : NULL;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "status", bc_status_string(status == BC_OK && result ? result->status : status));
    const bc_console_failure *failure = bc_megarac_probe_failure_get(probe);
    if (failure) {
        yyjson_mut_obj_add_uint(doc, root, "failure_phase", failure->phase);
        yyjson_mut_obj_add_uint(doc, root, "failure_cause", failure->cause);
    }
    yyjson_mut_obj_add_uint(doc, root, "keyboard_mode", bc_megarac_probe_keyboard_mode(probe));
    const bc_service_profile *profile = bc_megarac_probe_profile_get(probe);
    if (profile) {
        yyjson_mut_obj_add_uint(doc, root, "profile_variant", profile->variant);
        yyjson_mut_obj_add_bool(doc, root, "profile_verified", bc_service_profile_verified(profile, BC_SERVICE_KVM));
    }
    if (result) {
        yyjson_mut_obj_add_uint(doc, root, "http_status", result->http_status);
        yyjson_mut_obj_add_uint(doc, root, "kind", result->kind);
        yyjson_mut_obj_add_uint(doc, root, "wire_kind", result->info.kind);
        yyjson_mut_obj_add_str(doc, root, "host", result->info.host);
        yyjson_mut_obj_add_str(doc, root, "token", result->info.token);
        yyjson_mut_obj_add_str(doc, root, "server_ip", result->info.server_ip);
        yyjson_mut_obj_add_uint(doc, root, "port", result->info.port);
        yyjson_mut_obj_add_uint(doc, root, "secure", result->info.secure);
        yyjson_mut_obj_add_uint(doc, root, "cookie_length", result->cookie.length);
        if (result->error_body.length)
            yyjson_mut_obj_add_strncpy(doc, root, "error_body", result->error_body.data, (size_t)result->error_body.length);
    }
    bc_megarac_media_parameters media_params;
    bc_status media_status = bc_megarac_probe_media_parameters(probe, &media_params);
    if (result && result->status == BC_OK && result->kind == BC_MEGARAC_HTTP_JVIEWER) {
        if (argc > 6 && !strcmp(argv[6], "inspur-rpc")) assert(media_status == BC_UNSUPPORTED);
        else {
            assert(media_status == BC_OK && media_params.port == 6200 && media_params.secure == 0 && media_params.token_type == 0);
            assert(bc_megarac_media_parameters_transport_usable(&media_params));
        }
    } else if (result && result->status == BC_OK && result->info.kind == BC_MEGARAC_KVM_H5VIEWER_373) {
        assert(media_status == BC_OK || media_status == BC_UNSUPPORTED);
    } else assert(media_status == (probe ? BC_UNSUPPORTED : BC_INVALID_ARGUMENT));
    yyjson_mut_obj_add_str(doc, root, "media_status", bc_status_string(media_status));
    if (media_status == BC_OK) yyjson_mut_obj_add_uint(doc, root, "media_devices", media_params.devices);
    if (result && result->status == BC_OK) {
        assert((bc_megarac_probe_launch_request(probe) != NULL) == (result->kind == BC_MEGARAC_HTTP_JVIEWER));
        state.done = 0;
        bc_status cleanup = bc_megarac_probe_logout(probe, completed, &state);
        while (cleanup == BC_OK && !state.done) cleanup = bc_context_poll(context, 50);
        const bc_megarac_probe_result *closed = bc_megarac_probe_result_get(probe);
        assert(bc_megarac_probe_media_parameters(probe, &media_params) == BC_UNSUPPORTED);
        if (cleanup == BC_OK && closed) cleanup = closed->status;
        yyjson_mut_obj_add_str(doc, root, "logout", bc_status_string(cleanup));
        if (cleanup != BC_OK) status = cleanup;
        else assert(!bc_megarac_probe_launch_request(probe));
    }
    char *json = yyjson_mut_write(doc, 0, NULL);
    if (json) { puts(json); free(json); }
    yyjson_mut_doc_free(doc);
    int exit_code = status == BC_OK && result && result->status == BC_OK ? 0 : 1;
    if (probe) bc_megarac_probe_release(probe);
    bc_endpoint_release(endpoint); bc_context_destroy(context); bc_curl_transport_destroy(transport);
    return exit_code;
}

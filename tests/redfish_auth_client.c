#include "bcontrol/redfish_auth.h"
#include "bcontrol/transport.h"
#include "yyjson.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int done;
    bc_status status;
    uint32_t http, flags, mode;
    bc_redfish_connection *connection;
} auth_state;
typedef struct { int done; bc_status status; uint32_t http; } read_state;
static bc_string text(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
static void authenticated(bc_redfish_auth_operation *op, const bc_redfish_auth_result *result, void *userdata) {
    (void)op; auth_state *state = userdata;
    ++state->done; state->status = result->status; state->http = result->http_status; state->flags = result->flags; state->mode = result->auth_mode;
    state->connection = result->connection; bc_redfish_connection_retain(state->connection);
}
static void read_done(bc_redfish_operation *op, const bc_redfish_result *result, void *userdata) {
    (void)op; read_state *state = userdata; ++state->done; state->status = result->status; state->http = result->http_status;
}
static bc_status poll_until(bc_context *context, int *done) {
    bc_status status = BC_OK;
    while (status == BC_OK && !*done) status = bc_context_poll(context, 20);
    return status;
}
static bc_status read_system(bc_context *context, bc_endpoint *endpoint, bc_string path, read_state *state) {
    bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, 15000, 0};
    bc_redfish_operation *operation = NULL;
    bc_status status = bc_redfish_get_system(endpoint, path, &options, read_done, state, &operation);
    if (status == BC_OK) status = poll_until(context, &state->done);
    if (operation) bc_redfish_release(operation);
    return status;
}
static int legacy_resources(bc_context *context, bc_endpoint *endpoint) {
    bc_redfish_collection_options options = {sizeof(options), BC_ABI_VERSION, 15000, 16};
    bc_redfish_operation *op = NULL; read_state state = {0};
    bc_status status = bc_redfish_get_collection(endpoint, text("/redfish/v1/Chassis"), BC_COLLECTION_CHASSIS, &options, read_done, &state, &op);
    if (status == BC_OK) status = poll_until(context, &state.done);
    const bc_redfish_collection_info *collection = bc_redfish_collection_info_get(op);
    int passed = status == BC_OK && state.status == BC_OK && collection && collection->member_count == 1;
    bc_redfish_release(op); op = NULL; state = (read_state){0};
    bc_redfish_options read = {sizeof(read), BC_ABI_VERSION, 15000, 0};
    status = bc_redfish_get_resource(endpoint, text("/redfish/v1/Chassis/one/Thermal"), &read, read_done, &state, &op);
    if (status == BC_OK) status = poll_until(context, &state.done);
    const bc_redfish_resource_info *resource = bc_redfish_resource_info_get(op);
    yyjson_doc *doc = resource ? yyjson_read((const char *)resource->json.data, (size_t)resource->json.length, 0) : NULL;
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_val *temperature = yyjson_arr_get_first(yyjson_obj_get(root, "Temperatures"));
    yyjson_val *fan = yyjson_arr_get_first(yyjson_obj_get(root, "Fans"));
    passed = passed && status == BC_OK && state.status == BC_OK &&
        yyjson_equals_str(yyjson_obj_get(yyjson_obj_get(temperature, "Status"), "State"), "Enabled") &&
        yyjson_get_uint(yyjson_obj_get(fan, "Reading")) == 5280 &&
        yyjson_equals_str(yyjson_obj_get(fan, "ReadingUnits"), "RPM");
    yyjson_doc_free(doc); bc_redfish_release(op); op = NULL; state = (read_state){0};
    status = bc_redfish_get_resource(endpoint, text("/redfish/v1/Chassis/one"), &read, read_done, &state, &op);
    if (status == BC_OK) status = poll_until(context, &state.done);
    const bc_redfish_context_info *links = bc_redfish_context_info_get(op);
    passed = passed && status == BC_OK && state.status == BC_OK && links && links->system_count == 0;
    bc_redfish_release(op);
    return passed;
}
int main(int argc, char **argv) {
    if (argc < 4) return 2;
    bc_redfish_login_options login = {0}; login.struct_size = sizeof(login); login.abi_version = BC_ABI_VERSION; login.request_timeout_ms = 15000;
    if (!strcmp(argv[3], "basic")) login.mode = BC_REDFISH_LOGIN_BASIC;
    else if (!strcmp(argv[3], "session")) login.mode = BC_REDFISH_LOGIN_SESSION;
    else if (strcmp(argv[3], "auto")) return 2;
    login.username = text(getenv("BC_BMC_USERNAME")); login.password = text(getenv("BC_BMC_PASSWORD"));
    const char *behavior = argc > 5 ? argv[5] : "roundtrip";
    bc_string system_uri = text(argc > 6 ? argv[6] : "/redfish/v1/Systems/system");
    bc_transport *transport = NULL; bc_context *context = NULL; bc_endpoint *base = NULL, *held = NULL;
    bc_status status = bc_curl_transport_create(&transport);
    bc_context_options context_options = {sizeof(context_options), BC_ABI_VERSION, transport, 1024u * 1024u, 8, 0};
    if (status == BC_OK) status = bc_context_create(&context_options, &context);
    bc_endpoint_options endpoint = {0}; endpoint.struct_size = sizeof(endpoint); endpoint.abi_version = BC_ABI_VERSION;
    endpoint.device_id = text("auth-test"); endpoint.endpoint_id = text("redfish"); endpoint.origin = text(argv[1]); endpoint.ca_file = text(argv[2]);
    endpoint.username = login.username; endpoint.password = login.password;
    if (argc > 4 && !strcmp(argv[4], "skip-all")) endpoint.cert_policy = BC_CERT_SKIP_ALL;
    if (status == BC_OK) status = bc_endpoint_create(context, &endpoint, &base);
    int resources_ok = 0;
    auth_state created = {0}, deleted = {0}; read_state before = {0}, after = {0};
    read_state public_probe = {0};
    if (status == BC_OK && !strcmp(behavior, "probe-login")) {
        bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, 15000, 0};
        bc_redfish_operation *probe = NULL;
        bc_endpoint *anonymous = NULL;
        bc_auth_options auth = {0}; auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION;
        status = bc_endpoint_with_auth(base, &auth, &anonymous);
        if (status == BC_OK) status = bc_redfish_probe(anonymous, &options, read_done, &public_probe, &probe);
        if (status == BC_OK) status = poll_until(context, &public_probe.done);
        if (status == BC_OK) status = public_probe.status;
        bc_redfish_release(probe);
        bc_endpoint_release(anonymous);
    }
    bc_redfish_auth_operation *operation = NULL;
    if (status == BC_OK) status = bc_redfish_login(base, &login, authenticated, &created, &operation);
    if (status == BC_OK && !strcmp(behavior, "cancel-login")) bc_redfish_auth_cancel(operation);
    bc_redfish_auth_release(operation); operation = NULL;
    if (status == BC_OK) status = poll_until(context, &created.done);
    if (status == BC_OK && created.connection) {
        held = bc_redfish_connection_endpoint(created.connection); bc_endpoint_retain(held);
        status = read_system(context, held, system_uri, &before);
        if (!strcmp(behavior, "resources")) resources_ok = legacy_resources(context, held);
        if (status == BC_OK && created.mode == BC_REDFISH_LOGIN_SESSION) {
            status = bc_redfish_logout(created.connection, 15000, authenticated, &deleted, &operation);
            if (status == BC_OK && !strcmp(behavior, "cancel-logout")) bc_redfish_auth_cancel(operation);
            bc_redfish_auth_release(operation); operation = NULL;
            if (status == BC_OK) status = poll_until(context, &deleted.done);
            if (status == BC_OK) status = read_system(context, held, system_uri, &after);
        }
    }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL); yyjson_mut_val *out = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, out);
    yyjson_mut_obj_add_bool(doc, out, "resources_ok", resources_ok);
    yyjson_mut_obj_add_str(doc, out, "login_status", bc_status_string(created.done ? created.status : status));
    yyjson_mut_obj_add_uint(doc, out, "login_count", (uint64_t)created.done); yyjson_mut_obj_add_uint(doc, out, "login_http", created.http);
    yyjson_mut_obj_add_uint(doc, out, "mode", created.mode); yyjson_mut_obj_add_uint(doc, out, "flags", created.flags);
    yyjson_mut_obj_add_uint(doc, out, "read_http", before.http); yyjson_mut_obj_add_uint(doc, out, "post_logout_http", after.http);
    yyjson_mut_obj_add_str(doc, out, "logout_status", deleted.done ? bc_status_string(deleted.status) : "not_requested");
    yyjson_mut_obj_add_uint(doc, out, "logout_count", (uint64_t)deleted.done); yyjson_mut_obj_add_uint(doc, out, "logout_flags", deleted.flags);
    if (created.connection) {
        const bc_redfish_connection_info *info = bc_redfish_connection_info_get(created.connection);
        yyjson_mut_obj_add_uint(doc, out, "connection_state", info->state);
        yyjson_mut_obj_add_strncpy(doc, out, "session_uri", info->session_uri.data ? info->session_uri.data : "", (size_t)info->session_uri.length);
        yyjson_mut_obj_add_bool(doc, out, "endpoint_available", bc_redfish_connection_endpoint(created.connection) != NULL);
    }
    char *json = yyjson_mut_write(doc, 0, NULL); if (json) { puts(json); free(json); }
    yyjson_mut_doc_free(doc);
    if (context) { bc_context_shutdown(context); bc_context_poll(context, 0); }
    bc_redfish_auth_release(operation); bc_redfish_connection_release(created.connection); bc_redfish_connection_release(deleted.connection);
    bc_endpoint_release(held); bc_endpoint_release(base);
    if (context && bc_context_destroy(context) != BC_OK) status = BC_BUSY;
    if (transport && bc_curl_transport_destroy(transport) != BC_OK) status = BC_BUSY;
    return status == BC_OK && created.done == 1 ? 0 : 2;
}

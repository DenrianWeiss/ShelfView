#include "bcontrol/idrac_http.h"
#include "bcontrol/transport.h"
#include <assert.h>
#include <string.h>

typedef struct { bc_transport_done done; void *arg; unsigned count, callbacks; } fixture;
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static int equals(bc_string value, const char *s) { return value.length == strlen(s) && !memcmp(value.data, s, (size_t)value.length); }
static bc_status open_endpoint(void *user, const bc_endpoint_options *options, void **out) {
    assert(!options->username.length && !options->password.length);
    *out = user; return BC_OK;
}
static void close_endpoint(void *user, void *endpoint) { (void)user; (void)endpoint; }
static bc_status cookie(void *u, void *e, bc_string n, bc_string v) { (void)u; (void)e; (void)n; (void)v; return BC_OK; }
static bc_status submit(void *user, void *endpoint, const bc_http_options *options, uint64_t limit,
    bc_transport_done done, void *arg, void **out) {
    (void)endpoint; (void)limit; fixture *f = user;
    assert(options->timeout_ms == 100 && !options->body.length);
    assert(equals(options->headers[0], "Accept: application/json"));
    if (f->count == 0) {
        assert(options->method == BC_HTTP_POST && equals(options->path, "/sysmgmt/2015/bmc/session"));
        assert(options->header_count == 3);
        assert(equals(options->headers[1], "user: \" fixture-user \""));
        assert(equals(options->headers[2], "password: \"fixture-\\\"password\""));
    } else {
        assert(options->header_count == 2 && equals(options->headers[1], "XSRF-TOKEN: fixture-session"));
        assert(options->method == (f->count == 1 ? BC_HTTP_GET : BC_HTTP_DELETE));
        assert(equals(options->path, f->count == 1 ? "/sysmgmt/2015/server/vconsole?type=eHTML5" : "/sysmgmt/2015/bmc/session"));
    }
    ++f->count; f->done = done; f->arg = arg; *out = f; return BC_OK;
}
static void cancel(void *user, void *operation) { (void)operation; ((fixture *)user)->done = NULL; }
static bc_status poll(void *user, uint32_t timeout) { (void)user; (void)timeout; return BC_OK; }
static void complete(bc_request *request, const bc_response *response, void *user) {
    (void)request; (void)response; ++((fixture *)user)->callbacks;
}
static void respond(fixture *f, bc_context *context, const char *body) {
    bc_transport_session_response response = {0};
    response.cookie.auth.response.base.struct_size = sizeof(response);
    response.cookie.auth.response.metadata.struct_size = sizeof(response.cookie.auth.response.metadata);
    response.cookie.auth.response.base.status = BC_OK;
    response.cookie.auth.response.base.http_status = 200;
    response.cookie.auth.response.base.body = (bc_bytes){(const uint8_t *)body, strlen(body)};
    response.csrf_token = text("fixture-session");
    response.cookie.cookie_header = text("session=fixture");
    f->done(f->arg, &response.cookie.auth.response.base); f->done = NULL;
    assert(bc_context_poll(context, 0) == BC_OK);
}
int main(void) {
    fixture f = {0};
    bc_transport transport = {sizeof(transport), BC_ABI_VERSION, &f, open_endpoint, close_endpoint, submit, cancel, poll, cookie};
    bc_context_options options = {sizeof(options), BC_ABI_VERSION, &transport, 65536, 4, 0};
    bc_context *context = NULL; assert(bc_context_create(&options, &context) == BC_OK);
    bc_endpoint_options config = {0}; config.struct_size = sizeof(config); config.abi_version = BC_ABI_VERSION;
    config.origin = text("https://fixture.invalid"); config.device_id = config.endpoint_id = text("fixture"); config.flags = BC_ENDPOINT_COOKIE_JAR;
    bc_endpoint *endpoint = NULL, *other = NULL;
    assert(bc_endpoint_create(context, &config, &endpoint) == BC_OK);
    assert(bc_endpoint_create(context, &config, &other) == BC_OK);
    bc_request *login = NULL, *request = NULL;
    assert(bc_idrac_http_login(endpoint, text(" fixture-user "), text("fixture-\"password"), 100, complete, &f, &login) == BC_OK);
    assert(bc_idrac_http_login_status(login) == BC_BUSY);
    respond(&f, context, "{\"authResult\":0}");
    assert(bc_idrac_http_login_status(login) == BC_OK);
    assert(bc_idrac_http_submit(other, login, BC_IDRAC_HTTP_LAUNCH, 100, complete, &f, &request) == BC_INVALID_ARGUMENT && !request);
    assert(bc_idrac_http_submit(endpoint, login, BC_IDRAC_HTTP_LAUNCH, 100, complete, &f, &request) == BC_OK);
    respond(&f, context, "{}"); bc_request_release(request);
    assert(bc_idrac_http_submit(endpoint, login, BC_IDRAC_HTTP_LOGOUT, 100, complete, &f, &request) == BC_OK);
    respond(&f, context, "{}"); bc_request_release(request);
    assert(f.count == 3 && f.callbacks == 3);
    bc_request_release(login); bc_endpoint_release(other); bc_endpoint_release(endpoint);
    assert(bc_context_shutdown(context) == BC_OK); assert(bc_context_destroy(context) == BC_OK);
    return 0;
}

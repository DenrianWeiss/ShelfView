#include "bcontrol/bcontrol.h"
#include "bcontrol/transport.h"
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
typedef struct { int submitted, cancelled, called; bc_transport_done done; void *arg; const bc_endpoint_options *last_config; uint32_t header_count; char content_type[64], first_header[128]; } state;
static bc_status opened(void *u, const bc_endpoint_options *o, void **out) { ((state *)u)->last_config = o; *out = (void *)1; return BC_OK; }
static void closed(void *u, void *e) { (void)u; (void)e; }
static bc_status submitted(void *u, void *e, const bc_http_options *o, uint64_t n, bc_transport_done cb, void *arg, void **out) {
    (void)e; (void)o; (void)n;
    state *s = u; ++s->submitted; s->done = cb; s->arg = arg; *out = s;
    s->header_count = o->header_count;
    s->content_type[0] = 0; s->first_header[0] = 0;
    if (o->content_type.length && o->content_type.length < sizeof(s->content_type))
        memcpy(s->content_type, o->content_type.data, (size_t)o->content_type.length);
    if (o->header_count && o->headers[0].length < sizeof(s->first_header))
        memcpy(s->first_header, o->headers[0].data, (size_t)o->headers[0].length);
    return BC_OK;
}
static void cancelled(void *u, void *op) { (void)op; ++((state *)u)->cancelled; }
static bc_status polled(void *u, uint32_t n) { (void)u; (void)n; return BC_OK; }
static void completed(bc_request *r, const bc_response *response, void *u) {
    state *s = u; ++s->called;
    CHECK(response->status == BC_CANCELLED || response->status == BC_OUTCOME_UNKNOWN);
    CHECK(bc_request_response(r) == response);
}
static void metadata_completed(bc_request *r, const bc_response *response, void *u) {
    ++((state *)u)->called;
    CHECK(response->status == BC_OK && response->struct_size == sizeof(*response));
    const bc_http_metadata *metadata = bc_request_http_metadata(r);
    CHECK(metadata && metadata->location.length == 16 && !memcmp(metadata->location.data, "/redfish/v1/task", 16));
    CHECK(metadata->retry_after.length == 1 && *metadata->retry_after.data == '3');
    bc_string csrf = bc_request_csrf_token(r);
    CHECK(csrf.length == 10 && !memcmp(csrf.data, "csrf-token", 10));
    bc_string token = bc_request_auth_token(r);
    CHECK(token.length == 14 && !memcmp(token.data, "response-token", 14));
}
static const bc_socks5_proxy *last_proxy;
static bc_status proxy_opened(void *u, const bc_endpoint_options *o, const bc_socks5_proxy *p, void **out) {
    last_proxy = p; return opened(u, o, out);
}
static void proxy_test(void) {
    state s = {0};
    bc_transport_proxy t = {{sizeof(t), BC_ABI_VERSION, &s, opened, closed, submitted, cancelled, polled, NULL}, proxy_opened};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &t.base, 128, 1, 0};
    bc_context *c = NULL; CHECK(bc_context_create(&co, &c) == BC_OK);
    bc_endpoint_options eo = {0}; eo.struct_size=sizeof(eo); eo.abi_version=BC_ABI_VERSION;
    eo.device_id=(bc_string){"device",6}; eo.endpoint_id=(bc_string){"endpoint",8}; eo.origin=(bc_string){"https://bmc.invalid",18};
    char host[]="proxy.invalid", password[]="secret";
    bc_socks5_proxy proxy={sizeof(proxy),{host,13},{"u",1},{password,6},1080};
    bc_endpoint *e=NULL, *derived=NULL;
    CHECK(bc_endpoint_create_proxy(c,&eo,&proxy,&e)==BC_OK);
    memset(host,'x',13); memset(password,'x',6);
    CHECK(!strcmp(last_proxy->host.data,"proxy.invalid") && !strcmp(last_proxy->password.data,"secret"));
    bc_auth_options auth={0}; auth.struct_size=sizeof(auth); auth.abi_version=BC_ABI_VERSION; auth.mode=BC_AUTH_TOKEN;
    auth.token=(bc_string){"token",5};
    CHECK(bc_endpoint_with_auth(e,&auth,&derived)==BC_OK);
    bc_endpoint_release(e);
    CHECK(!strcmp(last_proxy->host.data,"proxy.invalid") && !strcmp(last_proxy->password.data,"secret"));
    bc_endpoint_release(derived);
    t.base.struct_size=sizeof(bc_transport);
    CHECK(bc_endpoint_create_proxy(c,&eo,&proxy,&e)==BC_UNSUPPORTED && !e);
    CHECK(bc_context_destroy(c)==BC_OK);
}
int main(void) {
    proxy_test();
    state s = {0};
    bc_transport t = {sizeof(t), BC_ABI_VERSION, &s, opened, closed, submitted, cancelled, polled, NULL};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &t, 128, 1, 0};
    bc_context *c = NULL; CHECK(bc_context_create(&co, &c) == BC_OK);
    t.struct_size = offsetof(bc_transport, cookie_set);
    bc_context *old_context = NULL; CHECK(bc_context_create(&co, &old_context) == BC_OK);
    CHECK(bc_context_destroy(old_context) == BC_OK); t.struct_size = sizeof(t);
    bc_endpoint_options eo = {0}; eo.struct_size = sizeof(eo); eo.abi_version = BC_ABI_VERSION;
    eo.device_id = (bc_string){"device", 6}; eo.endpoint_id = (bc_string){"redfish", 7};
    eo.origin = (bc_string){"https://localhost", 17};
    eo.username = (bc_string){"basic-user", 10}; eo.password = (bc_string){"basic-pass", 10};
    bc_endpoint *e = NULL;
    eo.cert_policy = 99; CHECK(bc_endpoint_create(c, &eo, &e) == BC_INVALID_ARGUMENT && !e);
    eo.cert_policy = 0; eo.flags = 0x80; CHECK(bc_endpoint_create(c, &eo, &e) == BC_INVALID_ARGUMENT && !e);
    eo.flags = BC_ENDPOINT_COOKIE_JAR; eo.reserved2 = 1; CHECK(bc_endpoint_create(c, &eo, &e) == BC_INVALID_ARGUMENT && !e);
    eo.reserved2 = 0; CHECK(bc_endpoint_create(c, &eo, &e) == BC_OK);
    bc_auth_options auth = {0}; auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION; auth.mode = BC_AUTH_TOKEN;
    auth.token = (bc_string){"bad\r\ntoken", 10};
    bc_endpoint *token_endpoint = NULL, *anonymous = NULL;
    CHECK(bc_endpoint_with_auth(e, &auth, &token_endpoint) == BC_INVALID_ARGUMENT);
    char token[] = "valid-token"; auth.token = (bc_string){token, sizeof(token) - 1};
    CHECK(bc_endpoint_with_auth(e, &auth, &token_endpoint) == BC_OK);
    CHECK(bc_endpoint_revision(token_endpoint) > bc_endpoint_revision(e));
    memset(token, 'x', sizeof(token) - 1);
    CHECK(s.last_config->struct_size == sizeof(bc_transport_endpoint_config));
    CHECK(s.last_config->username.length == 0 && s.last_config->password.length == 0 && s.last_config->cert_policy == eo.cert_policy);
    CHECK(!strcmp(((const bc_transport_endpoint_config *)s.last_config)->auth_token.data, "valid-token"));
    auth.mode = BC_AUTH_NONE; auth.token = (bc_string){NULL, 0};
    CHECK(bc_endpoint_with_auth(token_endpoint, &auth, &anonymous) == BC_OK);
    CHECK(s.last_config->struct_size == sizeof(bc_endpoint_options) && s.last_config->username.length == 0);
    bc_endpoint_release(anonymous); bc_endpoint_release(token_endpoint);
    CHECK(bc_context_destroy(c) == BC_BUSY);
    bc_http_options ro = {0}; ro.struct_size = sizeof(ro); ro.abi_version = BC_ABI_VERSION;
    ro.path = (bc_string){"/redfish/v1/", 12};
    bc_request *r = NULL, *extra = NULL;
    CHECK(bc_http_submit(e, &ro, completed, &s, &r) == BC_OK);
    CHECK(bc_http_submit(e, &ro, completed, &s, &extra) == BC_BUSY);
    CHECK(bc_request_response(r) == NULL);
    CHECK(bc_request_cancel(r) == BC_OK && s.cancelled == 1 && s.called == 0);
    CHECK(bc_request_cancel(r) == BC_OK && s.cancelled == 1);
    CHECK(bc_context_poll(c, 0) == BC_OK && s.called == 1);
    CHECK(bc_request_http_metadata(r) == NULL);
    bc_request_release(r);
    CHECK(bc_http_submit(e, &ro, metadata_completed, &s, &r) == BC_OK);
    char location[] = "/redfish/v1/task";
    char response_token[] = "response-token";
    bc_transport_session_response response = {0}; response.cookie.auth.response.base.struct_size = sizeof(response); response.cookie.auth.response.base.http_status = 202;
    response.cookie.auth.response.metadata.struct_size = sizeof(response.cookie.auth.response.metadata);
    response.cookie.auth.response.metadata.location = (bc_string){location, sizeof(location) - 1}; response.cookie.auth.response.metadata.retry_after = (bc_string){"3", 1};
    response.cookie.auth.auth_token = (bc_string){response_token, sizeof(response_token) - 1};
    char csrf_token[] = "csrf-token";
    response.csrf_token = (bc_string){csrf_token, sizeof(csrf_token) - 1};
    s.done(s.arg, &response.cookie.auth.response.base); memset(csrf_token, 'x', sizeof(csrf_token) - 1); memset(location, 'x', sizeof(location) - 1); memset(response_token, 'x', sizeof(response_token) - 1);
    CHECK(bc_context_poll(c, 0) == BC_OK && s.called == 2);
    bc_request_release(r);
    ro.method = BC_HTTP_POST;
    bc_string headers[2] = {{"X-Fixture: one", 14}, {"X-Trace: two", 12}};
    ro.content_type = (bc_string){"application/x-www-form-urlencoded", 33};
    ro.headers = headers; ro.header_count = 2;
    CHECK(bc_http_submit(e, &ro, completed, &s, &r) == BC_OK);
    CHECK(s.header_count == 2 && !strcmp(s.content_type, "application/x-www-form-urlencoded") && !strcmp(s.first_header, "X-Fixture: one"));
    CHECK(bc_request_cancel(r) == BC_OK && s.called == 2);
    CHECK(bc_context_poll(c, 0) == BC_OK && s.called == 3);
    bc_request_release(r);
    bc_string bad_headers[2] = {{"Cookie: injected", 16}, {"Bad Name: value", 15}};
    ro.headers = bad_headers; ro.header_count = 1;
    CHECK(bc_http_submit(e, &ro, completed, &s, &r) == BC_INVALID_ARGUMENT);
    ro.headers = bad_headers + 1;
    CHECK(bc_http_submit(e, &ro, completed, &s, &r) == BC_INVALID_ARGUMENT);
    ro.headers = headers; ro.header_count = 17;
    CHECK(bc_http_submit(e, &ro, completed, &s, &r) == BC_INVALID_ARGUMENT);
    ro.header_count = 2; ro.content_type = (bc_string){"bad\n", 4};
    CHECK(bc_http_submit(e, &ro, completed, &s, &r) == BC_INVALID_ARGUMENT);
    ro.content_type = (bc_string){NULL, 0};
    CHECK(bc_http_submit(e, &ro, completed, &s, &r) == BC_OK);
    CHECK(bc_request_cancel(r) == BC_OK && s.called == 3);
    CHECK(bc_context_poll(c, 0) == BC_OK && s.called == 4);
    bc_request_release(r);
    CHECK(bc_context_shutdown(c) == BC_OK);
    CHECK(bc_context_poll(c, 0) == BC_OK);
    CHECK(bc_http_submit(e, &ro, completed, &s, &extra) == BC_SHUTTING_DOWN);
    bc_endpoint_release(e);
    CHECK(bc_context_destroy(c) == BC_OK);

    uint8_t bytes[44] = {0};
    bc_media_header h = {BC_MEDIA_READ, 3, 0, UINT64_MAX, (UINT64_C(1) << 54) + 1, 4, 0}, decoded;
    CHECK(bc_media_header_encode(&h, bytes) == BC_OK);
    CHECK(bytes[4] == 0 && bytes[5] == 1 && bytes[16] == 255);
    CHECK(bc_media_header_decode(bytes, sizeof(bytes), 4, &decoded) == BC_OK);
    CHECK(decoded.request_id == h.request_id && decoded.offset == h.offset);
    CHECK(bc_media_header_decode(bytes, sizeof(bytes) - 1, 4, &decoded) == BC_INVALID_ARGUMENT);
    CHECK(bc_media_header_decode(bytes, sizeof(bytes), 3, &decoded) == BC_LIMIT_EXCEEDED);
    bytes[39] = 1; CHECK(bc_media_header_decode(bytes, sizeof(bytes), 4, &decoded) == BC_INVALID_ARGUMENT);
    CHECK(bc_media_range_check(UINT64_MAX, UINT64_MAX - 1, 2) == BC_INVALID_ARGUMENT);
    CHECK(bc_media_range_check(UINT64_MAX, UINT64_MAX - 1, 1) == BC_OK);
    h.offset = 1; h.payload_length = 4;
    CHECK(bc_media_read_encode(&h, 4, 5, 4, bytes) == BC_OK);
    uint32_t read_length = 0;
    CHECK(bc_media_read_decode(bytes, sizeof(bytes), 5, 4, &decoded, &read_length) == BC_OK && read_length == 4);
    CHECK(bc_media_read_decode(bytes, sizeof(bytes), 4, 4, &decoded, &read_length) == BC_INVALID_ARGUMENT);
    CHECK(bc_media_read_decode(bytes, sizeof(bytes), 5, 3, &decoded, &read_length) == BC_LIMIT_EXCEEDED);
    memset(bytes + 40, 0, 4);
    CHECK(bc_media_read_decode(bytes, sizeof(bytes), 5, 4, &decoded, &read_length) == BC_INVALID_ARGUMENT);
    puts("core: ownership, cancellation, shutdown, limits and media boundaries passed");
    return 0;
}

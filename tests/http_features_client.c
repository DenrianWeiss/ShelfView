#include "bcontrol/bcontrol.h"
#include "bcontrol/transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int done;
    bc_status status;
    uint32_t http_status;
    char body[256];
    int has_cookie;
    int has_error;
} result;

static void completed(bc_request *request, const bc_response *response, void *userdata) {
    (void)request;
    result *r = userdata;
    memset(r, 0, sizeof(*r));
    r->status = response->status;
    r->has_error = response->error.length > 0;
    r->http_status = response->http_status;
    uint64_t length = response->body.length < sizeof(r->body) - 1 ? response->body.length : sizeof(r->body) - 1;
    if (response->body.data) memcpy(r->body, response->body.data, (size_t)length);
    r->body[length] = 0;
    r->has_cookie = bc_request_cookie_header(request).length > 0;
    r->done = 1;
}

static int run(bc_context *context, bc_endpoint *endpoint, result *out, bc_http_options *options) {
    out->done = 0;
    bc_request *request = NULL;
    bc_status status = bc_http_submit(endpoint, options, completed, out, &request);
    while (status == BC_OK && !out->done) status = bc_context_poll(context, 50);
    bc_request_release(request);
    if (status == BC_OK) status = out->status;
    return status == BC_OK ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    bc_transport *transport = NULL;
    bc_context *context = NULL;
    bc_endpoint *endpoint = NULL;
    bc_status status = bc_curl_transport_create(&transport);
    bc_context_options context_options = {sizeof(context_options), BC_ABI_VERSION, transport, 65536, 4, 0};
    if (status == BC_OK) status = bc_context_create(&context_options, &context);
    bc_endpoint_options endpoint_options = {0};
    endpoint_options.struct_size = sizeof(endpoint_options); endpoint_options.abi_version = BC_ABI_VERSION;
    endpoint_options.device_id = (bc_string){"http-test", 9}; endpoint_options.endpoint_id = (bc_string){"fixture", 7};
    endpoint_options.origin = (bc_string){argv[1], strlen(argv[1])};
    endpoint_options.ca_file = (bc_string){argv[2], strlen(argv[2])};
    endpoint_options.cert_policy = BC_CERT_SKIP_ALL;
    endpoint_options.flags = BC_ENDPOINT_COOKIE_JAR;
    if (status == BC_OK) status = bc_endpoint_create(context, &endpoint_options, &endpoint);
    result r;
    bc_http_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.timeout_ms = 5000;
    int failed = status != BC_OK;
    if (!failed) {
        failed |= bc_endpoint_set_cookie(endpoint, (bc_string){"bad;name", 8}, (bc_string){"value", 5}) != BC_INVALID_ARGUMENT;
        failed |= bc_endpoint_set_cookie(endpoint, (bc_string){"imported", 8}, (bc_string){"value", 5}) != BC_OK;
        options.path = (bc_string){"/cookie/import", 14}; failed |= run(context, endpoint, &r, &options);
        failed |= r.http_status != 200;
    }
    if (!failed) { options.path = (bc_string){"/cookie/set", 11}; failed |= run(context, endpoint, &r, &options); }
    if (!failed) { options.path = (bc_string){"/cookie/check", 13}; failed |= run(context, endpoint, &r, &options); failed |= r.http_status != 200; }
    if (!failed) {
        options.path = (bc_string){"/compressed", 11}; failed |= run(context, endpoint, &r, &options);
        failed |= !strstr(r.body, "compressed") || !strstr(r.body, "ok");
    }
    if (!failed) {
        options.path = (bc_string){"/compressed-large", 17};
        int rejected = run(context, endpoint, &r, &options);
        failed |= !rejected || r.status != BC_LIMIT_EXCEEDED;
    }
    if (!failed) {
        options.path = (bc_string){"/bad-gzip-error", 15};
        failed |= !run(context, endpoint, &r, &options) || r.status != BC_HTTP_ERROR ||
            r.http_status != 405 || r.body[0] || !r.has_error;
        options.path = (bc_string){"/bad-gzip-ok", 12};
        failed |= !run(context, endpoint, &r, &options) || r.status != BC_IO_ERROR || r.http_status != 200;
        options.method = BC_HTTP_POST; options.path = (bc_string){"/bad-gzip-error", 15};
        failed |= !run(context, endpoint, &r, &options) || r.status != BC_OUTCOME_UNKNOWN || r.http_status != 405;
    }
    if (!failed) {
        bc_string headers[1] = {{"X-Fixture: token", 16}};
        options.method = BC_HTTP_POST; options.path = (bc_string){"/form", 5};
        options.content_type = (bc_string){"application/x-www-form-urlencoded", 33};
        options.headers = headers; options.header_count = 1;
        options.body = (bc_bytes){(const unsigned char *)"a=1&b=two", 9};
        failed |= run(context, endpoint, &r, &options);
        failed |= r.http_status != 200 || !strstr(r.body, "header") || !strstr(r.body, "form");
    }
    if (!failed) {
        uint8_t *upload = malloc(2u*1024u*1024u);
        if (!upload) failed = 1;
        else {
            memset(upload, 'x', 2u*1024u*1024u);
            bc_string no_expect = {"Expect:", 7};
            options.method = BC_HTTP_POST; options.path = (bc_string){"/disconnect-upload",18};
            options.content_type = (bc_string){"application/octet-stream",24};
            options.headers = &no_expect; options.header_count = 1;
            options.body = (bc_bytes){upload,2u*1024u*1024u};
            for (unsigned i = 0; i < 3; ++i) {
                result disconnected;
                failed |= !run(context,endpoint,&disconnected,&options) || disconnected.status != BC_OUTCOME_UNKNOWN;
            }
            free(upload);
        }
    }
    printf("{\"status\":\"%s\",\"http_status\":%u,\"cookie\":%s}\n", failed ? "failed" : "ok", r.http_status,
        r.has_cookie ? "true" : "false");
    bc_endpoint_release(endpoint); bc_context_destroy(context); bc_curl_transport_destroy(transport);
    return failed ? 1 : 0;
}

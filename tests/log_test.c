#include "bcontrol/bcontrol.h"
#include "bcontrol/log.h"
#include "bcontrol/redfish.h"
#include "bcontrol/transport.h"
#include "log_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static char captured[32768];
static unsigned records;

static void capture(void *userdata, const bc_log_record *record) {
    (void)userdata;
    ++records;
    size_t used = strlen(captured);
    if (used + record->detail.length + record->event.length + 96 >= sizeof(captured)) return;
    int n = snprintf(captured + used, sizeof(captured) - used, "level=%u category=%u event=%.*s %.*s\n",
        record->level, record->category, (int)record->event.length, record->event.data,
        (int)record->detail.length, record->detail.data);
    if (n > 0) captured[used + (size_t)n] = 0;
}
static void clear(void) { captured[0] = 0; records = 0; }
static void configure(uint32_t level, uint32_t categories) {
    bc_log_options options = {sizeof(options), BC_ABI_VERSION, level, categories, capture, NULL, 0};
    CHECK(bc_log_configure(&options) == BC_OK);
}
static int has(const char *text) { return strstr(captured, text) != NULL; }

typedef struct {
    bc_transport_done done;
    void *arg;
    unsigned submitted;
} fake_state;
static bc_status opened(void *userdata, const bc_endpoint_options *options, void **out) {
    (void)userdata; (void)options; *out = (void *)1; return BC_OK;
}
static void closed(void *userdata, void *endpoint) { (void)userdata; (void)endpoint; }
static bc_status submitted(void *userdata, void *endpoint, const bc_http_options *options, uint64_t limit,
    bc_transport_done done, void *arg, void **out) {
    (void)endpoint; (void)options; (void)limit;
    fake_state *state = userdata;
    state->done = done; state->arg = arg; *out = state; ++state->submitted;
    return BC_OK;
}
static void cancelled(void *userdata, void *operation) { (void)userdata; (void)operation; }
static bc_status polled(void *userdata, uint32_t timeout) { (void)userdata; (void)timeout; return BC_OK; }
static void completion(bc_request *request, const bc_response *response, void *userdata) {
    (void)request; (void)userdata;
    CHECK(response->status == BC_OK || response->status == BC_CANCELLED);
}
static void redfish_done(bc_redfish_operation *operation, const bc_redfish_result *result, void *userdata) {
    (void)operation; (void)userdata;
    CHECK(result->status == BC_CANCELLED || result->status == BC_OUTCOME_UNKNOWN);
}

int main(void) {
    fake_state state = {0};
    bc_transport transport = {sizeof(transport), BC_ABI_VERSION, &state, opened, closed, submitted, cancelled, polled, NULL};
    bc_context *context = NULL;
    bc_context_options context_options = {sizeof(context_options), BC_ABI_VERSION, &transport, 1024, 4, 0};

    clear();
    CHECK(bc_context_create(&context_options, &context) == BC_OK);
    CHECK(records == 0);
    bc_endpoint_options endpoint = {0};
    endpoint.struct_size = sizeof(endpoint); endpoint.abi_version = BC_ABI_VERSION;
    endpoint.device_id = (bc_string){"device", 6}; endpoint.endpoint_id = (bc_string){"redfish", 7};
    endpoint.origin = (bc_string){"https://bmc.example.com:8443", 28};
    endpoint.username = (bc_string){"alice-secret", 12}; endpoint.password = (bc_string){"password-secret", 15};
    bc_endpoint *first = NULL;
    CHECK(bc_endpoint_create(context, &endpoint, &first) == BC_OK);
    bc_auth_options auth = {0}; auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION;
    auth.mode = BC_AUTH_TOKEN; auth.token = (bc_string){"token-secret", 12};
    bc_endpoint *second = NULL;
    CHECK(bc_endpoint_with_auth(first, &auth, &second) == BC_OK);

    configure(BC_LOG_LEVEL_DEBUG, BC_LOG_CATEGORY_ALL);
    clear();
    bc_http_options request = {0}; request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION;
    static const char request_path[] = "/redfish/v1/Systems/1?token=query-secret";
    static const char request_body[] = "{\"Password\":\"body-secret\"}";
    static const char request_header[] = "X-Secret: header-secret";
    request.method = BC_HTTP_POST; request.path = (bc_string){request_path, sizeof(request_path) - 1};
    request.body = (bc_bytes){(const uint8_t *)request_body, sizeof(request_body) - 1};
    request.timeout_ms = 1000;
    bc_string header = {request_header, sizeof(request_header) - 1}; request.headers = &header; request.header_count = 1;
    bc_request *pending = NULL;
    CHECK(bc_http_submit(second, &request, completion, NULL, &pending) == BC_OK);
    bc_transport_cookie_response response = {0};
    response.auth.response.base.struct_size = sizeof(response);
    response.auth.response.base.status = BC_OK;
    response.auth.response.base.http_status = 200;
    static const char response_body[] = "{\"Password\":\"body-secret\"}";
    static const char response_error[] = "bmc.example.com password-secret body-secret";
    response.auth.response.base.body = (bc_bytes){(const uint8_t *)response_body, sizeof(response_body) - 1};
    response.auth.response.base.error = (bc_string){response_error, sizeof(response_error) - 1};
    response.auth.response.base.tls_version = (bc_string){"TLSv1.3", 7};
    response.auth.response.base.cipher = (bc_string){"TLS_AES_256_GCM_SHA384", 22};
    response.auth.response.base.peer_verified = 1;
    response.auth.response.metadata.struct_size = sizeof(response.auth.response.metadata);
    response.auth.auth_token = (bc_string){"response-token-secret", 21};
    static const char cookie[] = "SessionCookie=cookie-secret";
    response.cookie_header = (bc_string){cookie, sizeof(cookie) - 1};
    state.done(state.arg, &response.auth.response.base);
    CHECK(bc_context_poll(context, 0) == BC_OK);
    bc_request_release(pending);

    CHECK(has("event=request.submit"));
    CHECK(has("path=/redfish/v1/Systems/1"));
    CHECK(has("query=1"));
    CHECK(has("event=request.complete"));
    CHECK(has("token_len=21") && has("cookie_len=27"));
    CHECK(!strstr(captured, "alice-secret"));
    CHECK(!strstr(captured, "password-secret"));
    CHECK(!strstr(captured, "token-secret"));
    CHECK(!strstr(captured, "query-secret"));
    CHECK(!strstr(captured, "body-secret"));
    CHECK(!strstr(captured, "header-secret"));
    CHECK(!strstr(captured, "response-token-secret"));
    CHECK(!strstr(captured, "cookie-secret"));
    CHECK(!strstr(captured, "bmc.example.com"));

    configure(BC_LOG_LEVEL_WARN, BC_LOG_CATEGORY_ALL);
    clear();
    CHECK(bc_http_submit(first, &request, completion, NULL, &pending) == BC_OK);
    state.done(state.arg, &response.auth.response.base);
    CHECK(bc_context_poll(context, 0) == BC_OK);
    bc_request_release(pending);
    CHECK(records == 0);

    configure(BC_LOG_LEVEL_DEBUG, BC_LOG_CATEGORY_HTTP);
    clear();
    CHECK(bc_http_submit(first, &request, completion, NULL, &pending) == BC_OK);
    state.done(state.arg, &response.auth.response.base);
    CHECK(bc_context_poll(context, 0) == BC_OK);
    bc_request_release(pending);
    CHECK(has("category=2") && !has("category=1"));

    configure(BC_LOG_LEVEL_DEBUG, BC_LOG_CATEGORY_ALL);
    clear();
    BC_LOG_VERBOSE(BC_LOG_CATEGORY_IPMI, "test.verbose", "netfn=0x06 cmd=0x47 data=<redacted>");
    CHECK(records == 0);
    configure(BC_LOG_LEVEL_VERBOSE, BC_LOG_CATEGORY_ALL);
    clear();
    BC_LOG_VERBOSE(BC_LOG_CATEGORY_IPMI, "test.verbose", "netfn=0x06 cmd=0x47 data=<redacted>");
    CHECK(records == 1 && has("event=test.verbose") && has("data=<redacted>"));

    configure(BC_LOG_LEVEL_VERBOSE, BC_LOG_CATEGORY_REDFISH);
    clear();
    static const char action_body[] =
        "{\"Password\":\"redfish-secret\",\"ResetType\":\"On\","
        "\"Image\":\"https://user:pass@example.invalid/secret?token=url-secret\","
        "\"Oem\":{\"Pwd\":\"alias-password\",\"LoginPWD\":\"login-password\",\"Passcode\":\"passcode-secret\",\"VendorValue\":\"visible\"}}";
    bc_redfish_options redfish_options = {sizeof(redfish_options), BC_ABI_VERSION, 1000, 4};
    bc_redfish_operation *operation = NULL;
    static const char action_path[] = "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset";
    CHECK(bc_redfish_action(first, (bc_string){action_path, sizeof(action_path) - 1},
        (bc_bytes){(const uint8_t *)action_body, sizeof(action_body) - 1}, &redfish_options,
        redfish_done, NULL, &operation) == BC_OK);
    CHECK(has("event=redfish.request") && has("\"ResetType\":\"On\"") && has("\"VendorValue\":\"visible\""));
    CHECK(has("<redacted>") && has("<redacted-url>") && has("redacted=1"));
    CHECK(!strstr(captured, "redfish-secret") && !strstr(captured, "user:pass") && !strstr(captured, "url-secret"));
    CHECK(!has("alias-password") && !has("login-password") && !has("passcode-secret"));
    CHECK(bc_redfish_cancel(operation) == BC_OK);
    CHECK(bc_context_poll(context, 0) == BC_OK);
    bc_redfish_release(operation);

    clear();
    char nested[256];size_t used=0;
    for(unsigned i=0;i<40;++i)nested[used++]='[';
    static const char hidden[]="\"hidden-deep-value\"";
    memcpy(nested+used,hidden,sizeof(hidden)-1);used+=sizeof(hidden)-1;
    for(unsigned i=0;i<40;++i)nested[used++]=']';
    CHECK(bc_redfish_action(first,(bc_string){action_path,sizeof(action_path)-1},
        (bc_bytes){(const uint8_t *)nested,used},&redfish_options,redfish_done,NULL,&operation)==BC_OK);
    CHECK(has("<redacted>")&&!has("hidden-deep-value"));
    CHECK(bc_redfish_cancel(operation)==BC_OK);
    CHECK(bc_context_poll(context,0)==BC_OK);
    bc_redfish_release(operation);

    char path[64];
    CHECK(bc_log_path(path, sizeof(path), "/a/b?secret=1", 13) == 1);
    CHECK(!strcmp(path, "/a/b..."));
    char hex[5];
    CHECK(bc_log_hex(hex, sizeof(hex), (const uint8_t *)"\x01\xab\xff", 3, 3) == 2);
    CHECK(!strcmp(hex, "01ab"));

    configure(BC_LOG_LEVEL_OFF, BC_LOG_CATEGORY_ALL);
    clear();
    bc_log_emitf(BC_LOG_LEVEL_ERROR, BC_LOG_CATEGORY_HTTP, "test.off", "value=1");
    CHECK(records == 0);

    bc_endpoint_release(second); bc_endpoint_release(first);
    CHECK(bc_context_destroy(context) == BC_OK);
    puts("logging: gating, redaction, verbose and path helpers passed");
    return 0;
}

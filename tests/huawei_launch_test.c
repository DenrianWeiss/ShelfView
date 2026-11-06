#include "bcontrol/huawei_launch.h"
#include "bcontrol/transport.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bc_transport_done done; void *arg;
    unsigned submits, callbacks, cancels, closes, stage, fail_at;
    uint32_t contract, mode; uint64_t now, started;
} mock;
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static const char *export_uri = "/redfish/v1/Managers/Blade3/KvmService/Actions/KvmService.ExportKvmStartupFile";
static const char *download_uri = "/redfish/v1/Managers/Blade3/Actions/Oem/Huawei/Manager.GeneralDownload";
static const char *jnlp = "<jnlp><applet-desc><param name='IPA' value='metadata.example'/>"
    "<param name='port' value='2198'/><param name='verifyValue' value='-123'/>"
    "<param name='decrykey' value='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'/></applet-desc></jnlp>";
static uint64_t now(void *u) { return ((mock *)u)->now; }
static bc_status opened(void *u, const bc_endpoint_options *o, void **out) {
    (void)u; (void)o; *out = malloc(1); return *out ? BC_OK : BC_NO_MEMORY;
}
static void closed(void *u, void *p) { ++((mock *)u)->closes; free(p); }
static bc_status submitted(void *u, void *endpoint, const bc_http_options *o, uint64_t limit,
    bc_transport_done done, void *arg, void **out) {
    (void)endpoint; (void)limit; mock *m = u;
    const char *mode = m->mode == BC_HUAWEI_MODE_PRIVATE ? "Private" : "Shared";
    char body[256];
    if (m->stage) snprintf(body, sizeof(body),
        "{\"TransferProtocol\":\"HTTPS\",\"Path\":\"/tmp/web/kvm000102030405060708090a0b0c0d0e0f_kvm.jnlp\"}");
    else if (m->contract == BC_HUAWEI_LAUNCH_EXPORT_DIRECT)
        snprintf(body, sizeof(body), "{\"Mode\":\"%s\"}", mode);
    else snprintf(body, sizeof(body), "{\"Type\":\"URI\",\"Content\":\"/tmp/web/kvm000102030405060708090a0b0c0d0e0f_kvm.jnlp\",\"Mode\":\"%s\"}", mode);
    assert(o->method == BC_HTTP_POST && o->timeout_ms == 1000 - (m->now - m->started));
    assert(o->body.length == strlen(body) && !memcmp(o->body.data, body, strlen(body)));
    const char *path = m->stage ? download_uri : export_uri;
    assert(o->path.length == strlen(path) && !memcmp(o->path.data, path, strlen(path)));
    assert(o->content_type.length == strlen("application/json"));
    ++m->submits; ++m->stage;
    if (m->fail_at == m->stage) return BC_IO_ERROR;
    m->done = done; m->arg = arg; *out = m; return BC_OK;
}
static void cancelled(void *u, void *operation) { (void)operation; mock *m = u; ++m->cancels; m->done = NULL; }
static bc_status polled(void *u, uint32_t ms) { (void)u; (void)ms; return BC_OK; }
static void completed(bc_huawei_launch *op, void *u) { (void)op; ++((mock *)u)->callbacks; }
static bc_endpoint *endpoint(bc_context *c, const char *origin) {
    bc_endpoint_options o = {0}; o.struct_size = sizeof(o); o.abi_version = BC_ABI_VERSION;
    o.origin = text(origin); o.device_id = text("fixture"); o.endpoint_id = text("launch");
    bc_endpoint *e = NULL; assert(bc_endpoint_create(c, &o, &e) == BC_OK); return e;
}
static bc_huawei_launch_options options(mock *m, uint32_t contract) {
    bc_huawei_launch_options o = {0}; o.struct_size = sizeof(o); o.abi_version = BC_ABI_VERSION;
    o.contract = contract; o.timeout_ms = 1000; o.modes = BC_HUAWEI_MODE_SHARED;
    o.export_uri = text(export_uri); o.generation = 42; o.clock_ms = now; o.clock_user = m;
    if (contract == BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD) {
        o.download_uri = text(download_uri); o.nonce = text("000102030405060708090a0b0c0d0e0f");
    }
    m->now = m->started = 100; m->contract = contract; m->mode = BC_HUAWEI_MODE_SHARED;
    m->stage = 0; m->fail_at = 0; return o;
}
static bc_huawei_launch *start(mock *m, bc_endpoint *e, uint32_t contract) {
    bc_huawei_launch_options o = options(m, contract); bc_huawei_launch *op = NULL;
    assert(bc_huawei_launch_start(e, &o, completed, m, &op) == BC_OK);
    assert(!bc_huawei_launch_result_get(op, e, 42)); return op;
}
static void queue(mock *m, const char *body, uint32_t http, bc_status status) {
    bc_response r = {0}; r.struct_size = sizeof(r); r.status = status; r.http_status = http;
    r.body = (bc_bytes){(const uint8_t *)body, strlen(body)};
    bc_transport_done done = m->done; m->done = NULL; done(m->arg, &r);
}
static void respond(mock *m, bc_context *c, const char *body, uint32_t http, bc_status status) {
    queue(m, body, http, status); assert(bc_context_poll(c, 0) == BC_OK);
}
static const char *mode_rejected = "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{"
    "\"MessageId\":\"Base.1.18.ActionParameterValueNotInList\","
    "\"MessageArgs\":[\"Shared\",\"Mode\",\"KvmService.ExportKvmStartupFile\"]}]}}";
static void respond_details(mock *m, bc_context *context, const char *body, uint32_t http,
    bc_status status, const char *location, const char *token) {
    bc_transport_auth_response response = {0};
    response.response.base.struct_size = sizeof(response);
    response.response.base.status = status; response.response.base.http_status = http;
    response.response.base.body = (bc_bytes){(const uint8_t *)body, strlen(body)};
    response.response.metadata.struct_size = sizeof(bc_http_metadata);
    response.response.metadata.location = text(location); response.auth_token = text(token);
    bc_transport_done done = m->done; m->done = NULL; done(m->arg, &response.response.base);
    assert(bc_context_poll(context, 0) == BC_OK);
}
static void private_eligibility(mock *m, bc_context *context, bc_endpoint *endpoint) {
    bc_huawei_launch *op = start(m, endpoint, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
    respond_details(m, context, mode_rejected, 400, BC_HTTP_ERROR, "", "");
    const bc_huawei_launch_result *r = bc_huawei_launch_result_get(op, endpoint, 42);
    assert(r->status == BC_UNSUPPORTED && r->flags == 5 && m->stage == 1);
    assert(bc_huawei_launch_private_eligible(&r->failure, r->flags, 3, 0));
    assert(!bc_huawei_launch_private_eligible(&r->failure, r->flags, 1, 0));
    assert(!bc_huawei_launch_private_eligible(&r->failure, r->flags, 3, 1));
    assert(!bc_huawei_launch_private_eligible(&r->failure, r->flags | 2, 3, 0));
    bc_console_failure failure = r->failure; failure.cause = BC_CONSOLE_CAUSE_BUSY;
    assert(!bc_huawei_launch_private_eligible(&failure, r->flags, 3, 0));
    bc_huawei_launch_release(op);
    const char *bad[] = {
        "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"OEM.1.18.ActionParameterValueNotInList\",\"MessageArgs\":[\"Shared\",\"Mode\",\"KvmService.ExportKvmStartupFile\"]}]}}",
        "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.9.ActionParameterValueNotInList\",\"MessageArgs\":[\"Shared\",\"Mode\",\"KvmService.ExportKvmStartupFile\"]}]}}",
        "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.18.ActionParameterValueNotInList\",\"MessageArgs\":[\"Private\",\"Mode\",\"KvmService.ExportKvmStartupFile\"]}]}}",
        "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.18.ActionParameterValueNotInList\",\"MessageArgs\":[\"Shared\",\"Type\",\"KvmService.ExportKvmStartupFile\"]}]}}",
        "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.18.ActionParameterValueNotInList\",\"MessageArgs\":[\"Shared\",\"Mode\",\"ExportKvmStartupFile\"]}]}}",
        "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.18.ActionParameterValueNotInList\",\"MessageArgs\":[\"Shared\",\"Mode\",\"Other.ExportKvmStartupFile\"]}]}}",
        "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.18.ActionParameterValueNotInList\",\"MessageArgs\":[\"Shared\",\"Mode\",\"KvmService.ExportKvmStartupFile\"]},{\"MessageId\":\"Base.1.18.InsufficientPrivilege\"}]}}",
        "{\"error\":{\"code\":\"Base.1.18.InsufficientPrivilege\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.18.ActionParameterValueNotInList\",\"MessageArgs\":[\"Shared\",\"Mode\",\"KvmService.ExportKvmStartupFile\"]}]}}",
        "{\"error\":{\"code\":\"Base.1.18.GeneralError\",\"@Message.ExtendedInfo\":[{\"MessageId\":\"Base.1.18.ActionParameterValueNotInList\",\"MessageId\":\"Base.1.18.InsufficientPrivilege\",\"MessageArgs\":[\"Shared\",\"Mode\",\"KvmService.ExportKvmStartupFile\"]}]}}"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        op = start(m, endpoint, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
        respond_details(m, context, bad[i], 400, BC_HTTP_ERROR, "", "");
        r = bc_huawei_launch_result_get(op, endpoint, 42);
        assert(!bc_huawei_launch_private_eligible(&r->failure, r->flags, 3, 0) && r->flags == 1);
        bc_huawei_launch_release(op);
    }
    for (size_t length = 0; length < strlen(mode_rejected); ++length) {
        char body[512]; memcpy(body, mode_rejected, length); body[length] = 0;
        op = start(m, endpoint, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
        respond_details(m, context, body, 400, BC_HTTP_ERROR, "", "");
        r = bc_huawei_launch_result_get(op, endpoint, 42); assert(r->flags == 1);
        bc_huawei_launch_release(op);
    }
    const uint32_t statuses[] = {401, 403, 409, 423, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        op = start(m, endpoint, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
        respond_details(m, context, mode_rejected, statuses[i], BC_HTTP_ERROR, "", "");
        r = bc_huawei_launch_result_get(op, endpoint, 42); assert(r->flags == 1);
        bc_huawei_launch_release(op);
    }
    for (unsigned i = 0; i < 3; ++i) {
        op = start(m, endpoint, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
        respond_details(m, context, mode_rejected, 400, i ? BC_HTTP_ERROR : BC_OUTCOME_UNKNOWN,
            i == 1 ? "/session/uncertain" : "", i == 2 ? "unknown-token" : "");
        r = bc_huawei_launch_result_get(op, endpoint, 42); assert(r->flags == 1);
        bc_huawei_launch_release(op);
    }
}
int main(void) {
    const char *metadata[] = {
        "{\"@odata.type\":\"#ActionInfo.v1_0_0.ActionInfo\",\"Parameters\":[{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"Shared\",\"Private\"]}]}",
        "{\"@odata.type\":\"#ActionInfo.v1_0_0.ActionInfo\",\"Parameters\":[{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"Shared\"]},{\"Name\":\"Type\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"URI\"]},{\"Name\":\"Content\",\"Required\":true,\"DataType\":\"String\"}]}"
    };
    for (size_t i = 0; i < 2; ++i) {
        uint32_t format = 99, modes = 99;
        assert(bc_huawei_launch_request_format((const uint8_t *)metadata[i], (uint32_t)strlen(metadata[i]),
            &format, &modes) == BC_OK);
        assert(format == (i ? BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD : BC_HUAWEI_LAUNCH_EXPORT_DIRECT));
        assert(modes == (i ? 1 : 3));
        for (size_t n = 0; n < strlen(metadata[i]); ++n) {
            assert(bc_huawei_launch_request_format((const uint8_t *)metadata[i], (uint32_t)n,
                &format, &modes) != BC_OK);
            assert(!format && !modes);
        }
    }

    char invalid[2048];
    const char *values[] = {"URL", "BAD"};
    for (size_t i = 0; i < 2; ++i) {
        strcpy(invalid, metadata[1]);
        char *value = strstr(invalid, "URI"); assert(value); memcpy(value, values[i], 3);
        uint32_t format = 99, modes = 99;
        assert(bc_huawei_launch_request_format((const uint8_t *)invalid, (uint32_t)strlen(invalid),
            &format, &modes) == BC_UNSUPPORTED && !format && !modes);
    }
    uint32_t format = 99, modes = 99;
    assert(bc_huawei_launch_request_format(NULL, 0, &format, &modes) == BC_INVALID_ARGUMENT && !format && !modes);
    mock m = {0}; bc_transport t = {sizeof(t), BC_ABI_VERSION, &m, opened, closed, submitted, cancelled, polled, NULL};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &t, 65536, 4, 0}; bc_context *c = NULL;
    assert(bc_context_create(&co, &c) == BC_OK);
    bc_endpoint *e = endpoint(c, "https://bmc.example"), *other = endpoint(c, "https://bmc.example");
    private_eligibility(&m, c, e);
    bc_huawei_launch *op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
    unsigned callbacks = m.callbacks; respond(&m, c, jnlp, 200, BC_OK);
    const bc_huawei_launch_result *r = bc_huawei_launch_result_get(op, e, 42);
    assert(m.callbacks == callbacks + 1 && m.stage == 1 && r->status == BC_OK && r->flags == 3);
    assert(r->descriptor && r->descriptor->format == BC_CONSOLE_DESCRIPTOR_HUAWEI);
    assert(bc_service_profile_can_attempt(&r->descriptor->profile, BC_SERVICE_KVM));
    assert(!bc_service_profile_can_attempt(&r->descriptor->profile, BC_SERVICE_LOCAL_MEDIA));
    assert(!bc_huawei_launch_result_get(op, other, 42) && !bc_huawei_launch_result_get(op, e, 43));
    assert(bc_huawei_launch_cancel(op) == BC_OK && r->status == BC_CANCELLED && !r->descriptor);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); callbacks = m.callbacks; m.now = 400;
    respond(&m, c, "{}", 201, BC_OK); assert(m.stage == 2 && m.callbacks == callbacks);
    m.now = 450; respond(&m, c, jnlp, 200, BC_OK); r = bc_huawei_launch_result_get(op, e, 42);
    assert(r->status == BC_OK && r->descriptor && m.callbacks == callbacks + 1); bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD);
    respond(&m, c, jnlp, 200, BC_OK); r = bc_huawei_launch_result_get(op, e, 42);
    assert(r->status == BC_OK && r->descriptor && m.stage == 1);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD);
    respond(&m, c, "<html>login</html>", 200, BC_OK); r = bc_huawei_launch_result_get(op, e, 42);
    assert(r->status == BC_PROTOCOL_ERROR && !r->descriptor && m.stage == 1);
    bc_huawei_launch_release(op);
    const uint32_t http[] = {401, 403, 409, 202, 204};
    for (size_t i = 0; i < sizeof(http) / sizeof(http[0]); ++i) {
        op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); respond(&m, c, "{}", http[i], BC_HTTP_ERROR);
        r = bc_huawei_launch_result_get(op, e, 42); assert(r->status != BC_OK && !r->descriptor && m.stage == 1);
        if (http[i] == 401 || http[i] == 403) assert(r->failure.cause == BC_CONSOLE_CAUSE_AUTH_REJECTED);
        bc_huawei_launch_release(op);
    }
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); respond(&m, c, "", 0, BC_OUTCOME_UNKNOWN);
    r = bc_huawei_launch_result_get(op, e, 42); assert(r->status == BC_OUTCOME_UNKNOWN && r->flags == 1 && m.stage == 1);
    bc_huawei_launch_release(op);
    const uint64_t times[] = {1100, 99};
    for (size_t i = 0; i < 2; ++i) {
        op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); m.now = times[i]; respond(&m, c, "{}", 200, BC_OK);
        r = bc_huawei_launch_result_get(op, e, 42); assert(r->status != BC_OK && r->flags == 3 && m.stage == 1);
        bc_huawei_launch_release(op);
    }
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); m.fail_at = 2; respond(&m, c, "{}", 201, BC_OK);
    r = bc_huawei_launch_result_get(op, e, 42); assert(r->status == BC_IO_ERROR && !r->http_status && r->flags == 3);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); assert(bc_huawei_launch_cancel(op) == BC_OK);
    assert(bc_context_poll(c, 0) == BC_OK); r = bc_huawei_launch_result_get(op, e, 42);
    assert(r->status == BC_CANCELLED && r->flags == 1 && m.stage == 1); bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); queue(&m, "{}", 201, BC_OK);
    assert(bc_huawei_launch_cancel(op) == BC_OK && bc_context_poll(c, 0) == BC_OK);
    r = bc_huawei_launch_result_get(op, e, 42); assert(r->status == BC_CANCELLED && r->flags == 3 && m.stage == 1);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DIRECT); respond(&m, c, "<html>login</html>", 200, BC_OK);
    r = bc_huawei_launch_result_get(op, e, 42); assert(r->status == BC_PROTOCOL_ERROR && !r->descriptor);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
    respond(&m, c, "{\"token\":\"fixture\",\"session\":\"1\",\"client_ip\":\"192.0.2.2\",\"server_ip\":\"192.0.2.1\"}", 200, BC_OK);
    r = bc_huawei_launch_result_get(op, e, 42); assert(r->status == BC_PROTOCOL_ERROR && !r->descriptor);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DIRECT); respond(&m, c, jnlp, 201, BC_OK);
    r = bc_huawei_launch_result_get(op, e, 42); assert(r->status == BC_HTTP_ERROR && r->flags == 1);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); respond(&m, c, "{}", 200, BC_OK);
    respond(&m, c, "{}", 403, BC_HTTP_ERROR); r = bc_huawei_launch_result_get(op, e, 42);
    assert(r->status == BC_AUTHENTICATION_FAILED && r->failure.http_status == 403 && r->flags == 3);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); respond(&m, c, "{}", 200, BC_OK);
    assert(bc_huawei_launch_cancel(op) == BC_OK && bc_context_poll(c, 0) == BC_OK);
    r = bc_huawei_launch_result_get(op, e, 42); assert(r->status == BC_CANCELLED && !r->descriptor && m.stage == 2);
    bc_huawei_launch_release(op);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); bc_huawei_launch_release(op);
    respond(&m, c, "{}", 200, BC_OK); respond(&m, c, jnlp, 200, BC_OK);
    bc_huawei_launch_options o = options(&m, BC_HUAWEI_LAUNCH_EXPORT_DIRECT); unsigned submits = m.submits;
    o.modes = BC_HUAWEI_MODE_PRIVATE;
    assert(bc_huawei_launch_start(e, &o, completed, &m, &op) == BC_UNSUPPORTED && !op);
    o.modes = BC_HUAWEI_MODE_SHARED; o.contract = 99;
    assert(bc_huawei_launch_start(e, &o, completed, &m, &op) == BC_UNSUPPORTED && !op);
    o = options(&m, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD);
    o.download_uri = text("/redfish/v1/Managers/Blade4/Actions/Oem/Huawei/Manager.GeneralDownload");
    assert(bc_huawei_launch_start(e, &o, completed, &m, &op) == BC_INVALID_ARGUMENT && !op);
    o = options(&m, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD); o.nonce = text("bad");
    assert(bc_huawei_launch_start(e, &o, completed, &m, &op) == BC_INVALID_ARGUMENT && !op);
    bc_endpoint *insecure = endpoint(c, "http://bmc.example");
    o = options(&m, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
    assert(bc_huawei_launch_start(insecure, &o, completed, &m, &op) == BC_UNSUPPORTED && !op);
    bc_endpoint_release(insecure);
    assert(m.submits == submits);
    const uint32_t contracts[] = {BC_HUAWEI_LAUNCH_EXPORT_DIRECT, BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD};
    for (size_t i = 0; i < 2; ++i) {
        o = options(&m, contracts[i]); o.modes = BC_HUAWEI_MODE_PRIVATE; m.mode = BC_HUAWEI_MODE_PRIVATE;
        submits = m.submits; callbacks = m.callbacks;
        assert(bc_huawei_launch_start_private(e, &o, 0, completed, &m, &op) == BC_CONFIRMATION_REQUIRED && !op);
        assert(bc_huawei_launch_start_private(e, &o, 2, completed, &m, &op) == BC_INVALID_ARGUMENT && !op);
        assert(m.submits == submits && m.callbacks == callbacks);
        assert(bc_huawei_launch_start_private(e, &o, 1, completed, &m, &op) == BC_OK);
        if (contracts[i] == BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD) respond(&m, c, "{}", 200, BC_OK);
        respond(&m, c, jnlp, 200, BC_OK); r = bc_huawei_launch_result_get(op, e, 42);
        assert(r && r->status == BC_OK); bc_huawei_launch_release(op);
        submits = m.submits;
        assert(bc_huawei_launch_start_private(e, &o, 0, completed, &m, &op) == BC_CONFIRMATION_REQUIRED && !op);
        assert(m.submits == submits); /* Prior success never authorizes another Private attempt. */
    }
    o = options(&m, BC_HUAWEI_LAUNCH_EXPORT_DIRECT); submits = m.submits;
    assert(bc_huawei_launch_start_private(e, &o, 1, completed, &m, &op) == BC_UNSUPPORTED && !op);
    assert(m.submits == submits);
    op = start(&m, e, BC_HUAWEI_LAUNCH_EXPORT_DIRECT);
    respond(&m, c, jnlp, 200, BC_OK); bc_huawei_launch_release(op);
    bc_endpoint_release(e); bc_endpoint_release(other); assert(bc_context_destroy(c) == BC_OK && m.closes == 3);
    return 0;
}

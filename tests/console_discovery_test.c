#include "bcontrol/console_discovery.h"
#include "bcontrol/transport.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct { bc_transport_done done; void *arg; unsigned submits, callbacks, cancels, closes, method; } mock;
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static bc_status opened(void *u, const bc_endpoint_options *o, void **out) {
    (void)u; (void)o; *out = malloc(1); return *out ? BC_OK : BC_NO_MEMORY;
}
static void closed(void *u, void *p) { ++((mock *)u)->closes; free(p); }
static bc_status submitted(void *u, void *e, const bc_http_options *o, uint64_t limit,
    bc_transport_done done, void *arg, void **out) {
    (void)e; (void)limit; mock *m = u;
    assert(o->method == m->method && o->timeout_ms == 100);
    assert(o->body.length == (m->method == BC_HTTP_POST ? 2u : 0u));
    assert(o->path.length == 7 && !memcmp(o->path.data, "/launch", 7));
    assert(o->header_count == 1 && o->headers[0].length == strlen("X-CSRFTOKEN: fixture-only"));
    assert(!memcmp(o->headers[0].data, "X-CSRFTOKEN: fixture-only", (size_t)o->headers[0].length));
    ++m->submits; m->done = done; m->arg = arg; *out = m; return BC_OK;
}
static void cancelled(void *u, void *p) { (void)p; ++((mock *)u)->cancels; }
static bc_status polled(void *u, uint32_t ms) { (void)u; (void)ms; return BC_OK; }
static void completed(bc_console_discovery *op, void *u) { (void)op; ++((mock *)u)->callbacks; }
static void request_completed(bc_request *request, const bc_response *response, void *u) {
    (void)request; (void)response; ++((mock *)u)->callbacks;
}
static bc_endpoint *endpoint_at(bc_context *c, const char *origin) {
    bc_endpoint_options o = {0}; o.struct_size = sizeof(o); o.abi_version = BC_ABI_VERSION;
    o.origin = text(origin); o.device_id = text("fixture"); o.endpoint_id = text("launch");
    bc_endpoint *e = NULL; assert(bc_endpoint_create(c, &o, &e) == BC_OK); return e;
}
static bc_console_discovery *start(bc_endpoint *e, mock *m) {
    bc_string header = text("X-CSRFTOKEN: fixture-only");
    bc_console_discovery_options o = {sizeof(o), BC_ABI_VERSION, {"/launch", 7}, 42, 100, &header, 1};
    bc_console_discovery *op = NULL;
    assert(bc_console_discovery_start(e, &o, completed, m, &op) == BC_OK);
    assert(!bc_console_discovery_result_get(op, e, 42)); return op;
}
static void respond(mock *m, bc_context *c, const char *body, uint32_t http) {
    unsigned before = m->callbacks;
    bc_response r = {0}; r.struct_size = sizeof(r); r.status = http < 400 ? BC_OK : BC_HTTP_ERROR;
    r.http_status = http; r.body = (bc_bytes){(const uint8_t *)body, strlen(body)};
    m->done(m->arg, &r); assert(m->callbacks == before);
    assert(bc_context_poll(c, 0) == BC_OK && m->callbacks == before + 1);
}
static bc_status metadata_links(const char *json, uint32_t capacity, bc_console_metadata_link *links, uint32_t *count) {
    return bc_console_manager_metadata_links((const uint8_t *)json, (uint32_t)strlen(json),
        text("/redfish/v1/Managers/opaque"), links, capacity, count);
}
static void check_metadata_links(void) {
    bc_console_metadata_link links[2]; uint32_t count = 99;
    const char *trailing = "{\"@odata.id\":\"/redfish/v1/Managers/1/\",\"Oem\":{\"KvmService\":{\"@odata.id\":\"/redfish/v1/Managers/1/KvmService/\"}}}";
    assert(bc_console_manager_metadata_links((const uint8_t *)trailing, (uint32_t)strlen(trailing),
        text("/redfish/v1/Managers/1/"), links, 2, &count) == BC_OK && count == 1);
    assert(!strcmp(links[0].uri, "/redfish/v1/Managers/1/KvmService/"));
    assert(bc_console_manager_metadata_links((const uint8_t *)trailing, (uint32_t)strlen(trailing),
        text("/redfish/v1/Managers/2/"), links, 2, &count) == BC_PROTOCOL_ERROR && !count);
    assert(bc_console_manager_metadata_links((const uint8_t *)trailing, (uint32_t)strlen(trailing),
        text("/redfish/v1/Managers/1//"), links, 2, &count) == BC_INVALID_ARGUMENT && !count);
    const char *valid = "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"Oem\":{\"UnrelatedNamespace\":{"
        "\"KvmService\":{\"@odata.id\":\"/redfish/v1/Managers/opaque/KvmService\"},"
        "\"Attributes\":{\"@odata.id\":\"/redfish/v1/Managers/opaque/Attributes\"}}}}";
    assert(metadata_links(valid, 2, links, &count) == BC_OK && count == 2);
    assert(links[0].kind == BC_CONSOLE_METADATA_KVM && links[1].kind == BC_CONSOLE_METADATA_ATTRIBUTES);
    assert(!strcmp(links[0].uri, "/redfish/v1/Managers/opaque/KvmService"));
    const char *array = "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"Links\":{\"Oem\":{\"Dell\":{"
        "\"DellAttributes\":[{\"@odata.id\":\"/redfish/v1/Managers/opaque/Attributes\"},"
        "{\"@odata.id\":\"/redfish/v1/Managers/opaque/Oem/Dell/DellAttributes/System\"},"
        "{\"@odata.id\":\"/redfish/v1/Managers/opaque/Attributes\"}]}}}}";
    assert(metadata_links(array, 2, links, &count) == BC_OK && count == 2);
    assert(links[0].kind == BC_CONSOLE_METADATA_ATTRIBUTES && links[1].kind == BC_CONSOLE_METADATA_ATTRIBUTES);
    assert(!strcmp(links[0].uri, "/redfish/v1/Managers/opaque/Attributes"));
    assert(metadata_links(array, 1, links, &count) == BC_LIMIT_EXCEEDED && !count);
    const char *bad_arrays[] = {
        "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"DellAttributes\":[[]]}",
        "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"DellAttributes\":[null]}",
        "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"DellAttributes\":[{\"@odata.id\":\"https://foreign.example/\"}]}"
    };
    for (size_t i = 0; i < sizeof(bad_arrays) / sizeof(bad_arrays[0]); ++i)
        assert(metadata_links(bad_arrays[i], 2, links, &count) == BC_PROTOCOL_ERROR && !count);
    const char *casing = "{\"@odata.id\":\"/redfish/v1/managers/opaque\","
        "\"KvmService\":{\"@odata.id\":\"/redfish/v1/MANAGERS/opaque/kvmservice\"},"
        "\"Attributes\":{\"@odata.id\":\"/redfish/v1/managers/opaque/attributes\"}}";
    assert(metadata_links(casing, 2, links, &count) == BC_OK && count == 2);
    assert(!strcmp(links[0].uri, "/redfish/v1/MANAGERS/opaque/kvmservice"));
    assert(!strcmp(links[1].uri, "/redfish/v1/managers/opaque/attributes"));
    assert(metadata_links(valid, 1, links, &count) == BC_LIMIT_EXCEEDED && !count && !links[0].kind);
    const char *ignored = "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"Manufacturer\":\"Dell Huawei MegaRAC\","
        "\"Actions\":{\"KvmService\":{\"@odata.id\":\"https://foreign.example\"}}}";
    assert(metadata_links(ignored, 2, links, &count) == BC_OK && !count);
    const char *bad[] = {
        "{\"@odata.id\":\"/redfish/v1/managers/Opaque\"}",
        "{\"@odata.id\":\"/redfish/v1/Managers/other\"}",
        "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"@odata.id\":\"/redfish/v1/Managers/opaque\"}",
        "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"Attributes\":{},\"Attributes\":{}}"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(metadata_links(bad[i], 2, links, &count) == BC_PROTOCOL_ERROR && !count && !links[0].kind);
    const char *paths[] = {"https://foreign.example/", "/redfish/v1/Managers/other/KvmService",
        "/redfish/v1/Managers/opaque2/KvmService", "/redfish/v1/Managers/opaque/../KvmService",
        "/redfish/v1/Managers/opaque/%4bvmService", "/redfish/v1/Managers/opaque/KvmService?x=1",
        "/redfish/v1/Managers/opaque/Kvm\\u0000Service"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        char json[512];
        snprintf(json, sizeof(json), "{\"@odata.id\":\"/redfish/v1/Managers/opaque\",\"KvmService\":{\"@odata.id\":\"%s\"}}", paths[i]);
        assert(metadata_links(json, 2, links, &count) == BC_PROTOCOL_ERROR && !count);
    }
}
int main(void) {
    check_metadata_links();
    mock m = {0};
    bc_transport t = {sizeof(t), BC_ABI_VERSION, &m, opened, closed, submitted, cancelled, polled, NULL};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &t, 65536, 4, 0};
    bc_context *c = NULL, *other = NULL;
    assert(bc_context_create(&co, &c) == BC_OK && bc_context_create(&co, &other) == BC_OK);
    bc_endpoint *e = endpoint_at(c, "https://bmc.example"), *foreign = endpoint_at(other, "https://bmc.example");
    assert(bc_endpoint_revision(e) == bc_endpoint_revision(foreign));
    assert(!strcmp(bc_endpoint_origin(e).data, "https://bmc.example"));
    const char *h5 = "{\"token\":\"fixture\",\"session\":\"1\",\"client_ip\":\"192.0.2.2\","
        "\"server_ip\":\"192.0.2.1\",\"description\":\"Huawei Dell EXPRESSSCOPE Engine 3\"}";
    bc_console_discovery *op = start(e, &m); respond(&m, c, h5, 200);
    assert(!bc_console_discovery_result_get(op, foreign, 42));
    assert(!bc_console_discovery_result_get(op, e, 43));
    const bc_console_discovery_result *r = bc_console_discovery_result_get(op, e, 42);
    assert(r && r->state == BC_CONSOLE_DISCOVERY_READY && r->format == BC_CONSOLE_DESCRIPTOR_H5);
    assert(bc_service_profile_can_attempt(&r->profile, BC_SERVICE_KVM));
    assert(!bc_service_profile_can_attempt(&r->profile, BC_SERVICE_LOCAL_MEDIA));
    assert(!bc_service_profile_verified(&r->profile, BC_SERVICE_KVM));
    assert(!strcmp(r->megarac.token, "fixture"));
    assert(bc_console_discovery_cancel(op) == BC_OK && r->status == BC_CANCELLED && !r->megarac.token[0]);
    bc_console_discovery_release(op);

    const char *avocent = "<jnlp><information><title>Dell MegaRAC HPE</title></information>"
        "<application-desc main-class='com.avocent.kvm.client.Main'>"
        "<argument>ip=metadata.example</argument><argument>user=fixture</argument><argument>passwd=token</argument>"
        "<argument>kmport=2068</argument><argument>vport=2069</argument><argument>apcp=1</argument>"
        "</application-desc></jnlp>";
    op = start(e, &m); respond(&m, c, avocent, 200); r = bc_console_discovery_result_get(op, e, 42);
    assert(r->format == BC_CONSOLE_DESCRIPTOR_AVOCENT && r->profile.family == BC_SERVICE_FAMILY_AVOCENT);
    assert(!bc_service_profile_can_attempt(&r->profile, BC_SERVICE_KVM));
    const bc_avocent_launch *a = bc_console_discovery_avocent_get(op, e, 42);
    assert(a && a->video_port == 2069 && !strcmp(a->password, "token"));
    assert(!bc_console_discovery_avocent_get(op, foreign, 42) && !bc_console_discovery_avocent_get(op, e, 43));
    assert(bc_console_discovery_cancel(op) == BC_OK && !a->password[0]);
    assert(!bc_console_discovery_avocent_get(op, e, 42));
    bc_console_discovery_release(op);

    const char *jnlp = "<jnlp><application-desc><argument>-hostname</argument><argument>metadata.example</argument>"
        "<argument>-kvmtoken</argument><argument>fixture</argument><argument>-kvmport</argument><argument>7582</argument>"
        "<argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>";
    op = start(e, &m); respond(&m, c, jnlp, 200); r = bc_console_discovery_result_get(op, e, 42);
    assert(r->format == BC_CONSOLE_DESCRIPTOR_JVIEWER && !r->profile.variant && !r->megarac.kind);
    assert(!bc_service_profile_can_attempt(&r->profile, BC_SERVICE_KVM)); bc_console_discovery_release(op);
    const char *huawei = "<jnlp><applet-desc><param name='IPA' value='metadata.example'/>"
        "<param name='port' value='2198'/><param name='verifyValue' value='123'/>"
        "<param name='decrykey' value='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'/></applet-desc></jnlp>";
    op = start(e, &m); respond(&m, c, huawei, 200); r = bc_console_discovery_result_get(op, e, 42);
    assert(r->format == BC_CONSOLE_DESCRIPTOR_HUAWEI && r->profile.family == BC_SERVICE_FAMILY_HUAWEI);
    assert(bc_service_profile_can_attempt(&r->profile, BC_SERVICE_KVM)); bc_console_discovery_release(op);

    const char *query = "ip=bmc.example&kvmport=443&VCSID=fixture&VCSID2=secondary";
    const char *idrac = "{\"Location\":\"/restgui/vconsole/index.html?ip=bmc.example&kvmport=443&VCSID=fixture&VCSID2=secondary\"}";
    bc_idrac_launch_uri uri = {sizeof(uri), 0, {"https",5}, {"bmc.example",11},
        {"/restgui/vconsole/index.html",27}, {0}, 443};
    uri.path = text("/restgui/vconsole/index.html"); uri.query = text(query);
    op = start(e, &m); respond(&m, c, idrac, 200); r = bc_console_discovery_result_get(op, e, 42);
    assert(r->state == BC_CONSOLE_DISCOVERY_NEEDS_URI && !r->profile.evidence);
    assert(bc_console_discovery_resolve_idrac(op, foreign, 42, &uri, text("bmc.example"), 443) == BC_INVALID_ARGUMENT);
    assert(bc_console_discovery_resolve_idrac(op, e, 42, &uri, text("bmc.example"), 443) == BC_OK);
    assert(r->state == BC_CONSOLE_DISCOVERY_READY && r->profile.family == BC_SERVICE_FAMILY_IDRAC);
    assert(!strcmp(r->idrac.secondary_key, "secondary") && !r->location.length);
    bc_console_discovery_release(op);
    op = start(e, &m); respond(&m, c, idrac, 200); uri.query = text("ip=bmc.example&kvmport=443&VCSID=another&VCSID2=secondary");
    assert(bc_console_discovery_resolve_idrac(op, e, 42, &uri, text("bmc.example"), 443) == BC_PROTOCOL_ERROR);
    r = bc_console_discovery_result_get(op, e, 42); assert(!r->idrac.primary_key[0] && !r->profile.evidence);
    bc_console_discovery_release(op);
    const char *extra_token = "{\"token\":\"unrelated-metadata\",\"Location\":\"/restgui/vconsole/index.html?ip=bmc.example&kvmport=443&VCSID=fixture&VCSID2=secondary\"}";
    op = start(e, &m); respond(&m, c, extra_token, 200); r = bc_console_discovery_result_get(op, e, 42);
    assert(r->state == BC_CONSOLE_DISCOVERY_NEEDS_URI && !r->profile.evidence);
    bc_console_discovery_release(op);
    const char *h5_with_location = "{\"Location\":\"metadata\",\"token\":\"fixture\",\"session\":\"1\",\"client_ip\":\"192.0.2.2\",\"server_ip\":\"192.0.2.1\"}";
    op = start(e, &m); respond(&m, c, h5_with_location, 200); r = bc_console_discovery_result_get(op, e, 42);
    assert(r->state == BC_CONSOLE_DISCOVERY_READY && r->format == BC_CONSOLE_DESCRIPTOR_H5);
    bc_console_discovery_release(op);
    const char *bad[] = {"<html>Dell MegaRAC Huawei</html>", "{\"Location\":3,\"token\":\"b\"}", "{}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        op = start(e, &m); respond(&m, c, bad[i], 200); r = bc_console_discovery_result_get(op, e, 42);
        assert(r->state == BC_CONSOLE_DISCOVERY_FAILED && !r->profile.evidence);
        bc_console_discovery_release(op);
    }
    op = start(e, &m); respond(&m, c, h5, 401); r = bc_console_discovery_result_get(op, e, 42);
    assert(r->status == BC_AUTHENTICATION_FAILED && r->failure.cause == BC_CONSOLE_CAUSE_AUTH_REJECTED);
    assert(!r->profile.evidence); bc_console_discovery_release(op);
    op = start(e, &m); assert(bc_console_discovery_cancel(op) == BC_OK);
    unsigned callbacks = m.callbacks; assert(bc_context_poll(c, 0) == BC_OK && m.callbacks == callbacks + 1);
    r = bc_console_discovery_result_get(op, e, 42); assert(r->status == BC_CANCELLED && !r->profile.evidence);
    bc_console_discovery_release(op);
    op = start(e, &m);
    bc_response queued = {0}; queued.struct_size = sizeof(queued); queued.http_status = 200;
    queued.body = (bc_bytes){(const uint8_t *)h5, strlen(h5)};
    m.done(m.arg, &queued);
    assert(bc_console_discovery_cancel(op) == BC_OK);
    callbacks = m.callbacks; assert(bc_context_poll(c, 0) == BC_OK && m.callbacks == callbacks + 1);
    r = bc_console_discovery_result_get(op, e, 42); assert(r->status == BC_CANCELLED && !r->megarac.token[0]);
    bc_console_discovery_release(op);
    op = start(e, &m); bc_console_discovery_release(op);
    respond(&m, c, h5, 200); /* The in-flight callback owns the remaining reference. */
    bc_string csrf = text("X-CSRFTOKEN: fixture-only");
    bc_http_options post = {0}; post.struct_size = sizeof(post); post.abi_version = BC_ABI_VERSION;
    post.path = text("/launch"); post.method = BC_HTTP_POST; post.timeout_ms = 100;
    post.body = (bc_bytes){(const uint8_t *)"{}", 2}; post.headers = &csrf; post.header_count = 1;
    bc_request *request = NULL; m.method = BC_HTTP_POST;
    assert(bc_http_submit(e, &post, request_completed, &m, &request) == BC_OK);
    assert(bc_request_endpoint(request) == e);
    assert(bc_console_discovery_from_request(e, 50, request, &op) == BC_BUSY && !op);
    respond(&m, c, huawei, 200);
    assert(bc_console_discovery_from_request(foreign, 50, request, &op) == BC_INVALID_ARGUMENT && !op);
    unsigned submits = m.submits;
    assert(bc_console_discovery_from_request(e, 50, request, &op) == BC_OK && m.submits == submits);
    bc_request_release(request); /* The discovery object now owns a separate reference. */
    r = bc_console_discovery_result_get(op, e, 50);
    assert(r && r->format == BC_CONSOLE_DESCRIPTOR_HUAWEI && r->state == BC_CONSOLE_DISCOVERY_READY);
    assert(!bc_console_discovery_result_get(op, e, 42));
    bc_console_discovery_release(op); m.method = BC_HTTP_GET;
    bc_endpoint *insecure = endpoint_at(c, "http://bmc.example");
    op = start(insecure, &m); respond(&m, c, idrac, 200); uri.query = text(query);
    assert(bc_console_discovery_resolve_idrac(op, insecure, 42, &uri, text("bmc.example"), 443) == BC_PROTOCOL_ERROR);
    bc_console_discovery_release(op); bc_endpoint_release(insecure);
    bc_endpoint_release(e); bc_endpoint_release(foreign);
    assert(bc_context_destroy(c) == BC_OK && bc_context_destroy(other) == BC_OK && m.closes == 3);
    return 0;
}

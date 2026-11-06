#include "bcontrol/jviewer_discovery.h"
#include "bcontrol/transport.h"
#include "megarac_class_fixture.h"
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    bc_transport_done done; void *arg;
    const char *expected;
    uint32_t timeout, submits, sources, callbacks, closes, cancels, clock_calls, method, probe_callbacks;
    uint64_t now, delay;
    bc_endpoint *endpoint;
} mock;
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static bc_status opened(void *u, const bc_endpoint_options *o, void **out) {
    (void)u; (void)o; *out = malloc(1); return *out ? BC_OK : BC_NO_MEMORY;
}
static void closed(void *u, void *e) { ++((mock *)u)->closes; free(e); }
static bc_status submitted(void *u, void *e, const bc_http_options *o, uint64_t limit,
    bc_transport_done done, void *arg, void **out) {
    (void)e; (void)limit; mock *m = u;
    assert(o->method == m->method && (o->body.length == 0) == (m->method == BC_HTTP_GET) && o->timeout_ms == m->timeout);
    assert(o->path.length == strlen(m->expected) && !memcmp(o->path.data, m->expected, (size_t)o->path.length));
    ++m->submits; m->done = done; m->arg = arg; *out = m; return BC_OK;
}
static void cancelled(void *u, void *p) { (void)p; ++((mock *)u)->cancels; }
static bc_status cookie_set(void *u, void *e, bc_string name, bc_string value) {
    (void)u; (void)e; assert(name.length == 13 && value.length); return BC_OK;
}
static void probe_completed(bc_megarac_probe *p, const bc_megarac_probe_result *r, void *u) {
    (void)p; (void)r; ++((mock *)u)->probe_callbacks;
}
static bc_status polled(void *u, uint32_t ms) { (void)u; (void)ms; return BC_OK; }
static void source_completed(bc_request *r, const bc_response *v, void *u) { (void)r; (void)v; ++((mock *)u)->sources; }
static void completed(bc_jviewer_artifact *op, void *u) {
    mock *m = u; ++m->callbacks;
    assert(bc_jviewer_artifact_result_get(op, m->endpoint, 11));
}
static uint64_t clock_ms(void *u) { mock *m = u; return m->now + (m->clock_calls++ ? m->delay : 0); }
static bc_endpoint *endpoint(bc_context *context) {
    bc_endpoint_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.flags = BC_ENDPOINT_COOKIE_JAR; options.origin = text("https://bmc.example"); options.device_id = text("fixture"); options.endpoint_id = text("web");
    bc_endpoint *out = NULL; assert(bc_endpoint_create(context, &options, &out) == BC_OK); return out;
}
static void response(mock *m, bc_context *context, const uint8_t *body, uint32_t length, uint32_t http) {
    bc_response r = {0}; r.struct_size = sizeof(r); r.http_status = http; r.body = (bc_bytes){body, length};
    m->done(m->arg, &r); assert(bc_context_poll(context, 0) == BC_OK);
}
static bc_jviewer_artifact_options options(mock *m) {
    bc_jviewer_artifact_options o = {0}; o.struct_size = sizeof(o); o.abi_version = BC_ABI_VERSION;
    o.timeout_ms = 100; o.generation = 11; o.clock_ms = clock_ms; o.clock_user = m; return o;
}
static bc_jviewer_artifact *start(mock *m, bc_request *source) {
    m->now = 100; m->delay = 10; m->clock_calls = 0;
    m->expected = "/Java/release/client.jar"; m->timeout = 90;
    bc_jviewer_artifact_options o = options(m); bc_jviewer_artifact *out = NULL;
    assert(bc_jviewer_artifact_start(m->endpoint, source, &o, completed, m, &out) == BC_OK);
    assert(out && !bc_jviewer_artifact_result_get(out, m->endpoint, 11));
    bc_megarac_kvm_info info; bc_service_profile profile;
    assert(bc_jviewer_artifact_resolve(out,m->endpoint,11,&info,&profile) == BC_BUSY && !profile.evidence);
    assert(bc_jviewer_artifact_media_hint(out,m->endpoint,11,&profile) == BC_BUSY && !profile.evidence);
    return out;
}
int main(void) {
    mock m = {0};
    bc_transport transport = {sizeof(transport), BC_ABI_VERSION, &m, opened, closed, submitted, cancelled, polled, cookie_set};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &transport, 16 * 1024 * 1024, 4, 0};
    bc_context *context = NULL, *other = NULL;
    assert(bc_context_create(&co, &context) == BC_OK && bc_context_create(&co, &other) == BC_OK);
    m.endpoint = endpoint(context); bc_endpoint *foreign = endpoint(other);
    assert(bc_endpoint_revision(m.endpoint) == bc_endpoint_revision(foreign));
    bc_http_options request = {0}; request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION;
    m.expected = "/Java/jviewer.jnlp?ext_ip=fixture"; request.path = text(m.expected); request.timeout_ms = m.timeout = 100;
    bc_request *source = NULL; assert(bc_http_submit(m.endpoint, &request, source_completed, &m, &source) == BC_OK);
    assert(bc_request_path(source).length == request.path.length && !bc_request_path(NULL).data);
    bc_jviewer_artifact_options o = options(&m); bc_jviewer_artifact *op = NULL;
    assert(bc_jviewer_artifact_start(m.endpoint, source, &o, completed, &m, &op) == BC_BUSY && !op);
    const char *jnlp = "<jnlp codebase='https://bmc.example:443/Java'><resources><jar href='release/client.jar'/></resources>"
        "<application-desc main-class='com.ami.kvm.jviewer.JViewer'><argument>-hostname</argument><argument>bmc.example</argument>"
        "<argument>-kvmtoken</argument><argument>fixture</argument><argument>-kvmport</argument><argument>7578</argument>"
        "<argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>";
    response(&m, context, (const uint8_t *)jnlp, (uint32_t)strlen(jnlp), 200); assert(m.sources == 1);
    uint32_t sent = m.submits;
    m.now = 100; m.delay = 100; m.clock_calls = 0;
    assert(bc_jviewer_artifact_start(m.endpoint, source, &o, completed, &m, &op) == BC_TIMEOUT && !op && m.submits == sent);
    assert(bc_jviewer_artifact_start(foreign, source, &o, completed, &m, &op) == BC_INVALID_ARGUMENT && !op && m.submits == sent);
    uint8_t code[] = {0x11,0,203,0x3d,0xbb,0,11,0x59,0x10,18,0x1c,3,0xb7,0,15,3,0xac};
    fixture h = make(0,195,NULL,0), a = app_fixture(code,sizeof(code)), jar = jar_of(&h,&a,1,0);
    fixture entry = media_entry_fixture(0), media_class = media_serialization_fixture(0), parent = media_parent_fixture(0),
        cdrom = media_order_fixture(1,0), packet = media_order_fixture(0,0), scsi = media_scsi_fixture(0), packet_parent = media_scsi_parent_fixture(0);
    fixture *classes[] = {&h,&a,&entry,&media_class,&parent,&cdrom,&packet,&scsi,&packet_parent};
    const char *names[] = {"com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr.class",
        "com/ami/kvm/jviewer/gui/JViewerApp.class", "com/ami/kvm/jviewer/JViewer.class",
        "com/ami/iusb/protocol/IUSBHeader.class", "com/ami/iusb/protocol/RedirHeader.class",
        "com/ami/iusb/CDROMRedir.class", "com/ami/iusb/protocol/PacketMaster.class", "com/ami/iusb/protocol/IUSBSCSI.class", "com/ami/iusb/protocol/RedirPacket.class"};
    jar = jar_classes(classes,names,9,1);
    op = start(&m, source);
    assert(bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_STARTUP) == source);
    assert(!bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_JAR));
    response(&m, context, jar.data, jar.size, 200);
    uint32_t asset_submits = m.submits;
    bc_request *binary_asset = bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_JAR);
    const bc_response *binary = bc_request_response(binary_asset);
    assert(binary && binary->body.length == jar.size && !memcmp(binary->body.data, jar.data, jar.size));
    assert(bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_STARTUP) == source);
    assert(!bc_jviewer_artifact_asset_request_get(op, foreign, 11, BC_JVIEWER_ASSET_JAR));
    assert(!bc_jviewer_artifact_asset_request_get(op, m.endpoint, 12, BC_JVIEWER_ASSET_JAR));
    assert(!bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, 99));
    assert(m.submits == asset_submits);
    const bc_jviewer_artifact_result *result = bc_jviewer_artifact_result_get(op, m.endpoint, 11);
    assert(result && result->status == BC_OK && result->hint.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195);
    assert(!bc_service_profile_can_attempt(&result->hint, BC_SERVICE_KVM));
    bc_megarac_media_parameters media;
    assert(bc_jviewer_artifact_media_parameters(op,foreign,11,&media) == BC_INVALID_ARGUMENT && !media.flags);
    assert(bc_jviewer_artifact_media_parameters(op,m.endpoint,12,&media) == BC_INVALID_ARGUMENT && !media.flags);
    assert(bc_jviewer_artifact_media_parameters(op,m.endpoint,11,&media) == BC_OK);
    assert(media.token_type == 0 && (media.flags & BC_MEGARAC_MEDIA_TOKEN_TYPE_RESOURCE_DEFAULT));
    assert(!media.single_port && (media.flags & BC_MEGARAC_MEDIA_SINGLE_PORT_RESOURCE_DEFAULT));
    bc_megarac_kvm_info candidate; bc_service_profile candidate_profile, media_hint;
    assert(bc_jviewer_artifact_media_hint(op,foreign,11,&media_hint) == BC_INVALID_ARGUMENT && !media_hint.evidence);
    assert(bc_jviewer_artifact_media_hint(op,m.endpoint,12,&media_hint) == BC_INVALID_ARGUMENT && !media_hint.evidence);
    assert(bc_jviewer_artifact_media_hint(op,m.endpoint,11,&media_hint) == BC_OK);
    assert(media_hint.evidence == BC_SERVICE_EVIDENCE_HINT && !bc_service_profile_can_attempt(&media_hint,BC_SERVICE_LOCAL_MEDIA));
    assert(bc_jviewer_artifact_resolve(op,foreign,11,&candidate,&candidate_profile) == BC_INVALID_ARGUMENT && !candidate_profile.evidence);
    assert(bc_jviewer_artifact_resolve(op,m.endpoint,12,&candidate,&candidate_profile) == BC_INVALID_ARGUMENT && !candidate_profile.evidence);
    assert(bc_jviewer_artifact_resolve(op,m.endpoint,11,&candidate,&candidate_profile) == BC_OK);
    assert(candidate.kind == BC_MEGARAC_KVM_JVIEWER_195 && bc_service_profile_can_attempt(&candidate_profile,BC_SERVICE_KVM));
    assert(!bc_service_profile_verified(&candidate_profile,BC_SERVICE_KVM) && !bc_service_profile_can_attempt(&candidate_profile,BC_SERVICE_LOCAL_MEDIA));

    assert(!bc_jviewer_artifact_result_get(op, foreign, 11) && !bc_jviewer_artifact_result_get(op, m.endpoint, 12));
    assert(bc_jviewer_artifact_cancel(op) == BC_OK && !result->hint.evidence && result->status == BC_CANCELLED);
    assert(!bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_STARTUP));
    assert(!bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_JAR));
    assert(bc_jviewer_artifact_resolve(op,m.endpoint,11,&candidate,&candidate_profile) == BC_CANCELLED && !candidate_profile.evidence && !candidate.token[0]);
    assert(bc_jviewer_artifact_media_parameters(op,m.endpoint,11,&media) == BC_CANCELLED && !media.flags);
    assert(bc_jviewer_artifact_media_hint(op,m.endpoint,11,&media_hint) == BC_CANCELLED && !media_hint.evidence);
    bc_jviewer_artifact_release(op);
    const uint8_t html_asset[] = "<html>login required</html>";
    op = start(&m,source); response(&m,context,html_asset,sizeof(html_asset)-1,200);
    assert(!bc_jviewer_artifact_asset_request_get(op,m.endpoint,11,BC_JVIEWER_ASSET_JAR));
    assert(bc_jviewer_artifact_asset_request_get(op,m.endpoint,11,BC_JVIEWER_ASSET_STARTUP) == source);
    bc_jviewer_artifact_release(op);
    uint8_t *damaged = malloc(jar.size); assert(damaged); memcpy(damaged,jar.data,jar.size);
    damaged[35] ^= 1;
    op = start(&m,source); response(&m,context,damaged,jar.size,200);
    assert(!bc_jviewer_artifact_asset_request_get(op,m.endpoint,11,BC_JVIEWER_ASSET_JAR));
    bc_jviewer_artifact_release(op); free(damaged);
    fixture media_only = jar_classes(classes+1,names+1,8,1);
    op = start(&m,source); response(&m,context,media_only.data,media_only.size,200);
    assert(bc_jviewer_artifact_result_get(op,m.endpoint,11)->status == BC_UNSUPPORTED);
    assert(bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_JAR));
    assert(bc_jviewer_artifact_media_hint(op,m.endpoint,11,&media_hint) == BC_OK && media_hint.evidence == BC_SERVICE_EVIDENCE_HINT);
    assert(bc_jviewer_artifact_media_parameters(op,m.endpoint,11,&media) == BC_OK);
    assert(media.token_type == 0 && (media.flags & BC_MEGARAC_MEDIA_TOKEN_TYPE_RESOURCE_DEFAULT));
    assert(!media.single_port && (media.flags & BC_MEGARAC_MEDIA_SINGLE_PORT_RESOURCE_DEFAULT));
    bc_jviewer_artifact_release(op);
    fixture no_default = jar_classes(classes,names,2,1);
    op = start(&m,source); response(&m,context,no_default.data,no_default.size,200);
    assert(bc_jviewer_artifact_result_get(op,m.endpoint,11)->status == BC_OK);
    assert(bc_jviewer_artifact_media_parameters(op,m.endpoint,11,&media) == BC_UNSUPPORTED && !media.flags);
    bc_jviewer_artifact_release(op);
    fixture normal_entry = entry;
    entry = media_entry_fixture(7);
    fixture bad_mode = jar_classes(classes,names,9,1);
    op = start(&m,source); response(&m,context,bad_mode.data,bad_mode.size,200);
    assert(bc_jviewer_artifact_result_get(op,m.endpoint,11)->status == BC_OK);
    assert(bc_jviewer_artifact_media_parameters(op,m.endpoint,11,&media) == BC_UNSUPPORTED && !media.flags);
    bc_jviewer_artifact_release(op); entry = normal_entry;
    fixture kvm_only = jar_classes(classes,names,3,1);
    op = start(&m,source); response(&m,context,kvm_only.data,kvm_only.size,200);
    assert(bc_jviewer_artifact_result_get(op,m.endpoint,11)->status == BC_OK);
    assert(bc_jviewer_artifact_media_hint(op,m.endpoint,11,&media_hint) == BC_UNSUPPORTED && !media_hint.evidence);
    bc_jviewer_artifact_release(op);
    op = start(&m,source); response(&m,context,jar.data,jar.size,200); m.now = 190;
    assert(bc_jviewer_artifact_media_hint(op,m.endpoint,11,&media_hint) == BC_TIMEOUT && !media_hint.evidence);
    assert(!bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_JAR));
    m.now = 100;
    assert(!bc_jviewer_artifact_asset_request_get(op, m.endpoint, 11, BC_JVIEWER_ASSET_STARTUP));
    m.now = 190;
    assert(bc_jviewer_artifact_media_parameters(op,m.endpoint,11,&media) == BC_TIMEOUT && !media.flags);
    assert(bc_jviewer_artifact_resolve(op,m.endpoint,11,&candidate,&candidate_profile) == BC_TIMEOUT && !candidate_profile.evidence && !candidate.token[0]);
    bc_jviewer_artifact_release(op);
    for (unsigned reason = 0; reason < 4; ++reason) {
        op = start(&m, source);
        if (reason == 0) m.now = 190;
        if (reason == 1) m.now = 80;
        response(&m, context, jar.data, jar.size, reason == 2 ? 401 : reason == 3 ? 302 : 200);
        result = bc_jviewer_artifact_result_get(op, m.endpoint, 11);
        assert(result->status == (reason == 0 ? BC_TIMEOUT : reason == 1 ? BC_INVALID_ARGUMENT : reason == 2 ? BC_AUTHENTICATION_FAILED : BC_HTTP_ERROR));
        assert(!result->hint.evidence);
        if (reason == 2) assert(result->failure.cause == BC_CONSOLE_CAUSE_AUTH_REJECTED);
        if (reason == 1) m.now = 120;
        assert(bc_jviewer_artifact_media_parameters(op,m.endpoint,11,&media) == result->status && !media.flags);
        assert(bc_jviewer_artifact_media_hint(op,m.endpoint,11,&media_hint) == result->status && !media_hint.evidence);
        bc_jviewer_artifact_release(op);
    }
    op = start(&m, source); assert(bc_jviewer_artifact_cancel(op) == BC_OK);
    assert(bc_context_poll(context,0) == BC_OK);
    result = bc_jviewer_artifact_result_get(op,m.endpoint,11); assert(result->status == BC_CANCELLED && !result->hint.evidence);
    bc_jviewer_artifact_release(op);
    op = start(&m, source);
    bc_response queued = {0}; queued.struct_size=sizeof(queued); queued.http_status=200; queued.body=(bc_bytes){jar.data,jar.size};
    m.done(m.arg,&queued); assert(bc_jviewer_artifact_cancel(op) == BC_OK); assert(bc_context_poll(context,0) == BC_OK);
    assert(bc_jviewer_artifact_result_get(op,m.endpoint,11)->status == BC_CANCELLED); bc_jviewer_artifact_release(op);
    op = start(&m, source); uint32_t callbacks = m.callbacks; bc_jviewer_artifact_release(op);
    response(&m, context, jar.data, jar.size, 200); assert(m.callbacks == callbacks + 1);
    assert(m.sources == 1);
    m.expected = "/oem/start"; m.method = BC_HTTP_POST; m.timeout = 100;
    request.method = BC_HTTP_POST; request.path = text(m.expected); request.body = (bc_bytes){(const uint8_t *)"{}",2};
    bc_request *post = NULL; assert(bc_http_submit(m.endpoint,&request,source_completed,&m,&post) == BC_OK);
    response(&m,context,(const uint8_t *)jnlp,(uint32_t)strlen(jnlp),200);
    m.method = BC_HTTP_GET; uint32_t before_read = m.submits;
    op = start(&m,post); response(&m,context,jar.data,jar.size,200);
    assert(m.submits == before_read + 1 && m.sources == 2 && bc_jviewer_artifact_result_get(op,m.endpoint,11)->status == BC_OK);
    bc_jviewer_artifact_release(op); bc_request_release(post);
    bc_megarac_probe_options po = {0}; po.struct_size = sizeof(po); po.abi_version = BC_ABI_VERSION;
    po.host = text("bmc.example"); po.username = text("fixture"); po.password = text("fixture"); po.timeout_ms = 100;
    bc_service_profile manual = {sizeof(manual), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC,
        BC_SERVICE_MEGARAC_KVM_JVIEWER_373, BC_SERVICE_EVIDENCE_MANUAL};
    m.expected = "/rpc/WEBSES/create.asp"; m.method = BC_HTTP_POST; m.timeout = 100; bc_megarac_probe *probe = NULL;
    assert(bc_megarac_probe_start_discovery(m.endpoint,&po,&manual,probe_completed,&m,&probe) == BC_OK);
    assert(!bc_megarac_probe_launch_request(probe));
    m.expected = "/Java/jviewer.jnlp?EXTRNIP=bmc.example&JNLPSTR=JViewer"; m.method = BC_HTTP_GET;
    const char *cookie = "{\"SESSION_COOKIE\":\"fixture-cookie\"}";
    response(&m,context,(const uint8_t *)cookie,(uint32_t)strlen(cookie),200);
    response(&m,context,(const uint8_t *)jnlp,(uint32_t)strlen(jnlp),200);
    bc_request *retained = bc_megarac_probe_launch_request(probe); assert(retained && m.probe_callbacks == 1);
    bc_request_retain(retained);
    op = start(&m,retained); response(&m,context,jar.data,jar.size,200);
    assert(bc_jviewer_artifact_result_get(op,m.endpoint,11)->status == BC_OK); bc_jviewer_artifact_release(op);
    m.expected = "/rpc/WEBSES/logout.asp"; m.timeout = 100;
    assert(bc_megarac_probe_logout(probe,probe_completed,&m) == BC_OK && !bc_megarac_probe_launch_request(probe));
    const char *logout = "{\"HAPI_STATUS\":0}";
    response(&m,context,(const uint8_t *)logout,(uint32_t)strlen(logout),200);
    assert(!bc_megarac_probe_launch_request(probe) && m.probe_callbacks == 2 && bc_request_response(retained));
    bc_request_release(retained); bc_megarac_probe_release(probe);
    for (unsigned test = 0; test < 6; ++test) {
        char xml[2048], token[99]; memset(token, 'x', sizeof(token)-1); token[sizeof(token)-1] = 0;
        const char *fields = test == 2 ? "" : "<argument>-vmsecure</argument><argument>1</argument>"
            "<argument>-cdport</argument><argument>5120</argument><argument>-cdnum</argument><argument>1</argument>";
        snprintf(xml,sizeof(xml),"<jnlp codebase='https://bmc.example/Java'><resources><jar href='release/client.jar'/></resources>"
            "<application-desc main-class='com.ami.kvm.jviewer.JViewer'><argument>-hostname</argument><argument>bmc.example</argument>"
            "<argument>-kvmtoken</argument><argument>%s</argument><argument>-kvmport</argument><argument>7578</argument>"
            "<argument>-kvmsecure</argument><argument>1</argument><argument>-singleportenabled</argument><argument>%u</argument>%s"
            "</application-desc></jnlp>",test == 4 ? token : "fixture",test == 3 ? 1 : 0,fields);
        m.expected = "/Java/jviewer.jnlp"; m.method = BC_HTTP_GET; m.timeout = 100;
        request.method = BC_HTTP_GET; request.path = text(m.expected); request.body = (bc_bytes){0};
        bc_request *media_source = NULL;
        assert(bc_http_submit(m.endpoint,&request,source_completed,&m,&media_source) == BC_OK);
        response(&m,context,(const uint8_t *)xml,(uint32_t)strlen(xml),200);
        op = start(&m,media_source);
        fixture *asset = test == 1 ? &media_only : test == 5 ? &kvm_only : &jar;
        response(&m,context,asset->data,asset->size,200);
        bc_service_profile independent;
        bc_status status = bc_jviewer_artifact_media_resolve(op,m.endpoint,11,&independent,&media);
        if (test < 2) {
            assert(status == BC_OK && media.port == 5120 && media.secure == 1 && media.devices == 1);
            assert(bc_service_profile_can_attempt(&independent,BC_SERVICE_LOCAL_MEDIA));
            assert(!bc_service_profile_verified(&independent,BC_SERVICE_LOCAL_MEDIA));
            assert(!bc_service_profile_can_attempt(&independent,BC_SERVICE_KVM));
            if (test == 1) assert(bc_jviewer_artifact_result_get(op,m.endpoint,11)->status == BC_UNSUPPORTED);
            assert(bc_jviewer_artifact_media_resolve(op,foreign,11,&independent,&media) == BC_INVALID_ARGUMENT && !independent.evidence && !media.flags);
            assert(bc_jviewer_artifact_media_resolve(op,m.endpoint,12,&independent,&media) == BC_INVALID_ARGUMENT && !independent.evidence && !media.flags);
            if (!test) {
                assert(bc_jviewer_artifact_cancel(op) == BC_OK);
                assert(bc_jviewer_artifact_media_resolve(op,m.endpoint,11,&independent,&media) == BC_CANCELLED && !independent.evidence && !media.flags);
            } else {
                m.now = 200;
                assert(bc_jviewer_artifact_media_resolve(op,m.endpoint,11,&independent,&media) == BC_TIMEOUT && !independent.evidence && !media.flags);
                m.now = 100;
                assert(bc_jviewer_artifact_media_resolve(op,m.endpoint,11,&independent,&media) == BC_TIMEOUT && !independent.evidence && !media.flags);
            }
        } else assert(status == BC_UNSUPPORTED && !independent.evidence && !media.flags);
        bc_jviewer_artifact_release(op); bc_request_release(media_source);
    }
    bc_request_release(source); bc_endpoint_release(m.endpoint); bc_endpoint_release(foreign);
    assert(bc_context_destroy(context) == BC_OK && bc_context_destroy(other) == BC_OK && m.closes == 2);
    return 0;
}

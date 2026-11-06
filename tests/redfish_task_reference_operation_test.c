#include "bcontrol/redfish_task_reference.h"
#include "bcontrol/transport.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef struct { bc_transport_done done; void *arg; char path[1024]; uint32_t method; } mock;
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static bc_status opened(void *u, const bc_endpoint_options *o, void **out) { (void)u; (void)o; *out = malloc(1); return *out ? BC_OK : BC_NO_MEMORY; }
static void closed(void *u, void *e) { (void)u; free(e); }
static bc_status submitted(void *u, void *e, const bc_http_options *o, uint64_t limit, bc_transport_done done, void *arg, void **out) {
    (void)e; (void)limit; mock *m = u; assert(!m->done && o->path.length < sizeof(m->path));
    memcpy(m->path, o->path.data, (size_t)o->path.length); m->path[o->path.length] = 0;
    m->method = o->method; m->done = done; m->arg = arg; *out = m; return BC_OK;
}
static void cancelled(void *u, void *p) { (void)p; ((mock *)u)->done = NULL; }
static bc_status polled(void *u, uint32_t ms) { (void)u; (void)ms; return BC_OK; }
static void completed(bc_redfish_operation *op, const bc_redfish_result *r, void *u) { (void)op; (void)r; ++*(unsigned *)u; }
static void response(mock *m, bc_context *context, const char *path, uint32_t method, uint32_t http, const char *body) {
    if (!m->done || strcmp(m->path, path) || m->method != method) fprintf(stderr, "fixture expected %u %s, got %u %s (pending %d)\n", method, path, m->method, m->path, m->done != NULL);
    assert(m->done && !strcmp(m->path, path) && m->method == method);
    bc_response value = {0}; value.struct_size = sizeof(value); value.status = BC_OK; value.http_status = http;
    value.body = (bc_bytes){(const unsigned char *)body, strlen(body)};
    bc_transport_done done = m->done; void *arg = m->arg; m->done = NULL;
    done(arg, &value); assert(bc_context_poll(context, 0) == BC_OK);
}
static bc_endpoint *endpoint(bc_context *context) {
    bc_endpoint_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.origin = text("https://bmc.example"); options.device_id = text("fixture"); options.endpoint_id = text("web");
    bc_endpoint *out = NULL; assert(bc_endpoint_create(context, &options, &out) == BC_OK); return out;
}
#define COLLECTION "/redfish/v1/queue/jobs"
#define TASK COLLECTION "/7"
#define MEDIA "/redfish/v1/Managers/mgr/VirtualMedia/cd"
#define TARGET MEDIA "/Actions/InsertMedia"
static void discover(mock *m, bc_context *context) {
    response(m, context, "/redfish/v1/", BC_HTTP_GET, 200, "{\"@odata.type\":\"#ServiceRoot.v1_17_0.ServiceRoot\",\"RedfishVersion\":\"1.17.0\",\"TaskService\":{\"@odata.id\":\"/redfish/v1/queue\"}}");
    response(m, context, "/redfish/v1/queue", BC_HTTP_GET, 200, "{\"@odata.type\":\"#TaskService.v1_2_0.TaskService\",\"Tasks\":{\"@odata.id\":\"" COLLECTION "\"}}");
    response(m, context, COLLECTION, BC_HTTP_GET, 200, "{\"@odata.type\":\"#TaskCollection.TaskCollection\",\"Members\":[]}");
}
static void media(mock *m, bc_context *context) {
    response(m, context, MEDIA, BC_HTTP_GET, 200, "{\"@odata.type\":\"#VirtualMedia.v1_6_1.VirtualMedia\",\"Id\":\"cd\",\"Inserted\":false,\"Actions\":{\"#VirtualMedia.InsertMedia\":{\"target\":\"" TARGET "\"},\"#VirtualMedia.EjectMedia\":{\"target\":\"" MEDIA "/Actions/EjectMedia\"}}}");
}
static void task(mock *m, bc_context *context, const char *path, uint32_t method, uint32_t http, const char *state, int identity) {
    char body[2048]; int n = snprintf(body, sizeof(body),
        "{\"@odata.type\":\"#Task.v1_7_4.Task\",\"@odata.id\":\"%s\",\"Id\":\"7\",\"TaskState\":\"%s\"%s,\"Payload\":{\"HttpOperation\":\"POST\",\"TargetUri\":\"%s\",\"JsonBody\":\"secret-image\"},\"TaskMonitor\":\"/redfish/v1/TaskMonitors/secret?token=secret\"}",
        TASK, state, identity == 1 ? ",\"StartTime\":\"2026-10-24T05:00:00Z\"" : identity == 2 ? ",\"StartTime\":\"2026-10-24T05:00:01Z\"" : "", TARGET);
    assert(n > 0 && n < (int)sizeof(body)); response(m, context, path, method, http, body);
}
int main(void) {
    mock m = {0}; bc_transport transport = {sizeof(transport), BC_ABI_VERSION, &m, opened, closed, submitted, cancelled, polled, NULL};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &transport, 1024 * 1024, 8, 0}; bc_context *context = NULL;
    assert(bc_context_create(&co, &context) == BC_OK); bc_endpoint *device = endpoint(context), *foreign = endpoint(context);
    bc_redfish_collection_options collection = {sizeof(collection), BC_ABI_VERSION, 1000, 16};
    bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, 1000, 16}; unsigned callbacks = 0;
    bc_redfish_operation *discovery = NULL, *write = NULL, *read = NULL, *other = NULL;
    assert(bc_redfish_discover_tasks(device, &collection, completed, &callbacks, &discovery) == BC_OK); discover(&m, context);
    assert(bc_redfish_result_get(discovery)->status == BC_OK);
    bc_redfish_virtual_media_insert_options insert = {0}; insert.struct_size = sizeof(insert); insert.image = text("https://images.invalid/private.iso?token=secret");
    assert(bc_redfish_virtual_media_insert(device, text(MEDIA), &insert, &options, completed, &callbacks, &write) == BC_OK);
    unsigned char saved[BC_REDFISH_TASK_REFERENCE_MAX]; uint32_t length = 99, flags = 99;
    bc_string id = text("11111111-1111-1111-1111-111111111111"), digest = text("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    assert(bc_redfish_task_reference_export_operation(write, discovery, id, digest, saved, sizeof(saved), &length) == BC_UNSUPPORTED && !length);
    media(&m, context); task(&m, context, TARGET, BC_HTTP_POST, 202, "Running", 1);
    assert(bc_redfish_result_get(write)->status == BC_OK);
    bc_redfish_task_reference captured;
    assert(bc_redfish_task_reference_capture_operation(write, discovery, id, digest, &captured, saved, sizeof(saved), &length) == BC_OK);
    assert(captured.struct_size == sizeof(captured) && !strcmp(captured.target_uri, TARGET) && !strcmp(captured.collection_uri, COLLECTION));
    assert(length && !strstr((char *)saved, "secret") && !strstr((char *)saved, "TaskMonitor"));
    bc_redfish_task_binding binding = {sizeof(binding), BC_REDFISH_TASK_REFERENCE_INSERT, BC_HTTP_POST, 0, id, digest, text(COLLECTION), text(MEDIA), text(TARGET)};
    bc_redfish_task_reference ref; assert(bc_redfish_task_reference_import((bc_bytes){saved, length}, &binding, &ref) == BC_OK);
    assert(bc_redfish_get_virtual_media(device, text(MEDIA), &options, completed, &callbacks, &other) == BC_OK);
    media(&m, context);
    bc_redfish_task_reference restored;
    assert(bc_redfish_task_reference_restore_operation((bc_bytes){saved, length}, other, discovery, id, digest, BC_REDFISH_TASK_REFERENCE_INSERT, &restored) == BC_OK);
    assert(!strcmp(restored.task_uri, TASK));
    assert(bc_redfish_task_reference_restore_operation((bc_bytes){saved, length}, other, discovery, id, digest, BC_REDFISH_TASK_REFERENCE_EJECT, &restored) != BC_OK && !restored.struct_size);
    assert(bc_redfish_task_reference_restore_operation((bc_bytes){saved, length}, write, discovery, id, digest, BC_REDFISH_TASK_REFERENCE_INSERT, &restored) != BC_OK);
    bc_redfish_release(other); other = NULL;
    assert(bc_redfish_get_task(device, text(TASK), &options, completed, &callbacks, &read) == BC_OK);
    assert(bc_redfish_task_reference_match_operation(&ref, read, discovery, id, digest, &flags) == BC_UNSUPPORTED && !flags);
    task(&m, context, TASK, BC_HTTP_GET, 200, "Completed", 1);
    assert(bc_redfish_task_reference_match_operation(&ref, read, discovery, id, digest, &flags) == BC_OK && (flags & BC_TASK_TERMINAL));
    assert(bc_redfish_task_reference_match_operation(&ref, read, discovery, text("22222222-2222-2222-2222-222222222222"), digest, &flags) == BC_UNSUPPORTED && !flags);
    assert(bc_redfish_get_collection(device, text(COLLECTION), BC_COLLECTION_TASKS, &collection, completed, &callbacks, &other) == BC_OK);
    response(&m, context, COLLECTION, BC_HTTP_GET, 200, "{\"@odata.type\":\"#TaskCollection.TaskCollection\",\"Members\":[]}");
    assert(bc_redfish_task_reference_export_operation(write, other, id, digest, saved, sizeof(saved), &length) == BC_UNSUPPORTED && !length); bc_redfish_release(other);
    assert(bc_redfish_discover_tasks(foreign, &collection, completed, &callbacks, &other) == BC_OK);
    assert(bc_redfish_task_reference_export_operation(write, other, id, digest, saved, sizeof(saved), &length) == BC_UNSUPPORTED && !length);
    discover(&m, context);
    assert(bc_redfish_task_reference_export_operation(write, other, id, digest, saved, sizeof(saved), &length) == BC_UNSUPPORTED && !length); bc_redfish_release(other);
    assert(bc_redfish_task_reference_match_operation(&ref, read, discovery, id, digest, &flags) == BC_OK);
    bc_redfish_release(read); read = NULL;
    assert(bc_redfish_get_task(device, text(TASK), &options, completed, &callbacks, &read) == BC_OK);
    response(&m, context, TASK, BC_HTTP_GET, 404, "{}");
    assert(bc_redfish_task_reference_match_operation(&ref, read, discovery, id, digest, &flags) == BC_UNSUPPORTED && !flags);
    bc_redfish_release(read); read = NULL;
    assert(bc_redfish_get_task(device, text(TASK), &options, completed, &callbacks, &read) == BC_OK);
    task(&m, context, TASK, BC_HTTP_GET, 200, "Completed", 2);
    assert(bc_redfish_task_reference_match_operation(&ref, read, discovery, id, digest, &flags) == BC_UNSUPPORTED && !flags);
    bc_redfish_release(read); read = NULL;
    assert(bc_redfish_get_task(device, text(TASK "?token=secret"), &options, completed, &callbacks, &read) == BC_OK);
    task(&m, context, TASK "?token=secret", BC_HTTP_GET, 200, "Completed", 1);
    assert(bc_redfish_task_reference_match_operation(&ref, read, discovery, id, digest, &flags) == BC_UNSUPPORTED && !flags);
    bc_redfish_release(read); read = NULL;
    assert(bc_redfish_get_task_monitor(device, text("/redfish/v1/monitor/7"), &options, completed, &callbacks, &read) == BC_OK);
    task(&m, context, "/redfish/v1/monitor/7", BC_HTTP_GET, 202, "Running", 1);
    assert(bc_redfish_task_reference_match_operation(&ref, read, discovery, id, digest, &flags) == BC_UNSUPPORTED && !flags);
    bc_redfish_release(read); bc_redfish_release(write); write = NULL;
    assert(bc_redfish_virtual_media_insert(device, text(MEDIA), &insert, &options, completed, &callbacks, &write) == BC_OK);
    media(&m, context); task(&m, context, TARGET, BC_HTTP_POST, 202, "Running", 0);
    assert(bc_redfish_result_get(write)->status == BC_OK);
    assert(bc_redfish_task_reference_export_operation(write, discovery, id, digest, saved, sizeof(saved), &length) == BC_UNSUPPORTED && !length);
    bc_redfish_release(write); bc_redfish_release(discovery); bc_endpoint_release(device); bc_endpoint_release(foreign);
    assert(bc_context_destroy(context) == BC_OK); puts("operation-bound task reference passed"); return 0;
}

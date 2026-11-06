#include "bcontrol/redfish_task_reference.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static bc_bytes bytes(const char *s) { return (bc_bytes){(const unsigned char *)s, strlen(s)}; }
static const char *body = "{\"@odata.type\":\"#Task.v1_7_4.Task\",\"@odata.id\":\"/redfish/v1/TaskService/Tasks/7\",\"Id\":\"7\",\"StartTime\":\"2026-10-24T05:00:00Z\",\"TaskState\":\"Running\",\"Payload\":{\"HttpOperation\":\"POST\",\"TargetUri\":\"/redfish/v1/Managers/1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia\",\"JsonBody\":\"secret-token-and-image\"},\"TaskMonitor\":\"/redfish/v1/TaskService/TaskMonitors/secret?token=secret\",\"Messages\":[{\"Message\":\"secret-password\"}]}";
static void replace(char *out, size_t size, const char *source, const char *from, const char *to) {
    const char *p = strstr(source, from); assert(p);
    int n = snprintf(out, size, "%.*s%s%s", (int)(p - source), source, to, p + strlen(from)); assert(n > 0 && (size_t)n < size);
}
int main(void) {
    bc_redfish_task_binding scope = {0}; scope.struct_size = sizeof(scope); scope.action = BC_REDFISH_TASK_REFERENCE_INSERT; scope.http_method = BC_HTTP_POST;
    scope.endpoint_id = text("11111111-1111-1111-1111-111111111111");
    scope.address_digest = text("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    scope.collection_uri = text("/redfish/v1/TaskService/Tasks"); scope.media_uri = text("/redfish/v1/Managers/1/VirtualMedia/CD");
    scope.target_uri = text("/redfish/v1/Managers/1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia");
    unsigned char saved[BC_REDFISH_TASK_REFERENCE_MAX]; uint32_t length = 0, flags = 99;
    assert(bc_redfish_task_reference_export(bytes(body), &scope, saved, sizeof(saved), &length) == BC_OK && length);
    assert(!strstr((const char *)saved, "secret") && !strstr((const char *)saved, "TaskMonitor") && !strstr((const char *)saved, "JsonBody"));
    bc_redfish_task_reference ref;
    assert(bc_redfish_task_reference_import((bc_bytes){saved, length}, &scope, &ref) == BC_OK);
    assert(bc_redfish_task_reference_match(&ref, bytes(body), &flags) == BC_OK && !flags);
    char changed[4096]; replace(changed, sizeof(changed), body, "Running", "Completed");
    assert(bc_redfish_task_reference_match(&ref, bytes(changed), &flags) == BC_OK && (flags & BC_TASK_TERMINAL));
    const char *from[] = {"2026-10-24T05:00:00Z", "\"Id\":\"7\"", "\"HttpOperation\":\"POST\"", "\"StartTime\"", "\"Payload\"", "#Task.v1_7_4.Task", "\"@odata.id\":\"/redfish/v1/TaskService/Tasks/7\""};
    const char *to[] = {"2026-10-24T05:00:01Z", "\"Id\":\"8\"", "\"HttpOperation\":\"PATCH\"", "\"OtherTime\"", "\"OtherPayload\"", "#Other.v1_7_4.Task", "\"@odata.id\":\"/redfish/v1/TaskService/Tasks/7?secret=x\""};
    for (size_t i = 0; i < sizeof(from) / sizeof(from[0]); ++i) {
        replace(changed, sizeof(changed), body, from[i], to[i]); flags = 99;
        assert(bc_redfish_task_reference_match(&ref, bytes(changed), &flags) != BC_OK && !flags);
    }
    const char *invalidDates[] = {"2026-02-30T05:00:00Z", "2026-10-24T25:00:00Z", "2026-10-24T05:00:00", "2026-10-24T05:00:00+99:00", "2026-10-24T05:00:00.Z"};
    for (size_t i = 0; i < sizeof(invalidDates) / sizeof(invalidDates[0]); ++i) {
        replace(changed, sizeof(changed), body, "2026-10-24T05:00:00Z", invalidDates[i]); uint32_t n = 99;
        assert(bc_redfish_task_reference_export(bytes(changed), &scope, (unsigned char *)changed + 2048, 2048, &n) != BC_OK && !n);
    }
    for (size_t i = 0; i < strlen(body); ++i) { flags = 99; assert(bc_redfish_task_reference_match(&ref, (bc_bytes){(const unsigned char *)body, i}, &flags) != BC_OK && !flags); }
    for (uint32_t i = 0; i < length; ++i) { bc_redfish_task_reference value; assert(bc_redfish_task_reference_import((bc_bytes){saved, i}, &scope, &value) != BC_OK && !value.struct_size); }
    const char *validDates[] = {"2024-02-29T05:00:00.123456+08:00", "2026-10-24T05:00:60Z"};
    for (size_t i = 0; i < sizeof(validDates) / sizeof(validDates[0]); ++i) {
        replace(changed, sizeof(changed), body, "2026-10-24T05:00:00Z", validDates[i]);
        uint32_t n = 0; unsigned char result[BC_REDFISH_TASK_REFERENCE_MAX];
        assert(bc_redfish_task_reference_export(bytes(changed), &scope, result, sizeof(result), &n) == BC_OK && n);
    }
    const char *extra[] = {"\"HidePayload\":true,", "\"StartTime\":\"2026-10-24T05:00:00Z\",", "\"Payload\":{},", "\"@odata.id\":\"/redfish/v1/TaskService/Tasks/7\","};
    for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); ++i) {
        int n = snprintf(changed, sizeof(changed), "{%s%s", extra[i], body + 1); assert(n > 0 && n < (int)sizeof(changed));
        uint32_t written = 99; unsigned char result[BC_REDFISH_TASK_REFERENCE_MAX];
        assert(bc_redfish_task_reference_export(bytes(changed), &scope, result, sizeof(result), &written) != BC_OK && !written);
    }
    bc_redfish_task_binding wrong = scope; wrong.endpoint_id = text("22222222-2222-2222-2222-222222222222");
    assert(bc_redfish_task_reference_import((bc_bytes){saved, length}, &wrong, &ref) != BC_OK && !ref.struct_size);
    wrong = scope; wrong.target_uri = text("https://elsewhere/secret");
    assert(bc_redfish_task_reference_export(bytes(body), &wrong, saved, sizeof(saved), &length) != BC_OK && !length);
    memset(&ref, 'x', sizeof(ref)); ref.struct_size = sizeof(ref); ref.reserved = 0;
    assert(bc_redfish_task_reference_match(&ref, bytes(body), &flags) == BC_INVALID_ARGUMENT);
    puts("redfish task reference metadata passed"); return 0;
}

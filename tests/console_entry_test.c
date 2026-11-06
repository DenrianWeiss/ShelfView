#include "bcontrol/console_entry.h"
#include <assert.h>
#include <string.h>
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
int main(void) {
    uint32_t family = 42;
    bc_string empty = {0};
    bc_service_profile hint = {sizeof(hint), BC_SERVICE_KVM, BC_SERVICE_FAMILY_IDRAC,
        BC_SERVICE_IDRAC_KVM_EHTML5, BC_SERVICE_EVIDENCE_HINT};
    assert(bc_console_http_family_select(NULL, 0, empty, empty, 0, 0, &family) == BC_UNSUPPORTED && !family);
    assert(bc_console_http_family_select(&hint, 1, empty, empty, 0, 0, &family) == BC_OK && family == BC_SERVICE_FAMILY_IDRAC);
    bc_string action = text("/redfish/v1/Managers/1/KvmService/Actions/KvmService.ExportKvmStartupFile");
    assert(bc_console_http_family_select(NULL, 0, action, empty, BC_HUAWEI_LAUNCH_EXPORT_DIRECT,
        BC_HUAWEI_MODE_SHARED, &family) == BC_OK && family == BC_SERVICE_FAMILY_HUAWEI);
    assert(bc_console_http_family_select(&hint, 1, action, empty, BC_HUAWEI_LAUNCH_EXPORT_DIRECT,
        BC_HUAWEI_MODE_SHARED, &family) == BC_UNSUPPORTED && !family);
    assert(bc_console_http_family_select(NULL, 0, action, empty, BC_HUAWEI_LAUNCH_EXPORT_DIRECT,
        BC_HUAWEI_MODE_PRIVATE, &family) == BC_UNSUPPORTED && !family);
    hint.evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR;
    assert(bc_console_http_family_select(&hint, 1, empty, empty, 0, 0, &family) == BC_INVALID_ARGUMENT && !family);
    hint.evidence = BC_SERVICE_EVIDENCE_HINT; hint.family = BC_SERVICE_FAMILY_MEGARAC;
    assert(bc_console_http_family_select(&hint, 1, empty, empty, 0, 0, &family) == BC_INVALID_ARGUMENT && !family);
    const uint32_t missing[] = {404, 405, 501};
    for (unsigned i = 0; i < sizeof(missing)/sizeof(*missing); ++i)
        assert(bc_console_entry_can_select_manually(BC_HTTP_ERROR, missing[i]));
    assert(bc_console_entry_can_select_manually(BC_UNSUPPORTED, 0));
    assert(bc_console_entry_can_select_manually(BC_PROTOCOL_ERROR, 200));
    assert(!bc_console_entry_can_select_manually(BC_OK, 200));
    const uint32_t hard_http[] = {401, 403, 409, 423, 429, 500, 502, 503};
    for (unsigned i = 0; i < sizeof(hard_http)/sizeof(*hard_http); ++i) {
        assert(!bc_console_entry_can_select_manually(BC_UNSUPPORTED, hard_http[i]));
        assert(!bc_console_entry_can_select_manually(BC_PROTOCOL_ERROR, hard_http[i]));
    }
    const bc_status hard_status[] = {BC_AUTHENTICATION_FAILED, BC_BUSY, BC_TLS_ERROR, BC_TIMEOUT,
        BC_CANCELLED, BC_IO_ERROR, BC_OUTCOME_UNKNOWN, BC_SHUTTING_DOWN};
    for (unsigned i = 0; i < sizeof(hard_status)/sizeof(*hard_status); ++i)
        assert(!bc_console_entry_can_select_manually(hard_status[i], 404));
    return 0;
}

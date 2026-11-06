#include "bcontrol/redfish.h"
#include <assert.h>
#include <string.h>

static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static uint32_t match(const char *a, const char *b, const char *pattern) {
    return bc_redfish_resource_uri_match(text(a), text(b), text(pattern));
}
int main(void) {
    const char *a = "/redfish/v1/Managers/BladeA/KvmService";
    const char *b = "/redfish/v1/managers/BladeA/kvmservice";
    const char *pattern = "/redfish/v1/Managers/*/KvmService";
    assert(match(a, a, "") == BC_REDFISH_URI_EXACT);
    assert(match(a, b, "") == BC_REDFISH_URI_NO_MATCH);
    assert(match(a, b, pattern) == BC_REDFISH_URI_FIXED_CASE);
    assert(match(b, b, pattern) == BC_REDFISH_URI_EXACT);
    assert(match(a, "/redfish/v1/managers/bladeA/kvmservice", pattern) == BC_REDFISH_URI_NO_MATCH);
    assert(match(a, "/redfish/v1/managers/BladeB/kvmservice", pattern) == BC_REDFISH_URI_NO_MATCH);
    assert(match("/redfish/v1/Systems/NodeA/Storage/RAIDa/Volumes/VolA",
        "/redfish/v1/systems/NodeA/storage/RAIDa/volumes/VolA",
        "/redfish/v1/Systems/*/Storage/*/Volumes/*") == BC_REDFISH_URI_FIXED_CASE);
    assert(match("/redfish/v1/Systems/NodeA/Storage/RAIDa/Volumes/VolA",
        "/redfish/v1/systems/NodeA/storage/RAIDA/volumes/VolA",
        "/redfish/v1/Systems/*/Storage/*/Volumes/*") == BC_REDFISH_URI_NO_MATCH);
    assert(match(a, b, "/redfish/v1/Managers/*/Unknown") == BC_REDFISH_URI_NO_MATCH);
    const char *invalid[] = {
        "https://bmc/redfish/v1/Managers/BladeA/KvmService",
        "/REDFISH/v1/Managers/BladeA/KvmService",
        "/redfish/v1/Managers/BladeA/KvmService/",
        "/redfish/v1/Managers//KvmService",
        "/redfish/v1/Managers/../KvmService",
        "/redfish/v1/Managers/BladeA/KvmService?x=1",
        "/redfish/v1/Managers/BladeA/KvmService#x",
        "/redfish/v1/Managers/%42ladeA/KvmService",
        "/redfish/v1/Managers/BladeA/Unknown"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(match(a, invalid[i], pattern) == BC_REDFISH_URI_NO_MATCH);
    const char *bad_patterns[] = {"/redfish/v1/Managers/**/KvmService", "/redfish/v1/Managers/Bl*/KvmService",
        "/redfish/v1/Managers/*/KvmService/", "/redfish/v1/Managers/*/KvmService?x", "/redfish/v1/Managers/{id}/KvmService"};
    for (size_t i = 0; i < sizeof(bad_patterns) / sizeof(bad_patterns[0]); ++i)
        assert(match(a, a, bad_patterns[i]) == BC_REDFISH_URI_NO_MATCH);
    assert(bc_redfish_resource_uri_match((bc_string){NULL, 100}, text(a), text(pattern)) == BC_REDFISH_URI_NO_MATCH);
    assert(bc_redfish_resource_uri_match(text(a), text(a), (bc_string){NULL, 100}) == BC_REDFISH_URI_NO_MATCH);
    char embedded[] = "/redfish/v1/Managers/BladeA/KvmService";
    embedded[20] = 0;
    assert(bc_redfish_resource_uri_match(text(a), (bc_string){embedded, sizeof(embedded) - 1}, text(pattern)) == BC_REDFISH_URI_NO_MATCH);
    return 0;
}

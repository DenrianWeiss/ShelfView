#include "bcontrol/huawei_discovery.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static bc_status resource(const char *body, bc_huawei_kvm_resource *out) {
    return bc_huawei_kvm_resource_parse((const uint8_t *)body, (uint32_t)strlen(body),
        text("/redfish/v1/Managers/Blade3/kvmService"), out);
}
static bc_status info(const char *params, bc_huawei_kvm_action_info *out) {
    char body[4096];
    int n = snprintf(body, sizeof(body), "{\"@odata.type\":\"#ActionInfo.v1_0_0.ActionInfo\",\"Parameters\":%s}", params);
    assert(n > 0 && n < (int)sizeof(body));
    return bc_huawei_kvm_action_info_parse((const uint8_t *)body, (uint32_t)n, out);
}
int main(void) {
    const char *good = "{\"@odata.type\":\"#HwKvmService.v1_0_0.HwKvmService\","
        "\"@odata.id\":\"/redfish/v1/Managers/Blade3/kvmService\","
        "\"NumberOfActivatedSessions\":1,\"MaximumNumberOfSessions\":2,"
        "\"ActivatedSessionsType\":\"Shared\",\"AutoOSLockEnabled\":true,\"Actions\":{"
        "\"#KvmService.ExportKvmStartupFile\":{"
        "\"target\":\"/redfish/v1/Managers/Blade3/KvmService/Actions/KvmService.ExportKvmStartupFile\","
        "\"@Redfish.ActionInfo\":\"/redfish/v1/Managers/Blade3/KvmService/ExportKvmStartupFileActionInfo\"}}}";
    bc_huawei_kvm_resource r;
    assert(resource(good, &r) == BC_OK);
    assert(r.struct_size == sizeof(r) && r.flags == 15 && r.sessions == 1 && r.session_limit == 2);
    assert(r.session_mode == BC_HUAWEI_MODE_SHARED && r.auto_lock == 1);
    assert(!strcmp(r.export_uri, "/redfish/v1/Managers/Blade3/KvmService/Actions/KvmService.ExportKvmStartupFile"));
    assert(bc_huawei_kvm_resource_parse((const uint8_t *)good, (uint32_t)strlen(good),
        text("/redfish/v1/Managers/Blade3/KvmService"), &r) == BC_OK);
    assert(bc_huawei_kvm_resource_parse((const uint8_t *)good, (uint32_t)strlen(good),
        text("/redfish/v1/managers/Blade3/KVMSERVICE"), &r) == BC_OK);
    char body[4096];
    const char *id = strstr(good, "Blade3/kvmService"); assert(id);
    snprintf(body, sizeof(body), "%.*sBlade3/KvmService%s", (int)(id - good), good, id + strlen("Blade3/kvmService"));
    assert(resource(body, &r) == BC_OK);
    assert(bc_huawei_kvm_resource_parse((const uint8_t *)body, (uint32_t)strlen(body),
        text("/redfish/v1/Managers/Blade3/KvmService"), &r) == BC_OK);
    const char *bad[][2] = {
        {"Blade3/kvmService", "blade3/kvmService"},
        {"Blade3/kvmService", "Blade4/kvmService"},
        {"Blade3/KvmService/Actions", "Blade4/KvmService/Actions"},
        {"Blade3/KvmService/Export", "Blade4/KvmService/Export"},
        {"#HwKvmService.v1_0_0", "#HwKvmService.v9_0_0"},
        {"\"Shared\"", "\"Share\""},
        {"\"AutoOSLockEnabled\":true", "\"AutoOSLockEnabled\":1"},
        {"\"NumberOfActivatedSessions\":1", "\"NumberOfActivatedSessions\":-1"},
        {"\"MaximumNumberOfSessions\":2", "\"MaximumNumberOfSessions\":4294967296"},
        {"\"ActivatedSessionsType\":\"Shared\"", "\"ActivatedSessionsType\":null,\"ActivatedSessionsType\":null"},
        {"Blade3/KvmService/Export", "Blade3/../KvmService/Export"}
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        const char *at = strstr(good, bad[i][0]); assert(at);
        snprintf(body, sizeof(body), "%.*s%s%s", (int)(at - good), good, bad[i][1], at + strlen(bad[i][0]));
        memset(&r, 0xa5, sizeof(r)); assert(resource(body, &r) != BC_OK);
        assert(!r.struct_size && !r.flags && !r.export_uri[0] && !r.action_info_uri[0]);
    }
    assert(bc_huawei_kvm_resource_parse((const uint8_t *)good, (uint32_t)strlen(good),
        text("/redfish/v1/Managers/Blade4/kvmService"), &r) == BC_PROTOCOL_ERROR);
    assert(bc_huawei_kvm_resource_parse((const uint8_t *)good, (uint32_t)strlen(good),
        text("/redfish/v1/Managers/Blade3/../kvmService"), &r) == BC_INVALID_ARGUMENT);
    bc_huawei_kvm_action_info a;
    const char *mode = "[{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"String\","
        "\"AllowableValues\":[\"Shared\",\"Private\"]}]";
    assert(info(mode, &a) == BC_OK && a.parameters == BC_HUAWEI_PARAMETER_MODE &&
        a.required == BC_HUAWEI_PARAMETER_MODE && a.modes == 3);
    assert(info("[{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"Share\"]}]", &a) == BC_OK && !a.modes);
    assert(info("[{\"Name\":\"Mode\",\"Required\":false,\"DataType\":\"String\",\"AllowableValues\":[\"Shared\"]},"
        "{\"Name\":\"Type\",\"Required\":true,\"DataType\":\"String\"},"
        "{\"Name\":\"Content\",\"Required\":true,\"DataType\":\"String\"}]", &a) == BC_OK &&
        a.parameters == 7 && a.required == 6 && a.modes == BC_HUAWEI_MODE_SHARED);
    const char *invalid[] = {
        "[]", "{}", "[{}]",
        "[{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"Shared\",\"Shared\"]}]",
        "[{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"Shared\",4]}]",
        "[{\"Name\":\"Mode\",\"Required\":true,\"Required\":false,\"DataType\":\"String\",\"AllowableValues\":[\"Shared\"]}]",
        "[{\"Name\":\"Future\",\"Required\":true,\"DataType\":\"String\"}]",
        "[{\"Name\":\"Future\",\"Required\":false},{\"Name\":\"Future\",\"Required\":false}]",
        ("[{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"Shared\"]},"
        "{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"Private\"]}]"),
        "[{\"Name\":\"Mode\",\"Required\":true,\"DataType\":\"Integer\",\"AllowableValues\":[\"Shared\"]}]"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        memset(&a, 0xa5, sizeof(a)); assert(info(invalid[i], &a) != BC_OK);
        assert(!a.struct_size && !a.parameters && !a.modes);
    }
    assert(bc_huawei_kvm_action_info_parse(NULL, 0, &a) == BC_INVALID_ARGUMENT);
    snprintf(body, sizeof(body), "{\"@odata.type\":\"#ActionInfo.v1_4_2.ActionInfo\",\"Parameters\":%s}", mode);
    assert(bc_huawei_kvm_action_info_parse((const uint8_t *)body, (uint32_t)strlen(body), &a) == BC_OK && a.modes == 3);
    assert(bc_huawei_kvm_action_info_parse((const uint8_t *)"{}", 65537, &a) == BC_LIMIT_EXCEEDED);
    const char *manager = "{\"@odata.id\":\"/redfish/v1/Managers/Blade3\",\"Actions\":{\"Oem\":{\"Huawei\":{\"#Manager.GeneralDownload\":{\"target\":\"/redfish/v1/Managers/Blade3/Actions/Oem/Huawei/Manager.GeneralDownload\",\"@Redfish.ActionInfo\":\"/redfish/v1/Managers/Blade3/GeneralDownloadActionInfo\"}}}}}";
    bc_huawei_download_action download;
    bc_string manager_uri = text("/redfish/v1/Managers/Blade3");
    assert(bc_huawei_manager_download_parse((const uint8_t *)manager, (uint32_t)strlen(manager), manager_uri, &download) == BC_OK);
    assert(strstr(download.uri, "/Blade3/Actions/") && strstr(download.action_info_uri, "/Blade3/General"));
    for (size_t n = 0; n < strlen(manager); ++n) {
        memset(&download, 0xa5, sizeof(download));
        assert(bc_huawei_manager_download_parse((const uint8_t *)manager, (uint32_t)n, manager_uri, &download) != BC_OK);
        assert(!download.struct_size && !download.uri[0] && !download.action_info_uri[0]);
    }
    assert(bc_huawei_manager_download_parse((const uint8_t *)manager, (uint32_t)strlen(manager),
        text("/redfish/v1/Managers/Other"), &download) == BC_PROTOCOL_ERROR);
    const char *download_bad[][2] = {
        {"Blade3/Actions", "Blade4/Actions"},
        {"Blade3/General", "Blade4/General"},
        {"Huawei/Manager.GeneralDownload", "Public/Manager.GeneralDownload"},
        {"\"target\":", "\"target\":\"/wrong\",\"target\":"}
    };
    for (size_t i = 0; i < sizeof(download_bad) / sizeof(download_bad[0]); ++i) {
        const char *at = strstr(manager, download_bad[i][0]); assert(at);
        snprintf(body, sizeof(body), "%.*s%s%s", (int)(at - manager), manager,
            download_bad[i][1], at + strlen(download_bad[i][0]));
        assert(bc_huawei_manager_download_parse((const uint8_t *)body, (uint32_t)strlen(body),
            manager_uri, &download) != BC_OK && !download.struct_size && !download.uri[0]);
    }
    const char *absent = "{\"@odata.id\":\"/redfish/v1/Managers/Blade3\"}";
    assert(bc_huawei_manager_download_parse((const uint8_t *)absent, (uint32_t)strlen(absent),
        manager_uri, &download) == BC_UNSUPPORTED && !download.uri[0]);
    return 0;
}

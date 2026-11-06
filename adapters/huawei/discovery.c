#include "bcontrol/huawei_discovery.h"
#include "bcontrol/redfish.h"
#include "yyjson.h"
#include "../discovery_internal.h"
#include <string.h>

static int equal(yyjson_val *v, const char *s) {
    return yyjson_is_str(v) && yyjson_get_len(v) == strlen(s) &&
        !memcmp(yyjson_get_str(v), s, strlen(s));
}
static int unique(yyjson_val *obj) {
    if (!yyjson_is_obj(obj) || yyjson_obj_size(obj) > 128) return 0;
    size_t i, n; yyjson_val *key, *value;
    yyjson_obj_foreach(obj, i, n, key, value) {
        (void)value;
        yyjson_obj_iter iter = yyjson_obj_iter_with(obj);
        yyjson_val *other; unsigned matches = 0;
        while ((other = yyjson_obj_iter_next(&iter)))
            if (yyjson_get_len(key) == yyjson_get_len(other) &&
                !memcmp(yyjson_get_str(key), yyjson_get_str(other), yyjson_get_len(key))) ++matches;
        if (matches != 1) return 0;
    }
    return 1;
}
static bc_status document(const uint8_t *data, uint32_t length, yyjson_doc **doc) {
    *doc = NULL;
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > 65536) return BC_LIMIT_EXCEEDED;
    *doc = yyjson_read((const char *)data, length, 0);
    return *doc && unique(yyjson_doc_get_root(*doc)) ? BC_OK : BC_PROTOCOL_ERROR;
}
static int uri(yyjson_val *v, char *out, bc_string base) {
    if (!yyjson_is_str(v)) return 0;
    bc_string s = {yyjson_get_str(v), yyjson_get_len(v)};
    if (s.length > 1024 || s.length <= base.length ||
        !bc_redfish_uri_supported(s) ||
        !bc_discovery_uri_matches((bc_string){s.data, base.length}, base, "/redfish/v1/Managers/*") ||
        s.data[base.length] != '/') return 0;
    for (uint64_t i = 0; i < s.length; ++i)
        if (s.data[i] == '?' || s.data[i] == '%') return 0;
    memcpy(out, s.data, (size_t)s.length); out[s.length] = 0; return 1;
}
static int number(yyjson_val *root, const char *name, uint32_t flag,
    uint32_t *flags, uint32_t *out) {
    yyjson_val *v = yyjson_obj_get(root, name);
    if (!v) return 1;
    if (!yyjson_is_uint(v) || yyjson_get_uint(v) > UINT32_MAX) return 0;
    *flags |= flag; *out = (uint32_t)yyjson_get_uint(v); return 1;
}
static int action_info_type(yyjson_val *v) {
    if (!yyjson_is_str(v)) return 0;
    const char *s = yyjson_get_str(v), *prefix = "#ActionInfo.v1_";
    size_t at = strlen(prefix), length = yyjson_get_len(v);
    if (length <= at || memcmp(s, prefix, at)) return 0;
    for (unsigned part = 0; part < 2; ++part) {
        size_t start = at;
        while (at < length && s[at] >= '0' && s[at] <= '9') ++at;
        if (at == start || at == length || s[at++] != (part ? '.' : '_')) return 0;
    }
    return length - at == 10 && !memcmp(s + at, "ActionInfo", 10);
}
bc_status bc_huawei_kvm_resource_parse(const uint8_t *data, uint32_t length,
    bc_string resource_uri, bc_huawei_kvm_resource *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    static const char suffix[] = "/KvmService";
    if (resource_uri.length > 1024 ||
        !bc_discovery_uri_matches(resource_uri, resource_uri, "/redfish/v1/Managers/*/KvmService"))
        return BC_INVALID_ARGUMENT;
    size_t base = (size_t)resource_uri.length - (sizeof(suffix) - 1);
    yyjson_doc *doc; bc_status status = document(data, length, &doc);
    bc_huawei_kvm_resource result = {0}; result.struct_size = sizeof(result);
    if (status == BC_OK) {
        yyjson_val *root = yyjson_doc_get_root(doc), *id = yyjson_obj_get(root, "@odata.id");
        yyjson_val *actions = yyjson_obj_get(root, "Actions");
        yyjson_val *action = yyjson_obj_get(actions, "#KvmService.ExportKvmStartupFile");
        if (!equal(yyjson_obj_get(root, "@odata.type"), "#HwKvmService.v1_0_0.HwKvmService")) status = BC_UNSUPPORTED;
        else if (!yyjson_is_str(id) ||
            !bc_discovery_uri_matches(resource_uri, (bc_string){yyjson_get_str(id), yyjson_get_len(id)},
                "/redfish/v1/Managers/*/KvmService") ||
            !unique(actions) || !unique(action) ||
            !uri(yyjson_obj_get(action, "target"), result.export_uri, (bc_string){resource_uri.data, base}))
            status = BC_PROTOCOL_ERROR;
        else {
            bc_string target = {result.export_uri, strlen(result.export_uri)};
            if (!bc_discovery_uri_matches(target, target,
                "/redfish/v1/Managers/*/KvmService/Actions/KvmService.ExportKvmStartupFile")) status = BC_PROTOCOL_ERROR;
            yyjson_val *info = yyjson_obj_get(action, "@Redfish.ActionInfo");
            if (info && !uri(info, result.action_info_uri, (bc_string){resource_uri.data, base}))
                status = BC_PROTOCOL_ERROR;
        }
        if (status == BC_OK && (!number(root, "NumberOfActivatedSessions", BC_HUAWEI_SESSIONS_PRESENT,
                &result.flags, &result.sessions) ||
            !number(root, "MaximumNumberOfSessions", BC_HUAWEI_SESSION_LIMIT_PRESENT,
                &result.flags, &result.session_limit))) status = BC_PROTOCOL_ERROR;
        yyjson_val *mode = yyjson_obj_get(root, "ActivatedSessionsType");
        if (status == BC_OK && mode) {
            result.flags |= BC_HUAWEI_SESSION_MODE_PRESENT;
            if (equal(mode, "Shared")) result.session_mode = BC_HUAWEI_MODE_SHARED;
            else if (equal(mode, "Private")) result.session_mode = BC_HUAWEI_MODE_PRIVATE;
            else if (!yyjson_is_null(mode)) status = BC_UNSUPPORTED;
        }
        yyjson_val *lock = yyjson_obj_get(root, "AutoOSLockEnabled");
        if (status == BC_OK && lock) {
            if (!yyjson_is_bool(lock)) status = BC_PROTOCOL_ERROR;
            else { result.flags |= BC_HUAWEI_AUTO_LOCK_PRESENT; result.auto_lock = yyjson_is_true(lock); }
        }
    }
    if (doc) yyjson_doc_free(doc);
    if (status == BC_OK) *out = result;
    return status;
}
bc_status bc_huawei_kvm_action_info_parse(const uint8_t *data, uint32_t length,
    bc_huawei_kvm_action_info *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    yyjson_doc *doc; bc_status status = document(data, length, &doc);
    bc_huawei_kvm_action_info result = {sizeof(result), 0, 0, 0};
    if (status == BC_OK) {
        yyjson_val *root = yyjson_doc_get_root(doc), *params = yyjson_obj_get(root, "Parameters");
        if (!action_info_type(yyjson_obj_get(root, "@odata.type"))) status = BC_UNSUPPORTED;
        else if (!yyjson_is_arr(params) || yyjson_arr_size(params) > 64) status = BC_PROTOCOL_ERROR;
        else {
            size_t i, n; yyjson_val *p;
            yyjson_arr_foreach(params, i, n, p) {
                yyjson_val *name = yyjson_obj_get(p, "Name"), *required = yyjson_obj_get(p, "Required");
                uint32_t bit = equal(name, "Mode") ? BC_HUAWEI_PARAMETER_MODE :
                    equal(name, "Type") ? BC_HUAWEI_PARAMETER_TYPE :
                    equal(name, "Content") ? BC_HUAWEI_PARAMETER_CONTENT : 0;
                if (!unique(p) || !yyjson_is_str(name) || !yyjson_get_len(name) ||
                    !yyjson_is_bool(required) || (bit && result.parameters & bit)) { status = BC_PROTOCOL_ERROR; break; }
                for (size_t previous = 0; previous < i; ++previous) {
                    yyjson_val *old = yyjson_obj_get(yyjson_arr_get(params, previous), "Name");
                    if (yyjson_get_len(old) == yyjson_get_len(name) &&
                        !memcmp(yyjson_get_str(old), yyjson_get_str(name), yyjson_get_len(name)))
                        status = BC_PROTOCOL_ERROR;
                }
                if (status != BC_OK) break;
                if (!bit) { if (yyjson_is_true(required)) { status = BC_UNSUPPORTED; break; } continue; }
                result.parameters |= bit;
                if (yyjson_is_true(required)) result.required |= bit;
                if (!equal(yyjson_obj_get(p, "DataType"), "String")) { status = BC_UNSUPPORTED; break; }
                if (bit != BC_HUAWEI_PARAMETER_MODE) continue;
                yyjson_val *values = yyjson_obj_get(p, "AllowableValues"), *v;
                if (!yyjson_is_arr(values) || yyjson_arr_size(values) > 64) { status = BC_PROTOCOL_ERROR; break; }
                size_t j, count;
                yyjson_arr_foreach(values, j, count, v) {
                    if (!yyjson_is_str(v)) { status = BC_PROTOCOL_ERROR; break; }
                    uint32_t mode = equal(v, "Shared") ? BC_HUAWEI_MODE_SHARED :
                        equal(v, "Private") ? BC_HUAWEI_MODE_PRIVATE : 0;
                    if (mode && result.modes & mode) { status = BC_PROTOCOL_ERROR; break; }
                    result.modes |= mode;
                }
                if (status != BC_OK) break;
            }
            if (status == BC_OK && !(result.parameters & BC_HUAWEI_PARAMETER_MODE)) status = BC_UNSUPPORTED;
        }
    }
    if (doc) yyjson_doc_free(doc);
    if (status == BC_OK) *out = result;
    return status;
}

bc_status bc_huawei_manager_download_parse(const uint8_t *data, uint32_t length,
    bc_string manager_uri, bc_huawei_download_action *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    manager_uri = bc_discovery_resource_path(manager_uri);
    if (manager_uri.length > 1024 ||
        !bc_discovery_uri_matches(manager_uri, manager_uri, "/redfish/v1/Managers/*")) return BC_INVALID_ARGUMENT;
    yyjson_doc *doc;
    bc_status status = document(data, length, &doc);
    bc_huawei_download_action result = {0}; result.struct_size = sizeof(result);
    if (status == BC_OK) {
        yyjson_val *root = yyjson_doc_get_root(doc), *id = yyjson_obj_get(root, "@odata.id");
        yyjson_val *actions = yyjson_obj_get(root, "Actions");
        yyjson_val *oem = yyjson_obj_get(actions, "Oem");
        yyjson_val *huawei = yyjson_obj_get(oem, "Huawei");
        yyjson_val *action = yyjson_obj_get(huawei, "#Manager.GeneralDownload");
        if (!yyjson_is_str(id) || !bc_discovery_uri_matches(manager_uri,
            bc_discovery_resource_path((bc_string){yyjson_get_str(id), yyjson_get_len(id)}), "/redfish/v1/Managers/*")) status = BC_PROTOCOL_ERROR;
        else if ((actions && !unique(actions)) || (oem && !unique(oem)) ||
            (huawei && !unique(huawei))) status = BC_PROTOCOL_ERROR;
        else if (!action) status = BC_UNSUPPORTED;
        else if (!unique(action) || !uri(yyjson_obj_get(action, "target"), result.uri, manager_uri) ||
            !bc_discovery_uri_matches((bc_string){result.uri, strlen(result.uri)},
                (bc_string){result.uri, strlen(result.uri)},
                "/redfish/v1/Managers/*/Actions/Oem/Huawei/Manager.GeneralDownload")) status = BC_PROTOCOL_ERROR;
        if (status == BC_OK) {
            yyjson_val *info = yyjson_obj_get(action, "@Redfish.ActionInfo");
            if (info && !uri(info, result.action_info_uri, manager_uri)) status = BC_PROTOCOL_ERROR;
        }
    }
    if (doc) yyjson_doc_free(doc);
    if (status == BC_OK) *out = result;
    return status;
}

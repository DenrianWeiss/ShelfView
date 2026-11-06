#include "bcontrol/huawei_launch.h"
#include "bcontrol/redfish.h"
#include "yyjson.h"
#include "../discovery_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPORT 1u
#define DOWNLOAD 2u
struct bc_huawei_launch {
    bc_endpoint *endpoint;
    bc_request *request;
    bc_console_discovery *discovery;
    char *export_uri, *download_uri;
    char file[64];
    uint64_t generation, started, last_time;
    uint64_t (*clock_ms)(void *);
    void *clock_user;
    uint32_t timeout, phase, refs, contract, mode;
    int done, cancelled;
    bc_huawei_launch_result result;
    bc_huawei_launch_completion callback;
    void *user;
};
bc_status bc_huawei_launch_request_format(const uint8_t *data, uint32_t length,
    uint32_t *format, uint32_t *modes) {
    if (format) *format = 0;
    if (modes) *modes = 0;
    if (!format || !modes) return BC_INVALID_ARGUMENT;
    bc_huawei_kvm_action_info info;
    bc_status status = bc_huawei_kvm_action_info_parse(data, length, &info);
    if (status != BC_OK) return status;
    if (!(info.modes & BC_HUAWEI_MODE_SHARED)) return BC_UNSUPPORTED;
    uint32_t selected = BC_HUAWEI_LAUNCH_EXPORT_DIRECT;
    if (info.parameters != BC_HUAWEI_PARAMETER_MODE) {
        if (info.parameters != (BC_HUAWEI_PARAMETER_MODE | BC_HUAWEI_PARAMETER_TYPE |
            BC_HUAWEI_PARAMETER_CONTENT)) return BC_UNSUPPORTED;
        yyjson_doc *doc = yyjson_read((const char *)data, length, 0);
        if (!doc) return BC_PROTOCOL_ERROR;
        yyjson_val *params = yyjson_obj_get(yyjson_doc_get_root(doc), "Parameters");
        size_t i, count; yyjson_val *param; int uri = 0;
        yyjson_arr_foreach(params, i, count, param) {
            yyjson_val *name = yyjson_obj_get(param, "Name");
            if (yyjson_equals_str(name, "Content") && yyjson_obj_get(param, "AllowableValues")) {
                uri = 0; break;
            }
            if (!yyjson_equals_str(name, "Type")) continue;
            yyjson_val *values = yyjson_obj_get(param, "AllowableValues");
            if (!yyjson_is_arr(values) || yyjson_arr_size(values) > 64) break;
            size_t j, n; yyjson_val *value;
            yyjson_arr_foreach(values, j, n, value) {
                if (!yyjson_is_str(value)) { uri = 0; break; }
                if (yyjson_equals_str(value, "URI")) uri = 1;
            }
        }
        yyjson_doc_free(doc);
        if (!uri) return BC_UNSUPPORTED;
        selected = BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD;
    }
    *format = selected; *modes = info.modes;
    return BC_OK;
}
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static char *copy(bc_string s) {
    char *out = malloc((size_t)s.length + 1);
    if (out) { memcpy(out, s.data, (size_t)s.length); out[s.length] = 0; }
    return out;
}
static int targets(bc_string export_uri, bc_string download_uri, uint32_t contract) {
    static const char export_suffix[] = "/KvmService/Actions/KvmService.ExportKvmStartupFile";
    if (export_uri.length > 1024 || download_uri.length > 1024 ||
        !bc_discovery_uri_matches(export_uri, export_uri,
            "/redfish/v1/Managers/*/KvmService/Actions/KvmService.ExportKvmStartupFile")) return 0;
    size_t base = (size_t)export_uri.length - (sizeof(export_suffix) - 1);
    if (contract == BC_HUAWEI_LAUNCH_EXPORT_DIRECT) return !download_uri.length;
    return bc_discovery_uri_matches(download_uri, download_uri,
            "/redfish/v1/Managers/*/Actions/Oem/Huawei/Manager.GeneralDownload") &&
        download_uri.length > base && download_uri.data[base] == '/' &&
        bc_discovery_uri_matches((bc_string){export_uri.data, base}, (bc_string){download_uri.data, base},
            "/redfish/v1/Managers/*");
}
bc_status bc_huawei_launch_targets_validate(bc_string export_uri, bc_string download_uri, uint32_t format) {
    if (format != BC_HUAWEI_LAUNCH_EXPORT_DIRECT && format != BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD)
        return BC_UNSUPPORTED;
    return targets(export_uri, download_uri, format) ? BC_OK : BC_INVALID_ARGUMENT;
}
static bc_status remaining(bc_huawei_launch *op, uint32_t *out) {
    uint64_t now = op->clock_ms(op->clock_user);
    *out = 0;
    if (now < op->last_time) return BC_INVALID_ARGUMENT;
    op->last_time = now;
    if (now - op->started >= op->timeout) return BC_TIMEOUT;
    *out = op->timeout - (uint32_t)(now - op->started); return BC_OK;
}
static void fail(bc_huawei_launch *op, bc_status status, uint32_t cause) {
    bc_console_discovery_release(op->discovery); op->discovery = NULL;
    op->result.descriptor = NULL; op->result.status = status;
    op->result.failure = (bc_console_failure){sizeof(bc_console_failure), status, BC_CONSOLE_PHASE_LAUNCH,
        cause, 0, op->result.http_status, 0, BC_SERVICE_KVM, BC_SERVICE_FAMILY_HUAWEI};
}
static int unique_object(yyjson_val *object) {
    if (!yyjson_is_obj(object) || yyjson_obj_size(object) > 32) return 0;
    size_t i, count; yyjson_val *key, *value;
    yyjson_obj_foreach(object, i, count, key, value) {
        (void)value;
        yyjson_obj_iter iterator = yyjson_obj_iter_with(object);
        yyjson_val *other; unsigned matches = 0;
        while ((other = yyjson_obj_iter_next(&iterator)))
            if (yyjson_get_len(key) == yyjson_get_len(other) &&
                !memcmp(yyjson_get_str(key), yyjson_get_str(other), yyjson_get_len(key))) ++matches;
        if (matches != 1) return 0;
    }
    return 1;
}
static int base_message(yyjson_val *value, const char *name, unsigned minimum) {
    if (!yyjson_is_str(value)) return 0;
    const char *s = yyjson_get_str(value); size_t length = yyjson_get_len(value), at = 7;
    if (length <= at || memcmp(s, "Base.1.", at)) return 0;
    unsigned minor = 0; size_t first = at;
    while (at < length && s[at] >= '0' && s[at] <= '9') {
        if (minor > 10000) return 0;
        minor = minor * 10 + (unsigned)(s[at++] - '0');
    }
    return at > first && minor >= minimum && at < length && s[at++] == '.' &&
        length - at == strlen(name) && !memcmp(s + at, name, strlen(name));
}
static int shared_value_rejected(bc_request *request, const bc_response *response) {
    const bc_http_metadata *metadata = bc_request_http_metadata(request);
    if (response->http_status != 400 || (response->status != BC_OK && response->status != BC_HTTP_ERROR) ||
        !response->body.data || !response->body.length || response->body.length > 65536 ||
        !metadata || metadata->location.length || bc_request_auth_token(request).length) return 0;
    yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
    if (!doc) return 0;
    yyjson_val *root = yyjson_doc_get_root(doc), *error = yyjson_obj_get(root, "error");
    yyjson_val *messages = yyjson_obj_get(error, "@Message.ExtendedInfo");
    yyjson_val *message = yyjson_arr_get(messages, 0), *args = yyjson_obj_get(message, "MessageArgs");
    yyjson_val *action = yyjson_arr_get(args, 2), *code = yyjson_obj_get(error, "code");
    int eligible = unique_object(root) && yyjson_obj_size(root) == 1 && unique_object(error) &&
        yyjson_obj_size(error) <= 3 && (yyjson_obj_size(error) == 2 || yyjson_obj_get(error, "message")) &&
        (!yyjson_obj_get(error, "message") || yyjson_is_str(yyjson_obj_get(error, "message"))) &&
        (base_message(code, "GeneralError", 0) || base_message(code, "ActionParameterValueNotInList", 10)) &&
        yyjson_is_arr(messages) && yyjson_arr_size(messages) == 1 && unique_object(message) &&
        base_message(yyjson_obj_get(message, "MessageId"), "ActionParameterValueNotInList", 10) &&
        yyjson_is_arr(args) && yyjson_arr_size(args) == 3 &&
        yyjson_equals_str(yyjson_arr_get(args, 0), "Shared") && yyjson_equals_str(yyjson_arr_get(args, 1), "Mode") &&
        (yyjson_equals_str(action, "KvmService.ExportKvmStartupFile") ||
         yyjson_equals_str(action, "#KvmService.ExportKvmStartupFile"));
    yyjson_doc_free(doc); return eligible;
}
int bc_huawei_launch_private_eligible(const bc_console_failure *failure, uint32_t flags,
    uint32_t modes, int private_attempted) {
    return failure && failure->struct_size == sizeof(*failure) && !private_attempted &&
        failure->status == BC_UNSUPPORTED && failure->phase == BC_CONSOLE_PHASE_LAUNCH &&
        failure->cause == BC_CONSOLE_CAUSE_PROTOCOL && failure->http_status == 400 &&
        failure->service == BC_SERVICE_KVM && failure->family == BC_SERVICE_FAMILY_HUAWEI &&
        flags == (BC_HUAWEI_LAUNCH_EXPORT_SENT | BC_HUAWEI_LAUNCH_SHARED_MODE_REJECTED) &&
        modes == (BC_HUAWEI_MODE_SHARED | BC_HUAWEI_MODE_PRIVATE);
}
static void completed(bc_request *, const bc_response *, void *);
static bc_status submit(bc_huawei_launch *op, uint32_t phase) {
    op->phase = phase; op->result.http_status = 0;
    uint32_t timeout = 0; bc_status status = remaining(op, &timeout);
    if (status != BC_OK) return status;
    char body[256];
    const char *mode = op->mode == BC_HUAWEI_MODE_PRIVATE ? "Private" : "Shared";
    int size = phase == EXPORT && op->contract == BC_HUAWEI_LAUNCH_EXPORT_DIRECT ?
        snprintf(body, sizeof(body), "{\"Mode\":\"%s\"}", mode) : phase == EXPORT ? snprintf(body, sizeof(body),
        "{\"Type\":\"URI\",\"Content\":\"%s\",\"Mode\":\"%s\"}", op->file, mode) :
        snprintf(body, sizeof(body), "{\"TransferProtocol\":\"HTTPS\",\"Path\":\"%s\"}", op->file);
    if (size < 0 || (size_t)size >= sizeof(body)) return BC_LIMIT_EXCEEDED;
    bc_http_options request = {0}; request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION;
    request.path = text(phase == EXPORT ? op->export_uri : op->download_uri);
    request.method = BC_HTTP_POST; request.timeout_ms = timeout;
    request.body = (bc_bytes){(const uint8_t *)body, (uint32_t)size}; request.content_type = text("application/json");
    status = bc_http_submit(op->endpoint, &request, completed, op, &op->request);
    if (status == BC_OK) { ++op->refs; if (phase == EXPORT) op->result.flags |= BC_HUAWEI_LAUNCH_EXPORT_SENT; }
    return status;
}
static void completed(bc_request *request, const bc_response *response, void *user) {
    bc_huawei_launch *op = user;
    op->result.http_status = response->http_status;
    if (op->phase == EXPORT && response->status == BC_OK &&
        (response->http_status == 200 || (op->contract == BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD && response->http_status == 201)))
        op->result.flags |= BC_HUAWEI_LAUNCH_EXPORT_CONFIRMED;
    uint32_t unused; bc_status status = op->cancelled ? BC_CANCELLED : remaining(op, &unused);
    if (status == BC_OK) status = response->status;
    if (status == BC_OK && response->http_status != 200 &&
        !(op->phase == EXPORT && op->contract == BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD && response->http_status == 201))
        status = BC_HTTP_ERROR;
    if ((status == BC_OK || status == BC_HTTP_ERROR) &&
        (response->http_status == 401 || response->http_status == 403)) status = BC_AUTHENTICATION_FAILED;
    size_t first = 0;
    while (first < response->body.length &&
        (response->body.data[first] == ' ' || response->body.data[first] == '\t' ||
         response->body.data[first] == '\r' || response->body.data[first] == '\n')) ++first;
    int xml = first < response->body.length && response->body.data[first] == '<';
    if (status == BC_OK && op->phase == EXPORT &&
        op->contract == BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD && !xml) {
        bc_request_release(op->request); op->request = NULL;
        status = submit(op, DOWNLOAD);
        if (status == BC_OK) { bc_huawei_launch_release(op); return; }
    } else if (status == BC_OK) {
        status = bc_console_discovery_from_request(op->endpoint, op->generation, request, &op->discovery);
        if (status == BC_OK) {
            const bc_console_discovery_result *result = bc_console_discovery_result_get(op->discovery, op->endpoint, op->generation);
            status = result->status;
            if (status == BC_OK && (result->state != BC_CONSOLE_DISCOVERY_READY ||
                result->format != BC_CONSOLE_DESCRIPTOR_HUAWEI)) status = BC_PROTOCOL_ERROR;
            if (status == BC_OK) op->result.descriptor = result;
        }
    }
    if (status == BC_HTTP_ERROR && op->phase == EXPORT && op->mode == BC_HUAWEI_MODE_SHARED &&
        !op->cancelled && shared_value_rejected(request, response)) {
        op->result.flags |= BC_HUAWEI_LAUNCH_SHARED_MODE_REJECTED;
        status = BC_UNSUPPORTED;
    }
    if (status != BC_OK) fail(op, status, status == BC_AUTHENTICATION_FAILED ? BC_CONSOLE_CAUSE_AUTH_REJECTED :
        status == BC_PROTOCOL_ERROR || status == BC_UNSUPPORTED ? BC_CONSOLE_CAUSE_PROTOCOL : BC_CONSOLE_CAUSE_UNKNOWN);
    op->done = 1; op->callback(op, op->user); bc_huawei_launch_release(op);
}
static bc_status start(bc_endpoint *endpoint, const bc_huawei_launch_options *options,
    uint32_t mode, int confirmed, bc_huawei_launch_completion callback, void *user, bc_huawei_launch **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        !callback || !options->generation || !options->clock_ms || !options->timeout_ms || options->timeout_ms > INT32_MAX ||
        (confirmed != 0 && confirmed != 1))
        return BC_INVALID_ARGUMENT;
    if (options->contract != BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD &&
        options->contract != BC_HUAWEI_LAUNCH_EXPORT_DIRECT) return BC_UNSUPPORTED;
    if (!(options->modes & mode)) return BC_UNSUPPORTED;
    if (!bc_console_endpoint_is_https(endpoint)) return BC_UNSUPPORTED;
    if (!targets(options->export_uri, options->download_uri, options->contract))
        return BC_INVALID_ARGUMENT;
    if (options->contract == BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD &&
        (!options->nonce.data || options->nonce.length != 32)) return BC_INVALID_ARGUMENT;
    for (uint32_t i = 0; options->contract == BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD && i < 32; ++i) {
        unsigned char c = (unsigned char)options->nonce.data[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return BC_INVALID_ARGUMENT;
    }
    if (!confirmed) return BC_CONFIRMATION_REQUIRED;
    bc_huawei_launch *op = calloc(1, sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    op->refs = 1; op->endpoint = endpoint; bc_endpoint_retain(endpoint);
    op->callback = callback; op->user = user; op->generation = options->generation; op->contract = options->contract;
    op->mode = mode;
    op->clock_ms = options->clock_ms; op->clock_user = options->clock_user;
    op->started = op->last_time = op->clock_ms(op->clock_user); op->timeout = options->timeout_ms;
    op->result.struct_size = sizeof(op->result);
    op->export_uri = copy(options->export_uri);
    if (op->contract == BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD) {
        op->download_uri = copy(options->download_uri);
        snprintf(op->file, sizeof(op->file), "/tmp/web/kvm%.*s_kvm.jnlp", 32, options->nonce.data);
    }
    bc_status status = op->export_uri && (op->contract == BC_HUAWEI_LAUNCH_EXPORT_DIRECT || op->download_uri) ?
        submit(op, EXPORT) : BC_NO_MEMORY;
    if (status != BC_OK) { bc_huawei_launch_release(op); return status; }
    *out = op; return BC_OK;
}
bc_status bc_huawei_launch_start(bc_endpoint *endpoint, const bc_huawei_launch_options *options,
    bc_huawei_launch_completion callback, void *user, bc_huawei_launch **out) {
    return start(endpoint, options, BC_HUAWEI_MODE_SHARED, 1, callback, user, out);
}
bc_status bc_huawei_launch_start_private(bc_endpoint *endpoint, const bc_huawei_launch_options *options,
    int confirmed, bc_huawei_launch_completion callback, void *user, bc_huawei_launch **out) {
    return start(endpoint, options, BC_HUAWEI_MODE_PRIVATE, confirmed, callback, user, out);
}
const bc_huawei_launch_result *bc_huawei_launch_result_get(const bc_huawei_launch *op, const bc_endpoint *endpoint, uint64_t generation) {
    return op && op->done && op->endpoint == endpoint && op->generation == generation ? &op->result : NULL;
}
bc_status bc_huawei_launch_cancel(bc_huawei_launch *op) {
    if (!op) return BC_INVALID_ARGUMENT;
    op->cancelled = 1;
    if (op->done) { fail(op, BC_CANCELLED, BC_CONSOLE_CAUSE_UNKNOWN); return BC_OK; }
    return bc_request_cancel(op->request);
}
void bc_huawei_launch_release(bc_huawei_launch *op) {
    if (!op || --op->refs) return;
    bc_request_release(op->request); bc_console_discovery_release(op->discovery);
    bc_endpoint_release(op->endpoint); free(op->export_uri); free(op->download_uri);
    volatile unsigned char *p = (volatile unsigned char *)op;
    for (size_t i = 0; i < sizeof(*op); ++i) p[i] = 0;
    free(op);
}

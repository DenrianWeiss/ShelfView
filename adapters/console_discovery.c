#include "bcontrol/console_discovery.h"
#include "discovery_internal.h"
#include "yyjson.h"
#include <stdlib.h>
#include <string.h>

struct bc_console_discovery {
    bc_endpoint *endpoint;
    bc_request *request;
    uint32_t refs;
    int done, cancelled;
    bc_console_discovery_completion callback;
    void *user;
    bc_console_discovery_result result;
    bc_avocent_launch avocent;
    bc_aten_launch aten;
    char location[8193];
};
static void erase(void *data, size_t size) {
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}
int bc_console_endpoint_is_https(const bc_endpoint *endpoint) {
    bc_string origin = bc_endpoint_origin(endpoint);
    static const char prefix[] = "https://";
    if (origin.length < sizeof(prefix) - 1) return 0;
    for (size_t i = 0; i < sizeof(prefix) - 1; ++i) {
        unsigned char c = (unsigned char)origin.data[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)prefix[i]) return 0;
    }
    return 1;
}
static void clear_payload(bc_console_discovery *op) {
    erase(&op->avocent, sizeof(op->avocent));
    erase(&op->aten, sizeof(op->aten));
    erase(&op->result.megarac, sizeof(op->result.megarac));
    erase(&op->result.huawei, sizeof(op->result.huawei));
    erase(&op->result.idrac, sizeof(op->result.idrac));
    erase(op->location, sizeof(op->location));
    op->result.location = (bc_string){NULL, 0};
    memset(&op->result.profile, 0, sizeof(op->result.profile));
}
static void fail(bc_console_discovery *op, bc_status status, uint32_t cause) {
    clear_payload(op);
    op->result.state = BC_CONSOLE_DISCOVERY_FAILED; op->result.status = status;
    op->result.failure = (bc_console_failure){sizeof(bc_console_failure), status, BC_CONSOLE_PHASE_LAUNCH,
        cause, 0, op->result.http_status, 0, BC_SERVICE_KVM, 0};
}
static bc_status parse(bc_console_discovery *op, bc_bytes body) {
    if (!body.data || !body.length) return BC_PROTOCOL_ERROR;
    if (body.length > 65536) return BC_LIMIT_EXCEEDED;
    const uint8_t *p = body.data; uint32_t size = (uint32_t)body.length;
    while (size && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) { ++p; --size; }
    if (!size) return BC_PROTOCOL_ERROR;
    bc_console_discovery_result *r = &op->result;
    if (*p == '<') {
        bc_service_profile megarac_profile = {0}, huawei_profile = {0};
        bc_status megarac = bc_megarac_discover_jnlp(body.data, (uint32_t)body.length, &r->megarac, &megarac_profile);
        bc_status huawei = bc_huawei_kvm_discover_jnlp(body.data, (uint32_t)body.length, &r->huawei, &huawei_profile);
        bc_status avocent = bc_avocent_launch_parse(body.data, (uint32_t)body.length, &op->avocent);
        bc_status aten = bc_aten_launch_parse(body.data, (uint32_t)body.length, &op->aten);
        if ((megarac == BC_OK) + (huawei == BC_OK) + (avocent == BC_OK) + (aten == BC_OK) > 1) return BC_PROTOCOL_ERROR;
        if (aten == BC_OK) {
            r->profile = (bc_service_profile){sizeof(bc_service_profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_ATEN, 0, BC_SERVICE_EVIDENCE_DESCRIPTOR};
            r->format = BC_CONSOLE_DESCRIPTOR_ATEN; return BC_OK;
        }
        if (avocent == BC_OK) {
            r->profile = (bc_service_profile){sizeof(bc_service_profile),
                op->avocent.service == BC_AVOCENT_CONTROL ? BC_SERVICE_KVM : BC_SERVICE_LOCAL_MEDIA,
                BC_SERVICE_FAMILY_AVOCENT, op->avocent.service == BC_AVOCENT_MEDIA ? BC_SERVICE_AVOCENT_MEDIA_AVMP_CD : 0, BC_SERVICE_EVIDENCE_DESCRIPTOR};
            r->format = BC_CONSOLE_DESCRIPTOR_AVOCENT; return BC_OK;
        }
        if (megarac == BC_OK) { r->profile = megarac_profile; r->format = BC_CONSOLE_DESCRIPTOR_JVIEWER; return BC_OK; }
        if (huawei == BC_OK) { r->profile = huawei_profile; r->format = BC_CONSOLE_DESCRIPTOR_HUAWEI; return BC_OK; }
        return megarac == BC_LIMIT_EXCEEDED || huawei == BC_LIMIT_EXCEEDED || avocent == BC_LIMIT_EXCEEDED ? BC_LIMIT_EXCEEDED : BC_PROTOCOL_ERROR;
    }
    if (*p != '{') return BC_UNSUPPORTED;
    yyjson_doc *doc = yyjson_read((const char *)body.data, (size_t)body.length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    int location = yyjson_is_obj(root) && yyjson_obj_get(root, "Location") != NULL;
    int h5 = yyjson_is_obj(root) && yyjson_obj_get(root, "token") != NULL;
    if (doc) yyjson_doc_free(doc);
    bc_status h5_status = bc_megarac_discover_h5_config(body.data, (uint32_t)body.length, &r->megarac, &r->profile);
    uint32_t written = 0;
    bc_status idrac_status = bc_idrac_kvm_launch_location(body.data, (uint32_t)body.length,
        op->location, sizeof(op->location), &written);
    if (h5_status == BC_OK) {
        erase(op->location, sizeof(op->location)); r->format = BC_CONSOLE_DESCRIPTOR_H5; return BC_OK;
    }
    if (idrac_status == BC_OK) {
        memset(&r->profile, 0, sizeof(r->profile));
        r->format = BC_CONSOLE_DESCRIPTOR_IDRAC; r->state = BC_CONSOLE_DISCOVERY_NEEDS_URI;
        r->location = (bc_string){op->location, written}; return BC_OK;
    }
    if (h5_status == BC_LIMIT_EXCEEDED || idrac_status == BC_LIMIT_EXCEEDED) return BC_LIMIT_EXCEEDED;
    return location || h5 ? BC_PROTOCOL_ERROR : BC_UNSUPPORTED;

}
static void receive(bc_console_discovery *op, const bc_response *response) {
    op->result.http_status = response->http_status;
    bc_status status = op->cancelled ? BC_CANCELLED : response->status;
    if (status == BC_OK && response->http_status != 200) status = BC_HTTP_ERROR;
    if (response->http_status == 401 || response->http_status == 403) {
        if (status == BC_OK || status == BC_HTTP_ERROR) status = BC_AUTHENTICATION_FAILED;
    }
    if (status == BC_OK) {
        op->result.state = BC_CONSOLE_DISCOVERY_READY;
        status = parse(op, response->body);
    }
    if (status != BC_OK) fail(op, status, status == BC_AUTHENTICATION_FAILED ?
        BC_CONSOLE_CAUSE_AUTH_REJECTED : status == BC_PROTOCOL_ERROR || status == BC_UNSUPPORTED ?
        BC_CONSOLE_CAUSE_PROTOCOL : BC_CONSOLE_CAUSE_UNKNOWN);
    op->done = 1;
}
static void completed(bc_request *request, const bc_response *response, void *user) {
    (void)request;
    bc_console_discovery *op = user;
    receive(op, response);
    op->callback(op, op->user);
    bc_console_discovery_release(op);
}
bc_status bc_console_discovery_start(bc_endpoint *endpoint, const bc_console_discovery_options *options,
    bc_console_discovery_completion callback, void *user, bc_console_discovery **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !options || options->struct_size != sizeof(*options) ||
        options->abi_version != BC_ABI_VERSION || !callback || !options->generation ||
        !options->path.data || !options->path.length || options->path.length > 8192 ||
        options->path.data[0] != '/' || (options->path.length > 1 && options->path.data[1] == '/'))
        return BC_INVALID_ARGUMENT;
    for (uint64_t i = 0; i < options->path.length; ++i) {
        unsigned char c = (unsigned char)options->path.data[i];
        if (c < 33 || c > 126 || c == '\\' || c == '#') return BC_INVALID_ARGUMENT;
    }
    bc_console_discovery *op = calloc(1, sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    op->refs = 1; op->endpoint = endpoint; bc_endpoint_retain(endpoint);
    op->callback = callback; op->user = user;
    op->result.struct_size = sizeof(op->result);
    op->result.endpoint_revision = bc_endpoint_revision(endpoint); op->result.generation = options->generation;
    bc_http_options request = {0}; request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION;
    request.path = options->path; request.method = BC_HTTP_GET;
    request.timeout_ms = options->timeout_ms ? options->timeout_ms : 5000;
    request.headers = options->headers; request.header_count = options->header_count;
    bc_status status = bc_http_submit(endpoint, &request, completed, op, &op->request);
    if (status != BC_OK) { bc_console_discovery_release(op); return status; }
    ++op->refs; *out = op; return BC_OK;
}
bc_status bc_console_discovery_from_request(bc_endpoint *endpoint, uint64_t generation,
    bc_request *request, bc_console_discovery **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !generation || !request || bc_request_endpoint(request) != endpoint)
        return BC_INVALID_ARGUMENT;
    const bc_response *response = bc_request_response(request);
    if (!response) return BC_BUSY;
    bc_console_discovery *op = calloc(1, sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    op->refs = 1; op->endpoint = endpoint; bc_endpoint_retain(endpoint);
    op->request = request; bc_request_retain(request);
    op->result.struct_size = sizeof(op->result);
    op->result.endpoint_revision = bc_endpoint_revision(endpoint); op->result.generation = generation;
    receive(op, response); *out = op;
    return BC_OK;
}
const bc_console_discovery_result *bc_console_discovery_result_get(const bc_console_discovery *op,
    const bc_endpoint *endpoint, uint64_t generation) {
    return op && op->done && op->endpoint == endpoint && op->result.generation == generation ? &op->result : NULL;
}
bc_status bc_console_discovery_resolve_idrac(bc_console_discovery *op, const bc_endpoint *endpoint,
    uint64_t generation, const bc_idrac_launch_uri *uri, bc_string host, uint32_t port) {
    if (!bc_console_discovery_result_get(op, endpoint, generation)) return BC_INVALID_ARGUMENT;
    if (op->cancelled) return BC_CANCELLED;
    if (op->result.state != BC_CONSOLE_DISCOVERY_NEEDS_URI) return BC_INVALID_ARGUMENT;
    if (!bc_console_endpoint_is_https(endpoint)) { fail(op, BC_PROTOCOL_ERROR, BC_CONSOLE_CAUSE_PROTOCOL); return BC_PROTOCOL_ERROR; }
    const char *query = strchr(op->location, '?');
    if (!uri || !query || uri->query.length != strlen(query + 1) || !uri->query.data ||
        memcmp(uri->query.data, query + 1, (size_t)uri->query.length)) {
        fail(op, BC_PROTOCOL_ERROR, BC_CONSOLE_CAUSE_PROTOCOL); return BC_PROTOCOL_ERROR;
    }
    bc_status status = bc_idrac_kvm_discover_launch(uri, host, port, &op->result.idrac, &op->result.profile);
    if (status != BC_OK) fail(op, status, BC_CONSOLE_CAUSE_PROTOCOL);
    else { op->result.state = BC_CONSOLE_DISCOVERY_READY; erase(op->location, sizeof(op->location)); op->result.location = (bc_string){NULL, 0}; }
    return status;
}
const bc_avocent_launch *bc_console_discovery_avocent_get(const bc_console_discovery *op,
    const bc_endpoint *endpoint, uint64_t generation) {
    const bc_console_discovery_result *result = bc_console_discovery_result_get(op, endpoint, generation);
    return result && result->state == BC_CONSOLE_DISCOVERY_READY && result->status == BC_OK &&
        result->format == BC_CONSOLE_DESCRIPTOR_AVOCENT ? &op->avocent : NULL;
}
const bc_aten_launch *bc_console_discovery_aten_get(const bc_console_discovery *op,
    const bc_endpoint *endpoint, uint64_t generation) {
    const bc_console_discovery_result *r = bc_console_discovery_result_get(op, endpoint, generation);
    return r && r->state == BC_CONSOLE_DISCOVERY_READY && r->status == BC_OK &&
        r->format == BC_CONSOLE_DESCRIPTOR_ATEN ? &op->aten : NULL;
}
bc_status bc_console_discovery_cancel(bc_console_discovery *op) {
    if (!op) return BC_INVALID_ARGUMENT;
    op->cancelled = 1;
    if (op->done) { fail(op, BC_CANCELLED, BC_CONSOLE_CAUSE_UNKNOWN); return BC_OK; }
    return bc_request_cancel(op->request);
}
void bc_console_discovery_release(bc_console_discovery *op) {
    if (!op || --op->refs) return;
    bc_request_release(op->request); bc_endpoint_release(op->endpoint);
    erase(op, sizeof(*op)); free(op);
}

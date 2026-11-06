#include "../diagnostic_zip.h"
#include "bcontrol/jviewer_discovery.h"
#include "../discovery_internal.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

struct bc_jviewer_artifact {
    bc_endpoint *endpoint;
    bc_request *launch, *request;
    uint32_t refs, timeout;
    uint64_t started, last_time;
    uint64_t (*clock)(void *);
    void *clock_user;
    int done, cancelled, asset_invalid;
    bc_jviewer_artifact_completion callback;
    void *user;
    bc_jviewer_artifact_result result;
    bc_status resource_status, media_status;
    bc_service_profile media_hint;
    bc_status single_port_status; uint32_t single_port_default;
    bc_status token_default_status;
    uint32_t token_default;
};
static void erase(void *data, size_t length) {
    volatile uint8_t *p = data; while (length--) *p++ = 0;
}
static void fail(bc_jviewer_artifact *op, bc_status status) {
    memset(&op->result.hint, 0, sizeof(op->result.hint)); op->result.status = status;
    op->result.failure = (bc_console_failure){sizeof(bc_console_failure), status, BC_CONSOLE_PHASE_DISCOVERY,
        status == BC_AUTHENTICATION_FAILED ? BC_CONSOLE_CAUSE_AUTH_REJECTED :
        status == BC_PROTOCOL_ERROR || status == BC_UNSUPPORTED ? BC_CONSOLE_CAUSE_PROTOCOL : BC_CONSOLE_CAUSE_UNKNOWN,
        0, op->result.http_status, 0, BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC};
}
static bc_status remaining(bc_jviewer_artifact *op, uint32_t *out) {
    if (op->resource_status != BC_OK && op->resource_status != BC_BUSY) return op->resource_status;
    uint64_t now = op->clock(op->clock_user);
    if (now < op->last_time) { op->resource_status = BC_INVALID_ARGUMENT; return BC_INVALID_ARGUMENT; }
    op->last_time = now;
    if (now - op->started >= op->timeout) { op->resource_status = BC_TIMEOUT; return BC_TIMEOUT; }
    *out = op->timeout - (uint32_t)(now - op->started); return BC_OK;
}
static void completed(bc_request *request, const bc_response *response, void *user) {
    (void)request; bc_jviewer_artifact *op = user;
    op->result.http_status = response->http_status; uint32_t budget;
    bc_status status = op->cancelled ? BC_CANCELLED : remaining(op, &budget);
    if (status == BC_OK) status = response->status;
    if (status == BC_OK && response->http_status != 200) status = BC_HTTP_ERROR;
    if (status == BC_HTTP_ERROR && (response->http_status == 401 || response->http_status == 403)) status = BC_AUTHENTICATION_FAILED;
    if (status == BC_OK && response->body.length > 16 * 1024 * 1024) status = BC_LIMIT_EXCEEDED;
    op->resource_status = status;
    if (status == BC_OK) {
        op->media_status = bc_megarac_jviewer_jar_media_hint(response->body.data,
            (uint32_t)response->body.length,&op->media_hint);
        op->token_default_status = bc_megarac_jviewer_jar_token_default(response->body.data,
            (uint32_t)response->body.length, &op->token_default);
        op->single_port_status = bc_megarac_jviewer_jar_single_port_default(response->body.data,
            (uint32_t)response->body.length,&op->single_port_default);
        status = bc_megarac_jviewer_jar_evidence(response->body.data, (uint32_t)response->body.length, &op->result.hint);
        bc_status budget_status = remaining(op, &budget);
        if (budget_status != BC_OK) status = budget_status;
    }
    if (status != BC_OK) fail(op, status);
    op->done = 1; op->callback(op, op->user); bc_jviewer_artifact_release(op);
}
bc_status bc_jviewer_artifact_start(bc_endpoint *endpoint, bc_request *launch, const bc_jviewer_artifact_options *options,
    bc_jviewer_artifact_completion callback, void *user, bc_jviewer_artifact **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !launch || bc_request_endpoint(launch) != endpoint || !options ||
        options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        !options->generation || !options->clock_ms || !callback || !options->timeout_ms || options->timeout_ms > INT32_MAX)
        return BC_INVALID_ARGUMENT;
    if (!bc_console_endpoint_is_https(endpoint)) return BC_INVALID_ARGUMENT;
    const bc_response *source = bc_request_response(launch);
    if (!source) return BC_BUSY;
    /* Some old JViewer generators overstate the length. The strict XML parse
     * below still requires the complete document and its launch arguments. */
    if (source->status != BC_OK &&
        (source->status != BC_IO_ERROR || !(source->flags & BC_RESPONSE_EARLY_EOF))) return source->status;
    if (source->http_status == 401 || source->http_status == 403) return BC_AUTHENTICATION_FAILED;
    if (source->http_status != 200) return BC_HTTP_ERROR;
    if (source->body.length > 65536) return BC_LIMIT_EXCEEDED;
    uint64_t started = options->clock_ms(options->clock_user);
    bc_megarac_kvm_info info; bc_service_profile descriptor;
    bc_status status = bc_megarac_discover_jnlp(source->body.data, (uint32_t)source->body.length, &info, &descriptor);
    erase(&info, sizeof(info)); if (status != BC_OK) return status;
    bc_string path = bc_request_path(launch);
    if (!path.data) return BC_PROTOCOL_ERROR;
    const char *query = memchr(path.data, '?', (size_t)path.length);
    if (query) path.length = (uint64_t)(query - path.data);
    char resource[1025];
    status = bc_megarac_jviewer_resource_path(source->body.data, (uint32_t)source->body.length,
        bc_endpoint_origin(endpoint), path, resource, sizeof(resource));
    if (status != BC_OK) return status;
    bc_jviewer_artifact *op = calloc(1, sizeof(*op)); if (!op) return BC_NO_MEMORY;
    op->resource_status = BC_BUSY; op->media_status = BC_UNSUPPORTED;
    op->token_default_status = BC_UNSUPPORTED; op->single_port_status = BC_UNSUPPORTED;
    op->refs = 1; op->timeout = options->timeout_ms; op->started = op->last_time = started;
    op->clock = options->clock_ms; op->clock_user = options->clock_user;
    op->endpoint = endpoint; bc_endpoint_retain(endpoint); op->launch = launch; bc_request_retain(launch);
    op->callback = callback; op->user = user; op->result.struct_size = sizeof(op->result);
    op->result.endpoint_revision = bc_endpoint_revision(endpoint); op->result.generation = options->generation;
    uint32_t budget; status = remaining(op, &budget);
    if (status == BC_OK) {
        bc_http_options request = {0}; request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION;
        request.path = (bc_string){resource, strlen(resource)}; request.method = BC_HTTP_GET; request.timeout_ms = budget;
        request.headers = options->headers; request.header_count = options->header_count;
        status = bc_http_submit(endpoint, &request, completed, op, &op->request);
    }
    if (status != BC_OK) { bc_jviewer_artifact_release(op); return status; }
    ++op->refs; *out = op; return BC_OK;
}
const bc_jviewer_artifact_result *bc_jviewer_artifact_result_get(const bc_jviewer_artifact *op,
    const bc_endpoint *endpoint, uint64_t generation) {
    return op && op->done && op->endpoint == endpoint && op->result.generation == generation ? &op->result : NULL;
}
bc_request *bc_jviewer_artifact_asset_request_get(bc_jviewer_artifact *op,
    const bc_endpoint *endpoint, uint64_t generation, uint32_t kind) {
    if (!op || op->endpoint != endpoint || op->result.endpoint_revision != bc_endpoint_revision(endpoint) ||
        op->result.generation != generation || op->cancelled || op->asset_invalid ||
        (kind != BC_JVIEWER_ASSET_STARTUP && kind != BC_JVIEWER_ASSET_JAR)) return NULL;
    uint64_t now = op->clock(op->clock_user);
    if (now < op->last_time || now - op->started >= op->timeout) {
        op->asset_invalid = 1;
        op->resource_status = now < op->last_time ? BC_INVALID_ARGUMENT : BC_TIMEOUT;
        fail(op, op->resource_status); return NULL;
    }
    op->last_time = now;
    bc_request *request = kind == BC_JVIEWER_ASSET_STARTUP ? op->launch : op->request;
    const bc_response *response = bc_request_response(request);
    if (kind == BC_JVIEWER_ASSET_JAR && (!response || !bc_diagnostic_zip_valid(response->body.data, response->body.length))) return NULL;
    return request && bc_request_endpoint(request) == endpoint && response && response->status == BC_OK &&
        response->http_status == 200 && response->body.length <= (kind == BC_JVIEWER_ASSET_STARTUP ? 65536u : 16u*1024u*1024u) ? request : NULL;
}
bc_status bc_jviewer_artifact_resolve(bc_jviewer_artifact *op, const bc_endpoint *endpoint, uint64_t generation,
    bc_megarac_kvm_info *info, bc_service_profile *profile) {
    if (!info || !profile) return BC_INVALID_ARGUMENT;
    memset(info,0,sizeof(*info)); memset(profile,0,sizeof(*profile));
    if (!op || op->endpoint != endpoint || op->result.generation != generation) return BC_INVALID_ARGUMENT;
    if (!op->done) return BC_BUSY;
    if (op->result.status != BC_OK) return op->result.status;
    uint32_t budget; bc_status status = remaining(op,&budget);
    if (status != BC_OK) { fail(op,status); return status; }
    const bc_response *source = bc_request_response(op->launch);
    bc_service_profile descriptor; bc_megarac_kvm_info parsed;
    status = bc_megarac_discover_jnlp(source->body.data,(uint32_t)source->body.length,&parsed,&descriptor);
    if (status == BC_OK) {
        status = remaining(op,&budget);
        if (status != BC_OK) fail(op,status);
    }
    if (status == BC_OK && op->result.hint.service == BC_SERVICE_KVM && op->result.hint.family == BC_SERVICE_FAMILY_MEGARAC &&
        (op->result.hint.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195 || op->result.hint.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_373)) {
        descriptor.variant = op->result.hint.variant; descriptor.evidence |= BC_SERVICE_EVIDENCE_HINT;
        parsed.kind = descriptor.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195 ? BC_MEGARAC_KVM_JVIEWER_195 : BC_MEGARAC_KVM_JVIEWER;
        *info = parsed; *profile = descriptor;
    } else if (status == BC_OK) status = BC_UNSUPPORTED;
    erase(&parsed,sizeof(parsed)); return status;
}
bc_status bc_jviewer_artifact_media_hint(bc_jviewer_artifact *op, const bc_endpoint *endpoint,
    uint64_t generation, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    if (!op || op->endpoint != endpoint || op->result.generation != generation) return BC_INVALID_ARGUMENT;
    if (!op->done) return BC_BUSY;
    if (op->cancelled) return BC_CANCELLED;
    if (op->resource_status != BC_OK) return op->resource_status;
    uint32_t budget; bc_status status = remaining(op,&budget);
    if (status != BC_OK) return status;
    if (op->media_status != BC_OK) return op->media_status;
    *out = op->media_hint; return BC_OK;
}
bc_status bc_jviewer_artifact_media_parameters(bc_jviewer_artifact *op, const bc_endpoint *endpoint,
    uint64_t generation, bc_megarac_media_parameters *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!op || op->endpoint != endpoint || op->result.generation != generation) return BC_INVALID_ARGUMENT;
    if (!op->done) return BC_BUSY;
    if (op->cancelled) return BC_CANCELLED;
    if (op->resource_status != BC_OK) return op->resource_status;
    uint32_t budget;
    bc_status status = remaining(op, &budget);
    if (status != BC_OK) return status;
    const bc_response *source = bc_request_response(op->launch);
    const bc_response *archive = bc_request_response(op->request);
    bc_megarac_media_parameters params;
    status = bc_megarac_jviewer_media_parameters_with_jar(source->body.data, (uint32_t)source->body.length,
        archive->body, &params);
    if (status == BC_OK && !(params.flags & BC_MEGARAC_MEDIA_TOKEN_TYPE_PRESENT)) {
        if (op->token_default_status != BC_OK) status = op->token_default_status;
        else {
            params.token_type = op->token_default;
            params.flags |= BC_MEGARAC_MEDIA_TOKEN_TYPE_RESOURCE_DEFAULT;
        }
    }
    if (status == BC_OK && !(params.flags & BC_MEGARAC_MEDIA_SINGLE_PORT_PRESENT)) {
        if (op->single_port_status != BC_OK) status = op->single_port_status;
        else {
            params.single_port = op->single_port_default;
            params.flags |= BC_MEGARAC_MEDIA_SINGLE_PORT_RESOURCE_DEFAULT;
        }
    }
    if (status == BC_OK) status = remaining(op, &budget);
    if (status == BC_OK) *out = params;
    return status;
}
bc_status bc_jviewer_artifact_media_resolve(bc_jviewer_artifact *op, const bc_endpoint *endpoint,
    uint64_t generation, bc_service_profile *profile, bc_megarac_media_parameters *out) {
    if (profile) memset(profile, 0, sizeof(*profile));
    if (out) memset(out, 0, sizeof(*out));
    if (!profile || !out || !op || op->endpoint != endpoint ||
        op->result.endpoint_revision != bc_endpoint_revision(endpoint) || op->result.generation != generation)
        return BC_INVALID_ARGUMENT;
    bc_service_profile hint;
    bc_status status = bc_jviewer_artifact_media_hint(op, endpoint, generation, &hint);
    if (status == BC_OK && (hint.struct_size != sizeof(hint) || hint.service != BC_SERVICE_LOCAL_MEDIA ||
        hint.family != BC_SERVICE_FAMILY_MEGARAC || hint.variant != BC_SERVICE_MEGARAC_MEDIA_IUSB_CD ||
        hint.evidence != BC_SERVICE_EVIDENCE_HINT)) status = BC_UNSUPPORTED;
    bc_megarac_media_parameters params;
    if (status == BC_OK) status = bc_jviewer_artifact_media_parameters(op, endpoint, generation, &params);
    if (status == BC_OK && !bc_megarac_media_parameters_transport_usable(&params)) status = BC_UNSUPPORTED;
    bc_megarac_kvm_info launch = {0}; bc_service_profile descriptor;
    if (status == BC_OK) {
        const bc_response *source = bc_request_response(op->launch);
        status = bc_megarac_discover_jnlp(source->body.data, (uint32_t)source->body.length, &launch, &descriptor);
        if (status == BC_OK && (!launch.token[0] || strlen(launch.token) > 97)) status = BC_UNSUPPORTED;
    }
    uint32_t budget;
    if (status == BC_OK) status = remaining(op, &budget);
    if (status == BC_OK) {
        hint.evidence |= BC_SERVICE_EVIDENCE_DESCRIPTOR;
        *profile = hint; *out = params;
    }
    erase(&launch, sizeof(launch)); return status;
}
bc_status bc_jviewer_artifact_cancel(bc_jviewer_artifact *op) {
    if (!op) return BC_INVALID_ARGUMENT;
    op->cancelled = 1;
    if (op->done) { fail(op, BC_CANCELLED); return BC_OK; }
    return bc_request_cancel(op->request);
}
void bc_jviewer_artifact_release(bc_jviewer_artifact *op) {
    if (!op || --op->refs) return;
    bc_request_release(op->request); bc_request_release(op->launch); bc_endpoint_release(op->endpoint);
    erase(op, sizeof(*op)); free(op);
}

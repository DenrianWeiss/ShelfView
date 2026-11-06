#include "internal.h"
#include "../discovery_internal.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    char path[1025];
    bc_request *request;
    uint32_t kind, depth;
    uint64_t parents, expanded;
    int valid;
    bc_web_login_hint hint;
    uint32_t transport;
} node;
struct bc_web_entry_graph {
    bc_endpoint *endpoint;
    bc_web_session *session;
    bc_web_entry_options options;
    bc_web_entry_result result;
    bc_web_entry_completion callback;
    void *user;
    uint64_t started, last_time;
    uint32_t refs, count, current;
    int done, cancelled, login_permit_issued, authenticated, diagnostics_invalid;
    bc_console_discovery *launch;
    uint32_t launch_node, service;
    uint32_t transport, limit_reason, limit_node, limit_depth, hard_limits;
    uint32_t html_owner, script_owner;
    uint64_t limit_observed, limit_maximum;
    node nodes[64];
};
typedef struct { bc_web_entry_graph *op; uint32_t page, depth; } link_context;
static bc_status limited(bc_web_entry_graph *op, uint32_t reason, uint32_t source,
    uint32_t depth, uint64_t observed, uint64_t maximum) {
    int hard = reason != BC_WEB_LIMIT_SCRIPT_PARSE && reason != BC_WEB_LIMIT_HTML_PARSE;
    if (hard) ++op->hard_limits;
    if (!op->limit_reason || (hard && (op->limit_reason == BC_WEB_LIMIT_SCRIPT_PARSE || op->limit_reason == BC_WEB_LIMIT_HTML_PARSE))) {
        op->limit_reason = reason; op->limit_node = source; op->limit_depth = depth;
        op->limit_observed = observed; op->limit_maximum = maximum;
    }
    return BC_LIMIT_EXCEEDED;
}
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static void clear_hint(bc_web_entry_graph *op) {
    memset(&op->result.hint, 0, sizeof(op->result.hint));
    op->result.page_path[0] = op->result.script_path[0] = 0;
    op->transport = 0;
}
static bc_status remaining(bc_web_entry_graph *op, uint32_t *ms) {
    if (op->cancelled) return BC_CANCELLED;
    if (op->result.status != BC_BUSY && op->result.status != BC_OK) return op->result.status;
    uint64_t now = op->options.clock_ms(op->options.clock_user);
    bc_status status = BC_OK;
    if (now < op->last_time) status = BC_INVALID_ARGUMENT;
    else if (now - op->started >= op->options.timeout_ms) status = BC_TIMEOUT;
    op->last_time = now;
    if (status != BC_OK) { op->result.status = status; clear_hint(op); return status; }
    *ms = op->options.timeout_ms - (uint32_t)(now - op->started);
    return BC_OK;
}
static void finish(bc_web_entry_graph *op, bc_status status) {
    op->done = 1; op->result.status = status;
    if (status != BC_OK) clear_hint(op);
    op->callback(op, op->user);
}
static int asset(const char *path, uint32_t kind) {
    size_t length = strcspn(path, "?");
    if (kind == BC_WEB_LINK_HTML && length == 1 && path[0] == '/') return 1;
    if (kind == BC_WEB_LINK_HTML && !strncmp(path, "/cgi/url_redirect.cgi?url_name=", 29)) return 1;
    const char *extensions[] = {kind == BC_WEB_LINK_SCRIPT ? ".js" : ".html", ".htm"};
    unsigned count = kind == BC_WEB_LINK_SCRIPT ? 1 : 2;
    for (unsigned i = 0; i < count; ++i) {
        size_t n = strlen(extensions[i]);
        if (length >= n && !memcmp(path + length - n, extensions[i], n)) return 1;
    }
    return 0;
}
static bc_status add(link_context *, uint32_t, bc_string);
static bc_status link(void *, uint32_t, bc_string);
static bc_status script_links(bc_web_entry_graph *, uint32_t, link_context *, const uint8_t *, uint32_t);
static bc_status add(link_context *context, uint32_t kind, bc_string target) {
    bc_web_entry_graph *op = context->op;
    if (kind == BC_WEB_LINK_NAVIGATION) {
        if (!op->authenticated) { ++op->result.skipped_links; return BC_OK; }
        kind = BC_WEB_LINK_HTML;
    }
    if (kind == BC_WEB_LINK_INLINE) {
        if (!target.length) return BC_OK;
        bc_status status = script_links(op, context->page, context, (const uint8_t *)target.data, (uint32_t)target.length);
        if (status == BC_UNSUPPORTED || status == BC_PROTOCOL_ERROR) { ++op->result.unsupported_scripts; return BC_OK; }
        if (status == BC_LIMIT_EXCEEDED) limited(op, BC_WEB_LIMIT_SCRIPT_PARSE, context->page, context->depth, target.length, 0);
        return status;
    }
    char path[1025];
    if (!bc_web_login_resolve_path(text(op->nodes[context->page].path), target, path)) {
        ++op->result.skipped_links; return BC_OK;
    }
    size_t path_length = strcspn(path, "?");
    if (op->authenticated && (kind == BC_WEB_LINK_STARTUP ||
        (kind == BC_WEB_LINK_HTML && ((path_length >= 5 && !memcmp(path + path_length - 5, ".jnlp", 5)) ||
        !strcmp(path, "/cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk") ||
        !strcmp(path, "/cgi/url_redirect.cgi?url_name=man_ikvm&url_type=jwsk"))))) {
        kind = BC_WEB_LINK_STARTUP;
        if (!op->service) for (uint32_t i = 0; i < op->count; ++i) if (op->nodes[i].kind == BC_WEB_LINK_STARTUP && strcmp(op->nodes[i].path, path)) return BC_UNSUPPORTED;
    } else if (!asset(path, kind)) { ++op->result.skipped_links; return BC_OK; }
    for (uint32_t i = 0; i < op->count; ++i) {
        node *n = op->nodes + i;
        if (strcmp(n->path, path)) continue;
        if (n->kind != kind) return BC_PROTOCOL_ERROR;
        n->parents |= UINT64_C(1) << context->page;
        return BC_OK;
    }
    if (context->depth > op->options.max_depth) return limited(op, BC_WEB_LIMIT_DEPTH, context->page, context->depth, context->depth, op->options.max_depth);
    if (op->count == (op->authenticated ? 64u : op->options.max_requests)) return limited(op, BC_WEB_LIMIT_CANDIDATES, context->page, context->depth, op->count + 1, op->authenticated ? 64u : op->options.max_requests);
    node *n = op->nodes + op->count++;
    strcpy(n->path, path); n->kind = kind; n->depth = context->depth;
    n->parents = UINT64_C(1) << context->page;
    return BC_OK;
}
static bc_status link(void *user, uint32_t kind, bc_string target) { return add(user, kind, target); }
static bc_status script_links(bc_web_entry_graph *op, uint32_t source, link_context *context,
    const uint8_t *data, uint32_t length) {
    node *saved = malloc(sizeof(op->nodes));
    if (!saved) return BC_NO_MEMORY;
    memcpy(saved, op->nodes, sizeof(op->nodes));
    uint32_t count = op->count, skipped = op->result.skipped_links, hard = op->hard_limits;
    bc_status status = bc_web_login_script_origin_links(data, length,
        op->authenticated ? bc_endpoint_origin(op->endpoint) : (bc_string){0}, link, context);
    if (status == BC_LIMIT_EXCEEDED && op->hard_limits == hard) {
        memcpy(op->nodes, saved, sizeof(op->nodes)); op->count = count;
        op->result.skipped_links = skipped;
        limited(op, BC_WEB_LIMIT_SCRIPT_PARSE, source, op->nodes[source].depth, length, 0);
        if (op->nodes[source].kind == BC_WEB_LINK_SCRIPT) {
            op->nodes[source].valid = 0;
            memset(&op->nodes[source].hint, 0, sizeof(op->nodes[source].hint));
            op->nodes[source].transport = 0;
        }
        status = BC_UNSUPPORTED;
    }
    free(saved); return status;
}
static bc_status expand_scripts(bc_web_entry_graph *op) {
    for (uint32_t i = 0; i < op->count; ++i) {
        node *n = op->nodes + i;
        if (!n->valid || n->kind != BC_WEB_LINK_SCRIPT) continue;
        const bc_response *response = bc_request_response(n->request);
        uint64_t pending = n->parents & ~n->expanded;
        for (uint32_t j = 0; j < op->count; ++j) {
            if (!(pending & (UINT64_C(1) << j))) continue;
            n->expanded |= UINT64_C(1) << j;
            link_context context = {op, j, op->nodes[j].depth + 2};
            bc_status status = script_links(op, i, &context, response->body.data, (uint32_t)response->body.length);
            if (status == BC_UNSUPPORTED || status == BC_PROTOCOL_ERROR || status == BC_INVALID_ARGUMENT) { ++op->result.unsupported_scripts; if (!n->valid) break; continue; }
            if (status == BC_LIMIT_EXCEEDED) limited(op, BC_WEB_LIMIT_SCRIPT_PARSE, i, n->depth, response->body.length, 0);
            if (status != BC_OK) return status;
        }
    }
    return BC_OK;
}
static bc_status collect(bc_web_entry_graph *op) {
    clear_hint(op);
    for (uint32_t i = 0; i < op->count; ++i) {
        node *page = op->nodes + i;
        if (!page->valid || page->kind != BC_WEB_LINK_HTML) continue;
        const bc_response *response = bc_request_response(page->request);
        bc_web_login_hint hint;
        if (bc_web_login_form_hint(response->body.data, (uint32_t)response->body.length, &hint) != BC_OK) continue;
        if (op->result.hint.kind) return BC_UNSUPPORTED;
        op->result.hint = hint; strcpy(op->result.page_path, page->path);
    }
    for (uint32_t i = 0; i < op->count; ++i) {
        node *js = op->nodes + i;
        if (!js->valid || !js->hint.kind) continue;
        for (uint32_t j = 0; j < op->count; ++j) {
            node *page = op->nodes + j;
            if (!page->valid || page->kind != BC_WEB_LINK_HTML || !(js->parents & (UINT64_C(1) << j))) continue;
            const bc_response *html = bc_request_response(page->request);
            bc_status status = bc_web_login_page_matches(html->body.data, (uint32_t)html->body.length,
                text(page->path), text(js->path), &js->hint);
            if (status != BC_OK) continue;
            if (op->result.hint.kind && memcmp(&op->result.hint, &js->hint, sizeof(js->hint))) return BC_UNSUPPORTED;
            op->result.hint = js->hint;
            strcpy(op->result.page_path, page->path); strcpy(op->result.script_path, js->path);
        }
    }
    return op->result.hint.kind ? BC_OK : BC_UNSUPPORTED;
}
static void collect_transport(bc_web_entry_graph *op) {
    for (uint32_t p = 0; p < op->count; ++p) {
        node *page = op->nodes + p;
        if (!page->valid || page->kind != BC_WEB_LINK_HTML || strcmp(page->path, op->result.page_path)) continue;
        const bc_response *response = bc_request_response(page->request);
        for (uint32_t i = 0; i < op->count; ++i) {
            node *js = op->nodes + i;
            if (!js->valid || !js->transport || !(js->parents & (UINT64_C(1) << p))) continue;
            if (bc_web_login_page_library_matches(response->body.data, (uint32_t)response->body.length,
                text(page->path), text(js->path), text(op->result.script_path), &op->result.hint) != BC_OK) continue;
            if (op->transport) { op->transport = 0; return; }
            op->transport = js->transport;
        }
    }
}
static int next_kind(bc_web_entry_graph *op, uint32_t kind, uint32_t *last_owner) {
    uint32_t begin = *last_owner == UINT32_MAX ? 0 : (*last_owner + 1) % op->count;
    for (uint32_t step = 0; step < op->count; ++step) {
        uint32_t owner = (begin + step) % op->count;
        for (uint32_t i = 0; i < op->count; ++i) {
            node *n = op->nodes + i;
            if (n->kind != kind || n->request || !(n->parents & (UINT64_C(1) << owner))) continue;
            op->current = i; *last_owner = owner; return 1;
        }
    }
    return 0;
}
static int next(bc_web_entry_graph *op) {
    if (!op->authenticated) return ++op->current < op->count;
    for (uint32_t i = 0; i < op->count; ++i) {
        if (op->nodes[i].kind == BC_WEB_LINK_STARTUP && !op->nodes[i].request) { op->current = i; return 1; }
    }
    if (op->nodes[op->current].kind == BC_WEB_LINK_HTML) {
        uint32_t owner = op->current;
        uint64_t parent = UINT64_C(1) << owner;
        for (unsigned shared = 0; shared < 2; ++shared) {
            for (uint32_t i = 0; i < op->count; ++i) {
                node *n = op->nodes + i;
                if (n->kind != BC_WEB_LINK_SCRIPT || n->request || !(n->parents & parent) ||
                    (!shared && n->parents != parent)) continue;
                op->current = i; op->script_owner = owner; return 1;
            }
        }
    }
    int script_first = op->nodes[op->current].kind != BC_WEB_LINK_SCRIPT;
    if (script_first && next_kind(op, BC_WEB_LINK_SCRIPT, &op->script_owner)) return 1;
    if (next_kind(op, BC_WEB_LINK_HTML, &op->html_owner)) return 1;
    return next_kind(op, BC_WEB_LINK_SCRIPT, &op->script_owner);
}
static bc_status submit(bc_web_entry_graph *);
static void completed(bc_request *request, const bc_response *response, void *user) {
    bc_web_entry_graph *op = user; uint32_t budget;
    bc_status status = remaining(op, &budget);
    node *n = op->nodes + op->current;
    if (request != n->request) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK && response->body.length > 262144)
        status = limited(op, BC_WEB_LIMIT_RESPONSE_BYTES, op->current, n->depth, response->body.length, 262144);
    if (status == BC_OK && response->body.length > op->options.max_bytes - op->result.bytes)
        status = limited(op, BC_WEB_LIMIT_TOTAL_BYTES, op->current, n->depth, op->result.bytes + response->body.length, op->options.max_bytes);
    if (status == BC_OK && response->status == BC_LIMIT_EXCEEDED)
        status = limited(op, BC_WEB_LIMIT_TRANSPORT_BODY, op->current, n->depth, response->body.length, 0);
    if (status == BC_OK) {
        op->result.bytes += response->body.length;
        if (response->status != BC_OK && response->status != BC_HTTP_ERROR) {
            ++op->result.failed_requests; status = response->status;
        }
        else if (response->http_status == 301 || response->http_status == 302 || response->http_status == 303 || response->http_status == 307 || response->http_status == 308) {
            const bc_http_metadata *metadata = bc_request_http_metadata(request);
            link_context context = {op, op->current, n->depth + 1};
            if (!metadata || !metadata->location.length || n->kind != BC_WEB_LINK_HTML) ++op->result.skipped_links;
            else status = add(&context, BC_WEB_LINK_HTML, metadata->location);
        } else if (response->http_status != 200) {
            ++op->result.failed_requests;
            if (op->authenticated && (response->http_status == 401 || response->http_status == 403)) status = BC_AUTHENTICATION_FAILED;
            else if (!op->current) status = response->http_status == 401 || response->http_status == 403 ? BC_AUTHENTICATION_FAILED : BC_HTTP_ERROR;
        }
        else if (n->kind == BC_WEB_LINK_STARTUP) {
            status = bc_console_discovery_from_request(op->endpoint, op->options.generation, request, &op->launch);
            if (status == BC_OK) {
                const bc_console_discovery_result *launch = bc_console_discovery_result_get(op->launch, op->endpoint, op->options.generation);
                status = launch && launch->state == BC_CONSOLE_DISCOVERY_READY ? launch->status : BC_UNSUPPORTED;
            }
            if (status == BC_OK) {
                const bc_console_discovery_result *launch = bc_console_discovery_result_get(op->launch, op->endpoint, op->options.generation);
                if (op->service && launch->profile.service != op->service && launch->format != BC_CONSOLE_DESCRIPTOR_ATEN) {
                    bc_console_discovery_release(op->launch); op->launch = NULL;
                } else { n->valid = 1; op->launch_node = op->current; }
            }
        }
        else if (n->kind == BC_WEB_LINK_HTML) {
            link_context context = {op, op->current, n->depth + 1};
            status = bc_web_login_html_links(response->body.data, (uint32_t)response->body.length, link, &context);
            if (status == BC_LIMIT_EXCEEDED) limited(op, BC_WEB_LIMIT_HTML_PARSE, op->current, n->depth, response->body.length, 0);
            if (status == BC_OK) n->valid = 1;
            else if (status == BC_PROTOCOL_ERROR || status == BC_UNSUPPORTED || status == BC_INVALID_ARGUMENT) { ++op->result.skipped_links; status = BC_OK; }
        } else {
            n->valid = 1;
            (void)bc_web_login_script_hint(response->body.data, (uint32_t)response->body.length, &n->hint);
            (void)bc_web_login_xmit_form_hint(response->body.data, (uint32_t)response->body.length, &n->transport);
        }
    }
    if (status == BC_OK && op->launch) {
        status = remaining(op, &budget); finish(op, status); bc_web_entry_release(op); return;
    }
    if (status == BC_OK) status = expand_scripts(op);
    if (status == BC_OK) status = remaining(op, &budget);
    if (status == BC_OK && next(op)) status = submit(op);
    else if (status == BC_OK) {
        status = op->authenticated ? BC_UNSUPPORTED : collect(op);
        if (status == BC_OK) collect_transport(op);
        if (status == BC_OK) status = remaining(op, &budget);
        finish(op, status);
    }
    if (status != BC_OK && !op->done) finish(op, status);
    bc_web_entry_release(op);
}
static bc_status submit(bc_web_entry_graph *op) {
    uint32_t budget; bc_status status = remaining(op, &budget);
    if (status != BC_OK) return status;
    if (op->result.requests == op->options.max_requests) return limited(op, BC_WEB_LIMIT_REQUESTS, op->current, op->nodes[op->current].depth, op->result.requests + 1, op->options.max_requests);
    bc_http_options request = {0}; request.struct_size = sizeof(request); request.abi_version = BC_ABI_VERSION;
    request.path = text(op->nodes[op->current].path); request.method = BC_HTTP_GET; request.timeout_ms = budget;
    status = op->session ? bc_web_session_submit(op->session, &request, completed, op, &op->nodes[op->current].request) :
        bc_http_submit(op->endpoint, &request, completed, op, &op->nodes[op->current].request);
    if (status == BC_OK) { ++op->refs; ++op->result.requests; }
    return status;
}
static bc_status start(bc_endpoint *endpoint, const bc_web_entry_options *options,
    bc_web_entry_completion callback, void *user, const char *seed, bc_web_session *session, uint32_t service, bc_web_entry_graph **out) {
    int authenticated = session != NULL;
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        !options->generation || !options->clock_ms || !callback || !options->timeout_ms || options->timeout_ms > INT32_MAX ||
        !options->max_requests || options->max_requests > 32 || !options->max_depth || options->max_depth > (authenticated ? 16u : 8u) ||
        !options->max_bytes || options->max_bytes > UINT64_C(8) * 1024 * 1024 || !bc_console_endpoint_is_https(endpoint)) return BC_INVALID_ARGUMENT;
    bc_web_entry_graph *op = calloc(1, sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    op->html_owner = op->script_owner = UINT32_MAX;
    op->service = service; op->session = session; op->refs = 1; op->authenticated = authenticated; op->endpoint = endpoint; bc_endpoint_retain(endpoint); op->options = *options;
    op->callback = callback; op->user = user; op->started = op->last_time = options->clock_ms(options->clock_user);
    op->result.struct_size = sizeof(op->result); op->result.status = BC_BUSY;
    op->result.endpoint_revision = bc_endpoint_revision(endpoint); op->result.generation = options->generation;
    op->count = 1; op->nodes[0].kind = BC_WEB_LINK_HTML; strcpy(op->nodes[0].path, seed);
    bc_status status = submit(op);
    if (status != BC_OK) { bc_web_entry_release(op); return status; }
    *out = op; return BC_OK;
}
bc_status bc_web_entry_start(bc_endpoint *endpoint, const bc_web_entry_options *options,
    bc_web_entry_completion callback, void *user, bc_web_entry_graph **out) {
    return start(endpoint, options, callback, user, "/", NULL, 0, out);
}
bc_status bc_web_entry_start_owned(bc_web_session *session, const bc_web_entry_options *options,
    bc_web_entry_completion callback, void *user, bc_web_entry_graph **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    bc_endpoint *endpoint = bc_web_session_endpoint(session);
    const bc_web_session_result *result = bc_web_session_result_get(session);
    if (!endpoint || !result || result->status != BC_OK) return BC_INVALID_ARGUMENT;
    return start(endpoint, options, callback, user, result->landing_path, session, 0, out);
}
bc_status bc_web_entry_start_owned_service(bc_web_session *session, const bc_web_entry_options *options,
    uint32_t service, bc_web_entry_completion callback, void *user, bc_web_entry_graph **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    bc_endpoint *endpoint = bc_web_session_endpoint(session);
    const bc_web_session_result *result = bc_web_session_result_get(session);
    if (!endpoint || !result || result->status != BC_OK ||
        (service != BC_SERVICE_KVM && service != BC_SERVICE_LOCAL_MEDIA)) return BC_INVALID_ARGUMENT;
    return start(endpoint, options, callback, user, result->landing_path, session, service, out);
}
const bc_web_entry_result *bc_web_entry_result_get(bc_web_entry_graph *op,
    const bc_endpoint *endpoint, uint64_t generation) {
    if (!op || !op->done || op->endpoint != endpoint || op->result.generation != generation) return NULL;
    if (op->result.status == BC_OK) { uint32_t budget; (void)remaining(op, &budget); }
    return &op->result;
}
bc_request *bc_web_entry_launch_request_get(bc_web_entry_graph *op,
    const bc_endpoint *endpoint, uint64_t generation) {
    const bc_web_entry_result *result = bc_web_entry_result_get(op, endpoint, generation);
    return result && result->status == BC_OK && op->authenticated && op->launch ? op->nodes[op->launch_node].request : NULL;
}
static int diagnostics_valid(bc_web_entry_graph *op, const bc_endpoint *endpoint, uint64_t generation) {
    if (!op || !op->done || op->cancelled || op->diagnostics_invalid || op->endpoint != endpoint || op->options.generation != generation ||
        op->result.status == BC_TIMEOUT || op->result.status == BC_CANCELLED || op->result.status == BC_INVALID_ARGUMENT) return 0;
    uint64_t now = op->options.clock_ms(op->options.clock_user);
    if (now < op->last_time || now - op->started >= op->options.timeout_ms) { op->diagnostics_invalid = 1; return 0; }
    op->last_time = now; return 1;
}
bc_status bc_web_entry_limit_get(bc_web_entry_graph *op, const bc_endpoint *endpoint,
    uint64_t generation, bc_web_entry_limit *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    uint32_t size = out->struct_size;
    if (size != sizeof(*out)) {
        if (size >= sizeof(uint32_t)) memset(out, 0, size < sizeof(*out) ? size : sizeof(*out));
        return BC_INVALID_ARGUMENT;
    }
    uint32_t version = out->abi_version;
    memset(out, 0, sizeof(*out));
    if (version != BC_ABI_VERSION) return BC_INVALID_ARGUMENT;
    if (!op || op->endpoint != endpoint || op->result.generation != generation ||
        op->result.endpoint_revision != bc_endpoint_revision(endpoint)) return BC_INVALID_ARGUMENT;
    if (op->cancelled) return BC_CANCELLED;
    if (!diagnostics_valid(op, endpoint, generation)) return BC_TIMEOUT;
    if (!op->limit_reason) return op->done ? BC_UNSUPPORTED : BC_BUSY;
    out->struct_size = sizeof(*out); out->abi_version = BC_ABI_VERSION;
    out->reason = op->limit_reason; out->source_index = UINT32_MAX;
    uint32_t index = 0;
    for (uint32_t n = 0; n < op->count; ++n) {
        if (!op->nodes[n].request || !bc_request_response(op->nodes[n].request)) continue;
        if (n == op->limit_node) out->source_index = index;
        ++index;
    }
    out->candidates = op->count; out->requests = op->result.requests;
    out->depth = op->limit_depth; out->max_depth = op->options.max_depth;
    out->observed = op->limit_observed; out->maximum = op->limit_maximum;
    out->bytes = op->result.bytes; out->max_bytes = op->options.max_bytes;
    return BC_OK;
}
uint32_t bc_web_entry_resource_count(bc_web_entry_graph *op, const bc_endpoint *endpoint, uint64_t generation) {
    if (!diagnostics_valid(op, endpoint, generation)) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < op->count; ++i) if (op->nodes[i].request && bc_request_response(op->nodes[i].request)) ++count;
    return count;
}
bc_request *bc_web_entry_resource_request_get(bc_web_entry_graph *op, const bc_endpoint *endpoint,
    uint64_t generation, uint32_t index) {
    if (!diagnostics_valid(op, endpoint, generation)) return NULL;
    for (uint32_t i = 0; i < op->count; ++i) {
        bc_request *request = op->nodes[i].request;
        if (!request || !bc_request_response(request)) continue;
        if (!index--) return request;
    }
    return NULL;
}
bc_status bc_web_entry_xmit_form_hint_get(bc_web_entry_graph *op,
    const bc_endpoint *endpoint, uint64_t generation, uint32_t *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = 0;
    if (!op || op->endpoint != endpoint || op->result.generation != generation) return BC_INVALID_ARGUMENT;
    if (!op->done) return BC_BUSY;
    const bc_web_entry_result *result = bc_web_entry_result_get(op, endpoint, generation);
    if (result->status != BC_OK) return result->status;
    if (!op->transport) return BC_UNSUPPORTED;
    *out = op->transport; return BC_OK;
}
bc_status bc_web_entry_response_hint_get(bc_web_entry_graph *op,
    const bc_endpoint *endpoint, uint64_t generation, bc_web_login_response_hint *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!op || op->endpoint != endpoint || op->result.generation != generation) return BC_INVALID_ARGUMENT;
    if (!op->done) return BC_BUSY;
    const bc_web_entry_result *result = bc_web_entry_result_get(op, endpoint, generation);
    if (result->status != BC_OK) return result->status;
    if (!(op->transport & BC_WEB_LOGIN_XMIT_FORM_POST)) return BC_UNSUPPORTED;
    for (uint32_t i = 0; i < op->count; ++i) {
        node *n = op->nodes + i;
        if (!n->valid || n->kind != BC_WEB_LINK_SCRIPT || strcmp(n->path, result->script_path)) continue;
        const bc_response *response = bc_request_response(n->request);
        bc_status status = bc_web_login_response_hint_get(response->body.data, (uint32_t)response->body.length, out);
        char resolved[1025];
        if (status == BC_OK && !bc_web_login_resolve_path(text(result->page_path), text(out->landing_relative), resolved)) {
            memset(out, 0, sizeof(*out)); return BC_UNSUPPORTED;
        }
        return status;
    }
    return BC_UNSUPPORTED;
}
bc_status bc_web_login_contract_validate(bc_web_login_contract *permit) {
    if (!permit) return BC_INVALID_ARGUMENT;
    const bc_web_entry_result *result = bc_web_entry_result_get(permit->graph, permit->endpoint, permit->generation);
    if (!result) return BC_INVALID_ARGUMENT;
    return result->status;
}
bc_status bc_web_login_contract_from_graph(bc_web_entry_graph *op,
    const bc_endpoint *endpoint, uint64_t generation, bc_web_login_contract **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (op && op->login_permit_issued) return BC_BUSY;
    const bc_web_entry_result *result = bc_web_entry_result_get(op, endpoint, generation);
    if (!result) return BC_INVALID_ARGUMENT;
    if (result->status != BC_OK) return result->status;
    if (result->hint.kind == BC_WEB_LOGIN_APPWEB_XML || result->hint.kind == BC_WEB_LOGIN_ATEN_CGI) {
        bc_web_login_contract *permit = calloc(1, sizeof(*permit));
        if (!permit) return BC_NO_MEMORY;
        permit->graph = op; ++op->refs; permit->endpoint = op->endpoint;
        permit->generation = generation; permit->kind = result->hint.kind; permit->flags = result->hint.flags;
        strcpy(permit->cookie_name, result->hint.kind == BC_WEB_LOGIN_ATEN_CGI ? "SID" : "_appwebSessionId_");
        strcpy(permit->landing_path, result->hint.kind == BC_WEB_LOGIN_ATEN_CGI ? "/cgi/url_redirect.cgi?url_name=mainmenu" : "/index.html");
        op->login_permit_issued = 1; *out = permit; return BC_OK;
    }
    bc_web_login_response_hint response;
    bc_status status = bc_web_entry_response_hint_get(op, endpoint, generation, &response);
    if (status != BC_OK) return status;
    char cookie[65] = {0}; unsigned found = 0;
    for (uint32_t i = 0; i < op->count; ++i) {
        node *n = op->nodes + i;
        if (!n->valid || n->kind != BC_WEB_LINK_SCRIPT || !(n->parents & 1u)) continue;
        const bc_response *source = bc_request_response(n->request); char name[65];
        if (bc_web_login_cookie_name_hint(source->body.data, (uint32_t)source->body.length, name) != BC_OK) continue;
        if (++found != 1) return BC_UNSUPPORTED;
        strcpy(cookie, name);
    }
    if (found != 1 || response.flags != (BC_WEB_LOGIN_RESPONSE_COOKIE | BC_WEB_LOGIN_RESPONSE_CSRF_RPC)) return BC_UNSUPPORTED;
    bc_web_login_contract *permit = calloc(1, sizeof(*permit));
    if (!permit) return BC_NO_MEMORY;
    if (!bc_web_login_resolve_path(text(op->result.page_path), text(response.landing_relative), permit->landing_path)) {
        free(permit); return BC_UNSUPPORTED;
    }
    permit->graph = op; ++op->refs; permit->endpoint = op->endpoint;
    permit->generation = generation; permit->flags = op->result.hint.flags; permit->kind = BC_WEB_LOGIN_LEGACY_RPC;
    strcpy(permit->cookie_name, cookie); strcpy(permit->csrf_path, response.csrf_path);
    op->login_permit_issued = 1; *out = permit; return BC_OK;
}
void bc_web_login_contract_release(bc_web_login_contract *permit) {
    if (!permit) return;
    bc_web_entry_release(permit->graph); memset(permit, 0, sizeof(*permit)); free(permit);
}
bc_status bc_web_entry_cancel(bc_web_entry_graph *op) {
    if (!op) return BC_INVALID_ARGUMENT;
    op->cancelled = 1; clear_hint(op); op->result.status = BC_CANCELLED;
    return op->done ? BC_OK : bc_request_cancel(op->nodes[op->current].request);
}
void bc_web_entry_release(bc_web_entry_graph *op) {
    if (!op || --op->refs) return;
    bc_console_discovery_release(op->launch);
    for (uint32_t i = 0; i < op->count; ++i) bc_request_release(op->nodes[i].request);
    bc_endpoint_release(op->endpoint); memset(op, 0, sizeof(*op)); free(op);
}

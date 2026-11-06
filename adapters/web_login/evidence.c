#include "internal.h"
#include <stdlib.h>
#include <string.h>
struct bc_web_login_evidence {
    bc_endpoint *endpoint;
    bc_request *page, *script;
    uint64_t generation;
    bc_web_login_hint hint;
    int cancelled;
};
bc_status bc_web_login_page_script_hint(const uint8_t *page, uint32_t page_length,
    bc_string page_path, const uint8_t *script, uint32_t script_length,
    bc_string script_path, bc_web_login_hint *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    bc_web_login_hint hint;
    bc_status status = bc_web_login_script_hint(script, script_length, &hint);
    if (status == BC_OK) status = bc_web_login_page_matches(page, page_length, page_path, script_path, &hint);
    if (status == BC_OK) *out = hint;
    return status;
}
bc_status bc_web_login_evidence_from_requests(bc_endpoint *endpoint, uint64_t generation,
    bc_request *page, bc_request *script, bc_web_login_evidence **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !generation || !page || !script || page == script ||
        bc_request_endpoint(page) != endpoint || bc_request_endpoint(script) != endpoint) return BC_INVALID_ARGUMENT;
    const bc_response *html = bc_request_response(page), *js = bc_request_response(script);
    if (!html || !js) return BC_BUSY;
    if (html->status != BC_OK) return html->status;
    if (js->status != BC_OK) return js->status;
    if (html->http_status != 200 || js->http_status != 200) return BC_HTTP_ERROR;
    if (html->body.length > 262144 || js->body.length > 262144) return BC_LIMIT_EXCEEDED;
    bc_web_login_hint hint;
    bc_status status = bc_web_login_page_script_hint(html->body.data, (uint32_t)html->body.length,
        bc_request_path(page), js->body.data, (uint32_t)js->body.length, bc_request_path(script), &hint);
    if (status != BC_OK) return status;
    bc_web_login_evidence *op = calloc(1, sizeof(*op));
    if (!op) return BC_NO_MEMORY;
    op->endpoint = endpoint; op->page = page; op->script = script; op->generation = generation; op->hint = hint;
    bc_endpoint_retain(endpoint); bc_request_retain(page); bc_request_retain(script);
    *out = op; return BC_OK;
}
const bc_web_login_hint *bc_web_login_evidence_hint_get(const bc_web_login_evidence *op,
    const bc_endpoint *endpoint, uint64_t generation) {
    return op && !op->cancelled && op->endpoint == endpoint && op->generation == generation ? &op->hint : NULL;
}
void bc_web_login_evidence_cancel(bc_web_login_evidence *op) {
    if (op) { op->cancelled = 1; memset(&op->hint, 0, sizeof(op->hint)); }
}
void bc_web_login_evidence_release(bc_web_login_evidence *op) {
    if (!op) return;
    bc_request_release(op->page); bc_request_release(op->script); bc_endpoint_release(op->endpoint);
    memset(op, 0, sizeof(*op)); free(op);
}

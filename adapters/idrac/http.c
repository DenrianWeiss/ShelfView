#include "bcontrol/idrac_http.h"
#include "yyjson.h"
#include <stdlib.h>
#include <string.h>

static bc_string string(const char *s) { return (bc_string){s, strlen(s)}; }
static void erase_free(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    volatile char *p = s;
    while (n--) *p++ = 0;
    free(s);
}
static char *credential_header(const char *name, bc_string value) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return NULL;
    yyjson_mut_val *root = yyjson_mut_strn(doc, value.data ? value.data : "", (size_t)value.length);
    yyjson_mut_doc_set_root(doc, root);
    size_t size = 0;
    char *json = root ? yyjson_mut_write(doc, YYJSON_WRITE_ESCAPE_UNICODE, &size) : NULL;
    yyjson_mut_doc_free(doc);
    if (!json) return NULL;
    size_t prefix = strlen(name);
    char *header = malloc(prefix + size + 3);
    if (header) {
        memcpy(header, name, prefix); memcpy(header + prefix, ": ", 2);
        memcpy(header + prefix + 2, json, size + 1);
    }
    erase_free(json);
    return header;
}
bc_status bc_idrac_http_login(bc_endpoint *endpoint, bc_string username, bc_string password,
    uint32_t timeout, bc_completion callback, void *user, bc_request **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !timeout || !username.length || username.length > 1024 || password.length > 1024 ||
        !username.data || (password.length && !password.data)) return BC_INVALID_ARGUMENT;
    bc_status status = bc_endpoint_cookie_jar_available(endpoint);
    if (status != BC_OK) return status;
    char *name = credential_header("user", username), *secret = credential_header("password", password);
    if (!name || !secret) { erase_free(name); erase_free(secret); return BC_NO_MEMORY; }
    bc_string headers[] = {string("Accept: application/json"), string(name), string(secret)};
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.method = BC_HTTP_POST; options.path = string("/sysmgmt/2015/bmc/session");
    options.timeout_ms = timeout; options.headers = headers; options.header_count = 3;
    status = bc_http_submit(endpoint, &options, callback, user, out);
    erase_free(name); erase_free(secret);
    return status;
}
bc_status bc_idrac_http_login_status(const bc_request *request) {
    if (!request) return BC_INVALID_ARGUMENT;
    const bc_response *response = bc_request_response(request);
    if (!response) return BC_BUSY;
    if (response->status != BC_OK && response->status != BC_HTTP_ERROR) return response->status;
    if (response->http_status == 401 || response->http_status == 403) return BC_AUTHENTICATION_FAILED;
    if (response->http_status < 200 || response->http_status >= 300) return BC_HTTP_ERROR;
    if (!response->body.data || !response->body.length || response->body.length > 65536) return BC_PROTOCOL_ERROR;
    yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL, *result = NULL;
    size_t index, count; yyjson_val *key, *value; unsigned matches = 0;
    yyjson_obj_foreach(root, index, count, key, value) {
        if (yyjson_equals_str(key, "authResult")) { result = value; ++matches; }
    }
    bc_status status = matches != 1 || !yyjson_is_int(result) ? BC_PROTOCOL_ERROR :
        yyjson_get_sint(result) != 0 ? BC_AUTHENTICATION_FAILED :
        bc_request_csrf_token(request).length ? BC_OK : BC_PROTOCOL_ERROR;
    yyjson_doc_free(doc);
    return status;
}
bc_status bc_idrac_http_submit(bc_endpoint *endpoint, const bc_request *login,
    uint32_t operation, uint32_t timeout, bc_completion callback, void *user, bc_request **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !login || !timeout || bc_request_endpoint(login) != endpoint) return BC_INVALID_ARGUMENT;
    if (operation != BC_IDRAC_HTTP_LAUNCH && operation != BC_IDRAC_HTTP_LOGOUT) return BC_UNSUPPORTED;
    if (operation == BC_IDRAC_HTTP_LAUNCH) {
        bc_status status = bc_idrac_http_login_status(login);
        if (status != BC_OK) return status;
    }
    bc_string token = bc_request_csrf_token(login);
    if (!token.data || !token.length || token.length > 8180) return BC_PROTOCOL_ERROR;
    char *header = malloc((size_t)token.length + 13);
    if (!header) return BC_NO_MEMORY;
    memcpy(header, "XSRF-TOKEN: ", 12); memcpy(header + 12, token.data, (size_t)token.length);
    header[12 + token.length] = 0;
    bc_string headers[] = {string("Accept: application/json"), {header, token.length + 12}};
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.method = operation == BC_IDRAC_HTTP_LAUNCH ? BC_HTTP_GET : BC_HTTP_DELETE;
    options.path = string(operation == BC_IDRAC_HTTP_LAUNCH ? "/sysmgmt/2015/server/vconsole?type=eHTML5" : "/sysmgmt/2015/bmc/session");
    options.timeout_ms = timeout; options.headers = headers; options.header_count = 2;
    bc_status status = bc_http_submit(endpoint, &options, callback, user, out);
    erase_free(header);
    return status;
}

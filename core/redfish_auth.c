#include "bcontrol/redfish_auth.h"
#include "bcontrol/sensor_compat.h"
#include "bcontrol/inspur.h"
#include "redfish_internal.h"
#include "endpoint_internal.h"
#include "log_internal.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define LOGIN_ROOT 0u
#define LOGIN_SERVICE 1u
#define LOGIN_POST 2u
#define LOGIN_BASIC 3u
#define LOGOUT_DELETE 4u
#define LOGIN_INSPUR_PAGE 5u
#define LOGIN_INSPUR_SCRIPT 6u

struct bc_redfish_connection {
    bc_endpoint *endpoint;
    bc_redfish_connection_info info;
    uint32_t refs;
};
struct bc_redfish_auth_operation {
    bc_endpoint *endpoint;
    bc_request *request;
    bc_redfish_connection *connection;
    bc_redfish_login_options options;
    bc_redfish_auth_result result;
    bc_redfish_auth_completion callback;
    void *userdata;
    bc_string target;
    uint32_t phase, refs;
    int done;
};
static bc_string text(const char *value) { return (bc_string){value, value ? strlen(value) : 0}; }
static bc_string copy(bc_string value) {
    char *out = malloc((size_t)value.length + 1);
    if (!out) return (bc_string){NULL, 0};
    if (value.length) memcpy(out, value.data, (size_t)value.length);
    out[value.length] = 0; return (bc_string){out, value.length};
}
static void clear(void *data, uint64_t length) {
    volatile unsigned char *p = data;
    for (uint64_t i = 0; i < length; ++i) p[i] = 0;
    free(data);
}
static int valid(bc_string value, uint64_t maximum, int required) {
    return value.length <= maximum && (!required || value.length) && (!value.length ||
        (value.data && !memchr(value.data, 0, (size_t)value.length)));
}
static bc_status uri(bc_string *out, yyjson_val *value) {
    const char *s = yyjson_get_str(value); size_t n = yyjson_get_len(value);
    if (!s || !n || n > 8192 || strlen(s) != n) return BC_PROTOCOL_ERROR;
    if (!bc_redfish_uri_valid((bc_string){s, n})) return BC_UNSUPPORTED;
    bc_string owned = copy((bc_string){s, n});
    if (!owned.data) return BC_NO_MEMORY;
    free((void *)out->data); *out = owned; return BC_OK;
}
void bc_redfish_connection_retain(bc_redfish_connection *connection) { if (connection) ++connection->refs; }
void bc_redfish_connection_release(bc_redfish_connection *connection) {
    if (!connection || --connection->refs) return;
    bc_endpoint_release(connection->endpoint); free((void *)connection->info.session_uri.data); free(connection);
}
const bc_redfish_connection_info *bc_redfish_connection_info_get(const bc_redfish_connection *connection) { return connection ? &connection->info : NULL; }
bc_endpoint *bc_redfish_connection_endpoint(const bc_redfish_connection *connection) {
    return connection && connection->info.state == BC_REDFISH_CONNECTION_OPEN ? connection->endpoint : NULL;
}
void bc_redfish_auth_retain(bc_redfish_auth_operation *op) { if (op) ++op->refs; }
void bc_redfish_auth_release(bc_redfish_auth_operation *op) {
    if (!op || --op->refs) return;
    bc_endpoint_release(op->endpoint); bc_redfish_connection_release(op->connection);
    free((void *)op->options.username.data); clear((void *)op->options.password.data, op->options.password.length);
    free((void *)op->target.data); free((void *)op->result.session_uri.data);
    clear((void *)op->result.error_body.data, op->result.error_body.length);
    clear((void *)op->result.messages_json.data, op->result.messages_json.length); free(op);
}
const bc_redfish_auth_result *bc_redfish_auth_result_get(const bc_redfish_auth_operation *op) { return op && op->done ? &op->result : NULL; }
bc_status bc_redfish_auth_cancel(bc_redfish_auth_operation *op) {
    if (!op) return BC_INVALID_ARGUMENT;
    return !op->done && op->request ? bc_request_cancel(op->request) : BC_OK;
}
static void finish(bc_redfish_auth_operation *op, bc_status status) {
    if (status == BC_OK)
        BC_LOG_INFO(BC_LOG_CATEGORY_REDFISH, "redfish.auth.finish", "phase=%u status=ok mode=%u",
            op->phase, op->result.auth_mode);
    else
        BC_LOG_WARN(BC_LOG_CATEGORY_REDFISH, "redfish.auth.finish", "phase=%u status=%s mode=%u",
            op->phase, bc_status_string(status), op->result.auth_mode);
    if (op->phase == LOGOUT_DELETE) {
        op->connection->info.state = BC_REDFISH_CONNECTION_CLOSED;
        bc_endpoint_release(op->connection->endpoint); op->connection->endpoint = NULL;
        if (status == BC_OK) op->result.flags |= BC_REDFISH_AUTH_LOGGED_OUT;
    }
    clear((void *)op->options.password.data, op->options.password.length); op->options.password = (bc_string){NULL, 0};
    op->done = 1; op->result.status = status;
    op->callback(op, &op->result, op->userdata); bc_redfish_auth_release(op);
}
static void http_done(bc_request *, const bc_response *, void *);
static bc_status submit(bc_redfish_auth_operation *op, uint32_t method, bc_string path, bc_bytes body) {
    bc_http_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = path; options.method = method; options.body = body; options.timeout_ms = op->options.request_timeout_ms;
    const bc_string accept = {"Accept: application/json", sizeof("Accept: application/json") - 1};
    if (op->phase == LOGIN_POST) { options.headers = &accept; options.header_count = 1; }
    bc_redfish_log_request("auth", op->endpoint, method, path, body);
    return bc_http_submit(op->endpoint, &options, http_done, op, &op->request);
}
static bc_status basic(bc_redfish_auth_operation *op) {
    BC_LOG_INFO(BC_LOG_CATEGORY_REDFISH, "redfish.auth.mode", "mode=basic");
    bc_auth_options auth = {0}; auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION;
    auth.mode = BC_AUTH_BASIC; auth.username = op->options.username; auth.password = op->options.password;
    bc_endpoint *endpoint = NULL;
    bc_status status = bc_endpoint_with_auth(op->endpoint, &auth, &endpoint);
    if (status != BC_OK) return status;
    bc_endpoint_release(op->endpoint); op->endpoint = endpoint; op->phase = LOGIN_BASIC;
    op->result.auth_mode = BC_REDFISH_LOGIN_BASIC;
    return submit(op, BC_HTTP_GET, text("/redfish/v1/"), (bc_bytes){NULL, 0});
}
static bc_status unavailable(bc_redfish_auth_operation *op) {
    if (op->options.mode != BC_REDFISH_LOGIN_AUTO) return BC_UNSUPPORTED;
    op->result.flags |= BC_REDFISH_AUTH_FELL_BACK; return basic(op);
}
static bc_status post_session(bc_redfish_auth_operation *op) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return BC_NO_MEMORY;
    yyjson_mut_val *root = yyjson_mut_obj(doc); yyjson_mut_doc_set_root(doc, root);
    if (!root || !yyjson_mut_obj_add_strn(doc, root, "UserName", op->options.username.data, (size_t)op->options.username.length) ||
        !yyjson_mut_obj_add_strn(doc, root, "Password", op->options.password.data, (size_t)op->options.password.length)) {
        yyjson_mut_doc_free(doc); return BC_NO_MEMORY;
    }
    size_t length = 0; yyjson_write_err error;
    char *body = yyjson_mut_write_opts(doc, 0, NULL, &length, &error); yyjson_mut_doc_free(doc);
    if (!body) return error.code == YYJSON_WRITE_ERROR_INVALID_STRING ? BC_INVALID_ARGUMENT : BC_NO_MEMORY;
    op->phase = LOGIN_POST;
    bc_status status = submit(op, BC_HTTP_POST, op->target, (bc_bytes){(const unsigned char *)body, length});
    clear(body, length); return status;
}
static bc_status connection(bc_redfish_auth_operation *op, bc_endpoint *endpoint, uint32_t mode) {
    bc_redfish_connection *out = calloc(1, sizeof(*out));
    if (!out) return BC_NO_MEMORY;
    out->refs = 1; out->endpoint = endpoint; bc_endpoint_retain(endpoint);
    out->info.struct_size = sizeof(out->info); out->info.mode = mode;
    out->info.endpoint_revision = bc_endpoint_revision(endpoint);
    if (op->result.session_uri.length) {
        out->info.session_uri = copy(op->result.session_uri);
        if (!out->info.session_uri.data) { bc_redfish_connection_release(out); return BC_NO_MEMORY; }
    }
    op->connection = out; op->result.connection = out; return BC_OK;
}
static bc_status session_created(bc_redfish_auth_operation *op, bc_request *request, yyjson_val *root) {
    int standard = bc_redfish_resource_type(root, "#Session.", ".Session");
    if (standard) op->result.flags &= ~BC_REDFISH_AUTH_INSPUR_LEGACY;
    int legacy = (op->result.flags & BC_REDFISH_AUTH_INSPUR_LEGACY) != 0;
    if (!legacy && !standard) return BC_PROTOCOL_ERROR;
    const bc_http_metadata *metadata = bc_request_http_metadata(request);
    bc_string token = bc_request_auth_token(request);
    if (!metadata || !metadata->location.length) return BC_OUTCOME_UNKNOWN;
    bc_string location;
    if (!bc_redfish_same_origin_path(bc_endpoint_origin(op->endpoint), metadata->location, &location)) return BC_UNSUPPORTED;
    op->result.session_uri = copy(location);
    if (!op->result.session_uri.data) return BC_NO_MEMORY;
    if (!token.length) return BC_OUTCOME_UNKNOWN;
    if (legacy) {
        yyjson_val *ok = yyjson_obj_get(root, "ok"), *id = yyjson_obj_get(root, "Id");
        const char prefix[] = "/redfish/v1/SessionService/Sessions/";
        if (!yyjson_is_uint(ok) || yyjson_get_uint(ok) != 0 || !yyjson_is_str(id) ||
            yyjson_get_len(id) != token.length || memcmp(yyjson_get_str(id), token.data, (size_t)token.length) ||
            location.length <= sizeof(prefix) - 1 ||
            memcmp(location.data, prefix, sizeof(prefix) - 1)) return BC_PROTOCOL_ERROR;
    }
    yyjson_val *body_uri = yyjson_obj_get(root, "@odata.id");
    if (body_uri) {
        const char *s = yyjson_get_str(body_uri);
        bc_string body_path;
        if (!s || !bc_redfish_same_origin_path(bc_endpoint_origin(op->endpoint),
                (bc_string){s, yyjson_get_len(body_uri)}, &body_path) ||
            body_path.length != location.length || memcmp(body_path.data, location.data, (size_t)location.length)) return BC_PROTOCOL_ERROR;
    }
    yyjson_val *messages = yyjson_obj_get(root, "@Message.ExtendedInfo");
    if (messages) {
        if (!yyjson_is_arr(messages)) return BC_PROTOCOL_ERROR;
        size_t n = 0; char *json = yyjson_val_write(messages, 0, &n);
        if (!json) return BC_NO_MEMORY;
        op->result.messages_json = (bc_bytes){(const unsigned char *)json, n};
        size_t i, count; yyjson_val *item;
        yyjson_arr_foreach(messages, i, count, item) {
            const char *id = yyjson_get_str(yyjson_obj_get(item, "MessageId"));
            const char suffix[] = ".PasswordChangeRequired";
            if (id && strlen(id) >= sizeof(suffix) - 1 && !strcmp(id + strlen(id) - sizeof(suffix) + 1, suffix))
                op->result.flags |= BC_REDFISH_AUTH_PASSWORD_CHANGE_REQUIRED;
        }
    }
    bc_auth_options auth = {0}; auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION;
    auth.mode = BC_AUTH_TOKEN; auth.token = token;
    bc_endpoint *endpoint = NULL; bc_status status = bc_endpoint_with_auth(op->endpoint, &auth, &endpoint);
    if (status == BC_OK && legacy) bc_endpoint_redfish_profile_set(endpoint, BC_REDFISH_PROFILE_INSPUR);
    if (status == BC_OK) status = connection(op, endpoint, BC_REDFISH_LOGIN_SESSION);
    bc_endpoint_release(endpoint);
    if (status == BC_OK) {
        op->result.flags &= ~BC_REDFISH_AUTH_SESSION_MAY_EXIST;
        op->result.flags |= BC_REDFISH_AUTH_SESSION_CREATED;
        BC_LOG_INFO(BC_LOG_CATEGORY_REDFISH, "redfish.auth.session", "status=created token_len=%" PRIu64,
            token.length);
    }
    return status;
}
static void save_error(bc_redfish_auth_operation *op, const bc_response *response) {
    if (!response->body.length) return;
    bc_string value = copy((bc_string){(const char *)response->body.data, response->body.length});
    if (value.data) op->result.error_body = (bc_bytes){(const unsigned char *)value.data, value.length};
}
static void process(bc_redfish_auth_operation *op, bc_request *request, const bc_response *response) {
    op->result.http_status = response->http_status;
    uint32_t http = response->http_status; bc_status status = response->status;
    if (status == BC_OK && (http < 200 || http >= 300)) status = BC_HTTP_ERROR;
    if (op->phase == LOGIN_ROOT && status == BC_HTTP_ERROR && http == 500) {
        op->phase = LOGIN_INSPUR_PAGE;
        status = submit(op, BC_HTTP_GET, text("/index.html"), (bc_bytes){NULL, 0});
        if (status != BC_OK) finish(op, status);
        return;
    }
    if (op->phase == LOGIN_INSPUR_PAGE || op->phase == LOGIN_INSPUR_SCRIPT) {
        int page = op->phase == LOGIN_INSPUR_PAGE;
        int matches = status == BC_OK && http == 200 && response->body.length <= 262144 &&
            (page ? bc_inspur_login_page_matches(response->body.data, (uint32_t)response->body.length) :
                bc_inspur_login_script_matches(response->body.data, (uint32_t)response->body.length));
        if (!matches) {
            if (!op->target.data || status == BC_CANCELLED) {
                finish(op, status == BC_OK ? BC_UNSUPPORTED : status);
                return;
            }
            status = post_session(op);
            if (status != BC_OK) finish(op, status);
            return;
        }
        if (page) {
            op->phase = LOGIN_INSPUR_SCRIPT;
            status = submit(op, BC_HTTP_GET, text("/js/signin.js"), (bc_bytes){NULL, 0});
        } else {
            op->result.flags |= BC_REDFISH_AUTH_INSPUR_LEGACY;
            if (!op->target.data) op->target = copy(text("/redfish/v1/SessionService/Sessions"));
            status = op->target.data ? post_session(op) : BC_NO_MEMORY;
        }
        if (status != BC_OK) finish(op, status);
        return;
    }
    int not_supported = http == 404 || http == 405 || http == 501;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_REDFISH, "redfish.auth.response", "phase=%u status=%s http=%u bytes=%" PRIu64,
        op->phase, bc_status_string(status), http, response->body.length);
    if (op->phase == LOGIN_POST && !not_supported && (status == BC_OUTCOME_UNKNOWN || (http >= 200 && http < 300) || http >= 500))
        op->result.flags |= BC_REDFISH_AUTH_SESSION_MAY_EXIST;
    if ((op->phase == LOGIN_POST || op->phase == LOGIN_SERVICE) && not_supported && status == BC_HTTP_ERROR) {
        BC_LOG_WARN(BC_LOG_CATEGORY_REDFISH, "redfish.auth.fallback", "from=session to=basic reason=http_%u phase=%u",
            http, op->phase);
        status = unavailable(op);
        if (status == BC_OK) return;
        save_error(op, response); finish(op, status); return;
    }
    if (status != BC_OK) { save_error(op, response); finish(op, status); return; }
    if ((op->phase == LOGIN_POST && http != 201) || (op->phase == LOGOUT_DELETE && http != 200 && http != 204)) {
        save_error(op, response); finish(op, BC_OUTCOME_UNKNOWN); return;
    }
    if (op->phase == LOGOUT_DELETE && !response->body.length) { finish(op, BC_OK); return; }
    yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    if (!yyjson_is_obj(root)) status = op->phase == LOGIN_POST || op->phase == LOGOUT_DELETE ? BC_OUTCOME_UNKNOWN : BC_PROTOCOL_ERROR;
    else if (yyjson_obj_get(root, "error") && !(op->phase == LOGOUT_DELETE && bc_redfish_logout_response_succeeded(http,response->body))) status = BC_REDFISH_ERROR;
    if (status != BC_OK) {
        save_error(op, response); if (doc) yyjson_doc_free(doc); finish(op, status); return;
    }
    int more = 0;
    if (op->phase == LOGIN_POST) status = session_created(op, request, root);
    else if (op->phase == LOGIN_BASIC) {
        status = bc_redfish_resource_type(root, "#ServiceRoot.", ".ServiceRoot") ? connection(op, op->endpoint, BC_REDFISH_LOGIN_BASIC) : BC_PROTOCOL_ERROR;
    } else if (op->phase == LOGIN_ROOT) {
        if (!bc_redfish_resource_type(root, "#ServiceRoot.", ".ServiceRoot")) status = BC_PROTOCOL_ERROR;
        yyjson_val *links = yyjson_obj_get(root, "Links"), *sessions = yyjson_obj_get(links, "Sessions");
        if (status == BC_OK && links && !yyjson_is_obj(links)) status = BC_PROTOCOL_ERROR;
        if (status == BC_OK && sessions) {
            status = uri(&op->target, yyjson_obj_get(sessions, "@odata.id"));
            if (status == BC_OK) {
                if (yyjson_equals_str(yyjson_obj_get(root, "RedfishVersion"), "1.0.2") &&
                    !strcmp(op->target.data, "/redfish/v1/SessionService/Sessions")) {
                    op->phase = LOGIN_INSPUR_PAGE;
                    status = submit(op, BC_HTTP_GET, text("/index.html"), (bc_bytes){NULL, 0});
                } else status = post_session(op);
                more = status == BC_OK;
            }
        } else if (status == BC_OK) {
            yyjson_val *service = yyjson_obj_get(root, "SessionService");
            if (!service) { status = unavailable(op); more = status == BC_OK; }
            else {
                status = uri(&op->target, yyjson_obj_get(service, "@odata.id"));
                if (status == BC_OK) { op->phase = LOGIN_SERVICE; status = submit(op, BC_HTTP_GET, op->target, (bc_bytes){NULL, 0}); more = status == BC_OK; }
            }
        }
    } else if (op->phase == LOGIN_SERVICE) {
        if (!bc_redfish_resource_type(root, "#SessionService.", ".SessionService")) status = BC_PROTOCOL_ERROR;
        yyjson_val *enabled = yyjson_obj_get(root, "ServiceEnabled"), *sessions = yyjson_obj_get(root, "Sessions");
        if (status == BC_OK && enabled && !yyjson_is_null(enabled) && !yyjson_is_bool(enabled)) status = BC_PROTOCOL_ERROR;
        if (status == BC_OK && (!sessions || yyjson_is_false(enabled))) { status = unavailable(op); more = status == BC_OK; }
        else if (status == BC_OK) {
            status = uri(&op->target, yyjson_obj_get(sessions, "@odata.id"));
            if (status == BC_OK) { status = post_session(op); more = status == BC_OK; }
        }
    }
    yyjson_doc_free(doc);
    if (!more) { if (status != BC_OK) save_error(op, response); finish(op, status); }
}
static void http_done(bc_request *request, const bc_response *response, void *userdata) {
    bc_redfish_auth_operation *op = userdata; op->request = NULL;
    process(op, request, response); bc_request_release(request);
}
static bc_redfish_auth_operation *allocate(bc_redfish_auth_completion callback, void *userdata) {
    bc_redfish_auth_operation *op = calloc(1, sizeof(*op));
    if (!op) return NULL;
    op->refs = 1; op->callback = callback; op->userdata = userdata; op->result.struct_size = sizeof(op->result); return op;
}
bc_status bc_redfish_login(bc_endpoint *endpoint, const bc_redfish_login_options *options, bc_redfish_auth_completion callback, void *userdata, bc_redfish_auth_operation **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!endpoint || !options || !callback || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        options->mode > BC_REDFISH_LOGIN_SESSION || options->request_timeout_ms > INT32_MAX ||
        !valid(options->username, 4096, 1) || !valid(options->password, 65536, 0)) return BC_INVALID_ARGUMENT;
    bc_redfish_auth_operation *op = allocate(callback, userdata);
    if (!op) return BC_NO_MEMORY;
    op->options = *options; op->options.username = copy(options->username); op->options.password = copy(options->password);
    BC_LOG_INFO(BC_LOG_CATEGORY_REDFISH, "redfish.auth.start", "mode=%u user_len=%" PRIu64 " password=%u",
        options->mode, options->username.length, options->password.length != 0);
    if (!op->options.username.data || !op->options.password.data) { bc_redfish_auth_release(op); return BC_NO_MEMORY; }
    bc_auth_options anonymous = {0}; anonymous.struct_size = sizeof(anonymous); anonymous.abi_version = BC_ABI_VERSION;
    bc_status status = bc_endpoint_with_auth(endpoint, &anonymous, &op->endpoint);
    op->result.auth_mode = BC_REDFISH_LOGIN_SESSION;
    if (status == BC_OK) status = options->mode == BC_REDFISH_LOGIN_BASIC ? basic(op) : submit(op, BC_HTTP_GET, text("/redfish/v1/"), (bc_bytes){NULL, 0});
    if (status != BC_OK) { bc_redfish_auth_release(op); return status; }
    ++op->refs; *out = op; return BC_OK;
}
bc_status bc_redfish_logout(bc_redfish_connection *source, uint32_t timeout_ms, bc_redfish_auth_completion callback, void *userdata, bc_redfish_auth_operation **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!source || !callback || timeout_ms > INT32_MAX) return BC_INVALID_ARGUMENT;
    if (source->info.state == BC_REDFISH_CONNECTION_CLOSING) return BC_BUSY;
    if (source->info.state == BC_REDFISH_CONNECTION_CLOSED) return BC_SHUTTING_DOWN;
    if (source->info.mode != BC_REDFISH_LOGIN_SESSION) return BC_UNSUPPORTED;
    bc_redfish_auth_operation *op = allocate(callback, userdata);
    if (!op) return BC_NO_MEMORY;
    op->phase = LOGOUT_DELETE; op->options.request_timeout_ms = timeout_ms; op->result.auth_mode = BC_REDFISH_LOGIN_SESSION;
    op->connection = source; bc_redfish_connection_retain(source); op->result.connection = source;
    op->endpoint = source->endpoint; bc_endpoint_retain(op->endpoint);
    op->result.session_uri = copy(source->info.session_uri);
    if (!op->result.session_uri.data) { bc_redfish_auth_release(op); return BC_NO_MEMORY; }
    BC_LOG_INFO(BC_LOG_CATEGORY_REDFISH, "redfish.auth.logout", "status=start");
    bc_status status = submit(op, BC_HTTP_DELETE, source->info.session_uri, (bc_bytes){NULL, 0});
    if (status != BC_OK) { bc_redfish_auth_release(op); return status; }
    source->info.state = BC_REDFISH_CONNECTION_CLOSING;
    ++op->refs; *out = op; return BC_OK;
}

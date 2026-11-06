#include "megarac.h"
#include "probe_internal.h"
#include "h5_internal.h"
#include "../inspur/internal.h"
#include "bcontrol/bcontrol.h"
#include "../../core/log_internal.h"
#include "yyjson.h"
#include <inttypes.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define PHASE_IDENTIFY 0u
#define PHASE_SESSION 1u
#define PHASE_H5_CONFIG 2u
#define PHASE_LEGACY_SESSION 3u
#define PHASE_LEGACY_JNLP 4u
#define PHASE_LEGACY_CSRF 5u
#define PHASE_LOGOUT 6u
#define PHASE_INSPUR_SCRIPT 7u
#define PHASE_INSPUR_VIEWER 8u
#define PHASE_INSPUR_RANDOM 9u
#define PHASE_SPLIT_TOKEN 10u
#define PHASE_SPLIT_ADVISER 11u
#define PHASE_SPLIT_MEDIA 12u
#define PHASE_SPLIT_VIEWER 13u
#define PHASE_KEYBOARD_VIEWER 14u
#define PHASE_INSPUR_RPC_SCRIPT 15u
#define DISCOVERY_INSPUR_RPC 3
#define EXTENDED_LOGIN (BC_MEGARAC_LOGIN_CLIENT_ID | BC_MEGARAC_LOGIN_TRANSPORT_TYPE | BC_MEGARAC_LOGIN_CSRF_COOKIE)

struct bc_megarac_probe {
    uint32_t refs;
    bc_endpoint *endpoint;
    bc_request *launch_request, *h5_request;
    bc_megarac_probe_options options;
    char *host_copy, *username_copy, *password_copy;
    uint32_t phase;
    bc_http_options request;
    bc_megarac_probe_result result;
    bc_console_failure failure;
    bc_service_profile profile;
    char *error_body;
    char *cookie_header;
    char *csrf;
    bc_megarac_probe_completion callback;
    void *userdata;
    uint32_t submitted;
    int done, nec, owned, closing, explicit_login;
    int structured;
    int inspur, split_h5, web_media_proxy;
    uint32_t keyboard_mode;
    char *split_token;
    bc_megarac_media_parameters split_media;
    uint32_t forced_variant, selected_evidence;
    uint32_t login_flags;
    char legacy_cookie[257], client_id[9];
    bc_status pending_failure;
    uint32_t pending_http;
};

static bc_string text(const char *value) { return (bc_string){value, value ? strlen(value) : 0}; }
static void erase(void *data, size_t length) {
    volatile unsigned char *p = data;
    for (size_t i = 0; i < length; ++i) p[i] = 0;
}
static void free_secret(char *value) { if (value) { erase(value, strlen(value)); free(value); } }
static char *copy_text(bc_string value) {
    char *copy = malloc((size_t)value.length + 1);
    if (!copy) return NULL;
    if (value.length) memcpy(copy, value.data, (size_t)value.length);
    copy[value.length] = 0;
    return copy;
}
static int unreserved(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '-' || c == '_' || c == '.' || c == '~';
}
static char *form_encode(const char *value) {
    size_t length = strlen(value), needed = 0;
    for (size_t i = 0; i < length; ++i) needed += unreserved((unsigned char)value[i]) ? 1 : 3;
    char *out = malloc(needed + 1);
    if (!out) return NULL;
    const char *hex = "0123456789ABCDEF";
    size_t at = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (unreserved(c)) out[at++] = (char)c;
        else { out[at++] = '%'; out[at++] = hex[c >> 4]; out[at++] = hex[c & 15]; }
    }
    out[at] = 0;
    return out;
}
static void submit_callback(bc_request *request, const bc_response *response, void *userdata);
static bc_status submit(bc_megarac_probe *probe, uint32_t phase, uint32_t method, const char *path,
    bc_bytes body, const bc_string *headers, uint32_t header_count, bc_string content_type) {
    probe->phase = phase;
    probe->request.struct_size = sizeof(probe->request);
    probe->request.abi_version = BC_ABI_VERSION;
    probe->request.path = text(path);
    probe->request.method = method;
    probe->request.body = body;
    probe->request.timeout_ms = probe->options.timeout_ms;
    bc_string combined[4]; uint32_t count = 0;
    combined[count++] = text("User-Agent: bControl/0.1");
    if (header_count > 2) return BC_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < header_count; ++i) combined[count++] = headers[i];
    probe->request.headers = combined;
    probe->request.header_count = count;
    probe->request.content_type = content_type;
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_DEBUG
    char log_path[BC_LOG_PATH_MAX];
    uint32_t query = bc_log_path(log_path, sizeof(log_path), path, strlen(path));
    BC_LOG_DEBUG(BC_LOG_CATEGORY_VENDOR, "megarac.probe.request",
        "phase=%u method=%u path=%s query=%u body_bytes=%" PRIu64 " headers=%u",
        phase, method, log_path, query, body.length, count);
#endif
    bc_request *request = NULL;
    bc_status status = bc_http_submit(probe->endpoint, &probe->request, submit_callback, probe, &request);
    if (status == BC_OK) { ++probe->refs; ++probe->submitted; }
    if (request) bc_request_release(request);
    return status;
}
static bc_status legacy_session(bc_megarac_probe *probe) {
    if ((probe->login_flags & BC_MEGARAC_LOGIN_CLIENT_ID) && !probe->client_id[0]) return BC_INVALID_ARGUMENT;
    char *username = form_encode(probe->username_copy), *password = form_encode(probe->password_copy);
    if (!username || !password) { free(username); free_secret(password); return BC_NO_MEMORY; }
    size_t length = strlen(username) + strlen(password) + 100;
    char *body = malloc(length);
    if (!body) { free(username); free_secret(password); return BC_NO_MEMORY; }
    snprintf(body, length, "WEBVAR_USERNAME=%s&WEBVAR_PASSWORD=%s", username, password);
    if (probe->login_flags & BC_MEGARAC_LOGIN_CLIENT_ID) {
        size_t used = strlen(body); snprintf(body + used, length - used, "&WEBVAR_IPADDR=%s", probe->client_id);
    }
    if (probe->login_flags & BC_MEGARAC_LOGIN_TRANSPORT_TYPE) {
        size_t used = strlen(body); snprintf(body + used, length - used, "&WEBVAR_TYPE=Https");
    }
    free(username); free_secret(password);
    bc_string headers[2]; uint32_t count = 0;
    char origin_header[1050], referer_header[1050];
    bc_status status = BC_OK;
    if (probe->structured == DISCOVERY_INSPUR_RPC) {
        bc_string origin = bc_endpoint_origin(probe->endpoint);
        if (origin.length < 9 || origin.length > 1024 || memcmp(origin.data, "https://", 8)) status = BC_INVALID_ARGUMENT;
        else {
            snprintf(origin_header, sizeof(origin_header), "Origin: %.*s", (int)origin.length, origin.data);
            snprintf(referer_header, sizeof(referer_header), "Referer: %.*s/index.html", (int)origin.length, origin.data);
            headers[count++] = text(origin_header); headers[count++] = text(referer_header);
        }
    }
    if (status == BC_OK) status = submit(probe, PHASE_LEGACY_SESSION, BC_HTTP_POST, "/rpc/WEBSES/create.asp",
        (bc_bytes){(const unsigned char *)body, strlen(body)}, headers, count, text("application/x-www-form-urlencoded"));
    erase(body, length); free(body);
    return status;
}
static bc_status legacy_jnlp(bc_megarac_probe *probe) {
    char *host = form_encode(probe->host_copy);
    if (!host) return BC_NO_MEMORY;
    size_t length = strlen(host) * 2 + 80;
    char *path = malloc(length);
    if (!path) { free(host); return BC_NO_MEMORY; }
    if (probe->structured == DISCOVERY_INSPUR_RPC) snprintf(path, length, "/Java/jviewer.jnlp?EXTRNIP=%s&JNLPSTR=JViewer", host);
    else if (probe->explicit_login) snprintf(path, length, "/Java/jviewer.jnlp?EXTRNIP=%s&JNLPSTR=JViewer&ext_ip=%s", host, host);
    else if (probe->nec) snprintf(path, length, "/Java/jviewer.jnlp?ext_ip=%s", host);
    else if (probe->forced_variant) snprintf(path, length, "/Java/jviewer.jnlp?EXTRNIP=%s&JNLPSTR=JViewer", host);
    else snprintf(path, length, "/Java/jviewer.jnlp?EXTRNIP=%s&JNLPSTR=JViewer&ext_ip=%s", host, host);
    free(host);
    bc_status status = submit(probe, PHASE_LEGACY_JNLP, BC_HTTP_GET, path, (bc_bytes){NULL, 0}, NULL, 0,
        (bc_string){NULL, 0});
    free(path);
    return status;
}
static bc_status h5_config(bc_megarac_probe *probe) {
    char *csrf = probe->csrf;
    if (!csrf) return BC_PROTOCOL_ERROR;
    size_t length = strlen(csrf) + 16;
    char *header = malloc(length);
    if (!header) return BC_NO_MEMORY;
    snprintf(header, length, "X-CSRFTOKEN: %s", csrf);
    bc_string headers[1] = {{header, strlen(header)}};
    bc_status status = submit(probe, probe->split_h5 ? PHASE_SPLIT_TOKEN : PHASE_H5_CONFIG, BC_HTTP_GET,
        probe->split_h5 ? "/api/kvm/token" : "/api/settings/media/h5viewercfg",
        (bc_bytes){NULL, 0}, headers, 1, (bc_string){NULL, 0});
    free(header);
    return status;
}
static const char *json_csrf(yyjson_val *root) {
    static const char *const keys[] = {"CSRFToken", "CSRFTOKEN", "csrf_token", "CsrfToken"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        yyjson_val *value = yyjson_obj_get(root, keys[i]);
        if (yyjson_is_str(value)) return yyjson_get_str(value);
    }
    return NULL;
}
static void probe_destroy(bc_megarac_probe *probe) {
    bc_request_release(probe->launch_request); bc_request_release(probe->h5_request);
    bc_endpoint_release(probe->endpoint);
    free(probe->host_copy); free(probe->username_copy); free_secret(probe->password_copy);
    free_secret(probe->csrf); free_secret(probe->error_body); free_secret(probe->cookie_header);
    free_secret(probe->split_token);
    erase(probe, sizeof(*probe)); free(probe);
}
static yyjson_doc *legacy_object(bc_bytes body) {
    if (!body.data || !body.length || body.length > 65536) return NULL;
    const uint8_t *start = memchr(body.data, '{', (size_t)body.length);
    if (!start) return NULL;
    return yyjson_read((const char *)start, (size_t)(body.length - (uint64_t)(start - body.data)),
        YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_UNQUOTED_KEY | YYJSON_READ_ALLOW_TRAILING_COMMAS | YYJSON_READ_STOP_WHEN_DONE);
}
static yyjson_doc *rpc_object(const bc_response *response, const char *assignment) {
    bc_bytes body = bc_inspur_rpc_payload(response->body, assignment);
    return body.length ? yyjson_read((const char *)body.data, (size_t)body.length,
        YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_UNQUOTED_KEY | YYJSON_READ_ALLOW_TRAILING_COMMAS) : NULL;
}
static yyjson_val *legacy_record(yyjson_val *root, const char *key) {
    yyjson_val *list = yyjson_obj_get(root, key);
    return list ? (yyjson_is_arr(list) && yyjson_arr_size(list) >= 1 && yyjson_arr_size(list) <= 16 ? yyjson_arr_get_first(list) : NULL) : root;
}
static int safe_token(yyjson_val *value, char *out, size_t capacity) {
    const char *s = yyjson_get_str(value); size_t length = yyjson_get_len(value);
    if (!s || !length || length >= capacity) return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    memcpy(out, s, length); out[length] = 0; return 1;
}
static bc_status legacy_csrf(bc_megarac_probe *probe) {
    char body[288]; snprintf(body, sizeof(body), "SESSION_COOKIE=%s", probe->legacy_cookie);
    return submit(probe, PHASE_LEGACY_CSRF, BC_HTTP_POST, "/rpc/getcsrftoken.asp",
        (bc_bytes){(const unsigned char *)body, strlen(body)}, NULL, 0, text("application/x-www-form-urlencoded"));
}
static bc_status logout_request(bc_megarac_probe *probe) {
    if (probe->result.kind == BC_MEGARAC_HTTP_H5VIEWER) {
        char header[512]; snprintf(header, sizeof(header), "X-CSRFTOKEN: %s", probe->csrf ? probe->csrf : "");
        bc_string headers[] = {text(header)};
        return submit(probe, PHASE_LOGOUT, BC_HTTP_DELETE, "/api/session", (bc_bytes){NULL, 0}, headers, 1, (bc_string){NULL, 0});
    }
    if (probe->structured == DISCOVERY_INSPUR_RPC && probe->csrf) {
        char header[288]; snprintf(header, sizeof(header), "X-CSRFTOKEN: %s", probe->csrf);
        bc_string headers[] = {text(header)};
        return submit(probe, PHASE_LOGOUT, BC_HTTP_GET, "/rpc/WEBSES/logout.asp", (bc_bytes){NULL, 0}, headers, 1, (bc_string){NULL, 0});
    }
    return submit(probe, PHASE_LOGOUT, BC_HTTP_GET, "/rpc/WEBSES/logout.asp", (bc_bytes){NULL, 0}, NULL, 0, (bc_string){NULL, 0});
}
static int has_session_cookie(bc_string header) {
    const char key[] = "SessionCookie=";
    for (uint64_t i = 0; i + sizeof(key) - 1 < header.length; ++i)
        if ((!i || header.data[i - 1] == ' ') && !memcmp(header.data + i, key, sizeof(key) - 1)) return 1;
    return 0;
}
static void capture_cookie(bc_megarac_probe *probe, const bc_request *request) {
    char manual[288];
    if (probe->legacy_cookie[0]) snprintf(manual, sizeof(manual), "SessionCookie=%s", probe->legacy_cookie);
    bc_string cookie = probe->legacy_cookie[0] ? text(manual) : bc_request_cookie_header(request);
    if (!cookie.length) return;
    char *copy = malloc((size_t)cookie.length + 1);
    if (!copy) return;
    memcpy(copy, cookie.data, (size_t)cookie.length); copy[cookie.length] = 0;
    free(probe->cookie_header);
    probe->cookie_header = copy;
    probe->result.cookie = text(copy);
}
static void complete(bc_megarac_probe *probe, bc_status status, uint32_t http_status) {
    if (probe->done) return;
    probe->result.status = status;
    probe->result.http_status = http_status;
    probe->done = 1;
    ++probe->refs;
    if (probe->callback) probe->callback(probe, &probe->result, probe->userdata);
    if (--probe->refs == 0) probe_destroy(probe);
}
static void fail_status(bc_megarac_probe *probe, bc_status status, uint32_t http_status) {
    if (!probe->closing) {
        uint32_t phase = probe->phase == PHASE_IDENTIFY || probe->phase == PHASE_INSPUR_RPC_SCRIPT ? BC_CONSOLE_PHASE_DISCOVERY :
            probe->phase == PHASE_SESSION || probe->phase == PHASE_LEGACY_SESSION ?
            BC_CONSOLE_PHASE_LOGIN : BC_CONSOLE_PHASE_LAUNCH;
        uint32_t cause = status == BC_PROTOCOL_ERROR ? BC_CONSOLE_CAUSE_PROTOCOL :
            status == BC_AUTHENTICATION_FAILED ? BC_CONSOLE_CAUSE_AUTH_REJECTED :
            status == BC_BUSY ? BC_CONSOLE_CAUSE_BUSY : BC_CONSOLE_CAUSE_UNKNOWN;
        probe->failure = (bc_console_failure){sizeof(probe->failure), status, phase, cause,
            probe->profile.variant, http_status, 0, BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC};
    }
    if (probe->owned && !probe->closing) {
        probe->pending_failure = status; probe->pending_http = http_status; probe->closing = 1;
        bc_status cleanup = logout_request(probe);
        if (cleanup == BC_OK) return;
        probe->result.cleanup_status = cleanup; probe->closing = 0;
    }
    complete(probe, status, http_status);
}
static void save_error(bc_megarac_probe *probe, const bc_response *response) {
    free(probe->error_body);
    probe->error_body = NULL;
    probe->result.error_body = (bc_string){NULL, 0};
    if (!response->body.length) return;
    probe->error_body = malloc((size_t)response->body.length + 1);
    if (!probe->error_body) return;
    memcpy(probe->error_body, response->body.data, (size_t)response->body.length);
    probe->error_body[response->body.length] = 0;
    probe->result.error_body = text(probe->error_body);
}
static bc_status h5_session(bc_megarac_probe *probe) {
    char *username = form_encode(probe->username_copy), *password = form_encode(probe->password_copy);
    if (!username || !password) { free(username); free_secret(password); return BC_NO_MEMORY; }
    size_t length = strlen(username) + strlen(password) + 24;
    char *body = malloc(length);
    if (!body) { free(username); free_secret(password); return BC_NO_MEMORY; }
    snprintf(body, length, "username=%s&password=%s", username, password);
    free(username); free_secret(password);
    bc_status status = submit(probe, PHASE_SESSION, BC_HTTP_POST, "/api/session",
        (bc_bytes){(const unsigned char *)body, strlen(body)}, NULL, 0, text("application/x-www-form-urlencoded"));
    erase(body, length); free(body); return status;
}
static void h5_session_response(bc_megarac_probe *probe, const bc_response *response) {
    if (response->status == BC_OK && (response->http_status == 200 || response->http_status == 201)) {
        yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
        yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
        const char *csrf = yyjson_is_obj(root) ? json_csrf(root) : NULL;
        if (csrf && *csrf) {
            probe->owned = 1; probe->result.kind = BC_MEGARAC_HTTP_H5VIEWER;
            probe->csrf = copy_text(text(csrf));
            yyjson_doc_free(doc);
            if (!probe->csrf) { fail_status(probe, BC_NO_MEMORY, response->http_status); return; }
            bc_status status = h5_config(probe);
            if (status != BC_OK) fail_status(probe, status, response->http_status);
            return;
        }
        yyjson_doc_free(doc);
        save_error(probe, response);
        fail_status(probe, BC_PROTOCOL_ERROR, response->http_status);
        return;
    }
    save_error(probe, response);
    if ((response->status == BC_OK || response->status == BC_HTTP_ERROR) && (response->http_status == 404 || response->http_status == 405)) {
        if (probe->forced_variant || probe->explicit_login) { fail_status(probe, BC_UNSUPPORTED, response->http_status); return; }
        bc_status status = legacy_session(probe);
        if (status != BC_OK) fail_status(probe, status, response->http_status);
    } else fail_status(probe, response->http_status == 401 || response->http_status == 403 ? BC_AUTHENTICATION_FAILED :
        response->status == BC_OK ? BC_PROTOCOL_ERROR : response->status, response->http_status);
}
static void submit_callback(bc_request *request, const bc_response *response, void *userdata) {
    bc_megarac_probe *probe = userdata;
    uint32_t phase = probe->phase;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_VENDOR, "megarac.probe.response", "phase=%u status=%s http=%u bytes=%" PRIu64,
        phase, bc_status_string(response->status), response->http_status, response->body.length);
    if (phase == PHASE_KEYBOARD_VIEWER) {
        if (response->status == BC_CANCELLED || response->status == BC_SHUTTING_DOWN) {
            fail_status(probe, response->status, response->http_status); goto done;
        }
        if (response->status == BC_OK && response->http_status == 200 && response->body.length <= 2097152)
            probe->keyboard_mode = bc_megarac_h5_keyboard_mode(response->body.data, (uint32_t)response->body.length);
        complete(probe, BC_OK, 200);
        goto done;
    }
    if (phase == PHASE_IDENTIFY) {
        if (response->status != BC_OK && response->status != BC_HTTP_ERROR) { fail_status(probe, response->status, response->http_status); goto done; }
        if (response->http_status == 401 || response->http_status == 403) { fail_status(probe, BC_AUTHENTICATION_FAILED, response->http_status); goto done; }
        if (response->http_status != 200 && response->http_status != 404 && response->http_status != 405) { fail_status(probe, BC_HTTP_ERROR, response->http_status); goto done; }
        if (probe->structured == DISCOVERY_INSPUR_RPC) {
            bc_status status = response->http_status == 200 && response->body.length <= 262144 &&
                bc_inspur_rpc_page_matches(response->body.data, (uint32_t)response->body.length) ?
                submit(probe, PHASE_INSPUR_RPC_SCRIPT, BC_HTTP_GET, "/js/signin.js", (bc_bytes){0}, NULL, 0, (bc_string){0}) : BC_UNSUPPORTED;
            if (status != BC_OK) fail_status(probe, status, response->http_status);
            goto done;
        }
        char *page = copy_text((bc_string){(const char *)response->body.data, response->body.length});
        if (!page) { fail_status(probe, BC_NO_MEMORY, response->http_status); goto done; }
        probe->nec = strstr(page, "EXPRESSSCOPE Engine 3") != NULL;
        probe->inspur = bc_inspur_login_page_matches(response->body.data, (uint32_t)response->body.length); free(page);
        if (probe->structured == 2 && !probe->inspur) { fail_status(probe, BC_UNSUPPORTED, response->http_status); goto done; }
        probe->login_flags = probe->nec ? EXTENDED_LOGIN : 0u;
        BC_LOG_INFO(BC_LOG_CATEGORY_VENDOR, "megarac.identify", "nec=%u generation=%s", probe->nec,
            probe->nec ? "legacy" : "h5");
        bc_status status = probe->inspur ? submit(probe, PHASE_INSPUR_SCRIPT, BC_HTTP_GET, "/js/signin.js",
            (bc_bytes){NULL, 0}, NULL, 0, (bc_string){NULL, 0}) : probe->nec ? legacy_session(probe) : h5_session(probe);
        if (status != BC_OK) fail_status(probe, status, response->http_status);
        goto done;
    }
    if (phase == PHASE_INSPUR_RPC_SCRIPT) {
        bc_status status = response->status;
        if (status == BC_OK) status = response->http_status == 200 && response->body.length <= 262144 &&
            bc_inspur_rpc_script_matches(response->body.data, (uint32_t)response->body.length) ? BC_OK : BC_UNSUPPORTED;
        if (status == BC_OK) {
            bc_endpoint *owned = NULL;
            bc_auth_options auth = {0};
            auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION; auth.mode = BC_AUTH_NONE;
            status = bc_endpoint_with_auth(probe->endpoint, &auth, &owned);
            if (status == BC_OK) {
                bc_endpoint_release(probe->endpoint);
                probe->endpoint = owned;
                status = bc_endpoint_cookie_jar_available(owned);
            }
        }
        if (status == BC_OK) status = legacy_session(probe);
        if (status != BC_OK) fail_status(probe, status, response->http_status);
        goto done;
    }
    if (phase >= PHASE_INSPUR_SCRIPT && phase <= PHASE_SPLIT_VIEWER) {
        bc_status status = response->status;
        if (status == BC_OK && response->http_status != 200) status = BC_HTTP_ERROR;
        if (status != BC_OK) { fail_status(probe, status, response->http_status); goto done; }
        if (response->body.length > 2097152) { fail_status(probe, BC_LIMIT_EXCEEDED, response->http_status); goto done; }
        uint32_t n = (uint32_t)response->body.length;
        const uint8_t *data = response->body.data;
        if (phase == PHASE_SPLIT_VIEWER) {
            if (!bc_megarac_split_h5_viewer_matches(data, n)) status = BC_UNSUPPORTED;
            else {
                probe->split_h5 = 1; probe->keyboard_mode = bc_megarac_h5_keyboard_mode(data, n);
                status = h5_config(probe);
            }
        } else if (phase == PHASE_INSPUR_SCRIPT) {
            status = bc_inspur_login_script_matches(data, n) ? submit(probe, PHASE_INSPUR_VIEWER, BC_HTTP_GET,
                "/viewer.min.js", (bc_bytes){NULL, 0}, NULL, 0, (bc_string){NULL, 0}) : BC_UNSUPPORTED;
        } else if (phase == PHASE_INSPUR_VIEWER) {
            probe->split_h5 = bc_megarac_split_h5_viewer_matches(data, n);
            probe->web_media_proxy = probe->split_h5 && bc_inspur_web_media_proxy_matches(data, n);
            probe->keyboard_mode = bc_megarac_h5_keyboard_mode(data, n);
            status = probe->split_h5 ? submit(probe, PHASE_INSPUR_RANDOM, BC_HTTP_GET,
                "/api/randomtag", (bc_bytes){NULL, 0}, NULL, 0, (bc_string){NULL, 0}) : BC_UNSUPPORTED;
        } else if (phase == PHASE_INSPUR_RANDOM) {
            char *form = NULL;
            status = bc_inspur_login_form(text(probe->username_copy), text(probe->password_copy), data, n, &form);
            if (status == BC_OK) status = submit(probe, PHASE_SESSION, BC_HTTP_POST, "/api/session",
                (bc_bytes){(const uint8_t *)form, strlen(form)}, NULL, 0, text("application/x-www-form-urlencoded"));
            free_secret(form);
        } else {
            char header[512]; snprintf(header, sizeof(header), "X-CSRFTOKEN: %s", probe->csrf);
            bc_string headers[] = {text(header)};
            if (phase == PHASE_SPLIT_TOKEN) {
                probe->split_token = copy_text((bc_string){(const char *)data, n});
                status = probe->split_token ? submit(probe, PHASE_SPLIT_ADVISER, BC_HTTP_GET,
                    "/api/settings/media/adviser", (bc_bytes){NULL, 0}, headers, 1, (bc_string){NULL, 0}) : BC_NO_MEMORY;
            } else if (phase == PHASE_SPLIT_ADVISER) {
                status = bc_megarac_split_h5_config((const uint8_t *)probe->split_token,
                    (uint32_t)strlen(probe->split_token), data, n, probe->inspur, &probe->result.info, &probe->profile);
                free_secret(probe->split_token); probe->split_token = NULL;
                if (status == BC_OK && probe->forced_variant && probe->forced_variant != probe->profile.variant) status = BC_UNSUPPORTED;
                if (status == BC_OK) probe->profile.evidence |= probe->selected_evidence;
                if (status == BC_OK) status = submit(probe, PHASE_SPLIT_MEDIA, BC_HTTP_GET,
                    "/api/settings/media/instance", (bc_bytes){NULL, 0}, headers, 1, (bc_string){NULL, 0});
            } else {
                (void)bc_megarac_split_h5_media(data, n, probe->web_media_proxy, &probe->split_media);
                capture_cookie(probe, request);
                complete(probe, BC_OK, response->http_status);
            }
        }
        if (status != BC_OK) fail_status(probe, status, response->http_status);
        goto done;
    }
    if (phase == PHASE_LOGOUT) {
        bc_status status = response->status;
        int rpc = probe->structured == DISCOVERY_INSPUR_RPC;
        if (rpc && response->http_status == 200 && status == BC_IO_ERROR &&
            (response->flags & BC_RESPONSE_EARLY_EOF)) status = BC_OK;
        if (status == BC_OK && (response->http_status < 200 || response->http_status >= 300)) status = BC_HTTP_ERROR;
        if (status == BC_OK && probe->result.kind == BC_MEGARAC_HTTP_JVIEWER) {
            yyjson_doc *doc = rpc ? rpc_object(response, "WEBVAR_JSONVAR_WEB_SESSION_LOGOUT") : legacy_object(response->body);
            yyjson_val *hapi = doc ? yyjson_obj_get(yyjson_doc_get_root(doc), "HAPI_STATUS") : NULL;
            if ((rpc || hapi) && (!yyjson_is_int(hapi) || yyjson_get_sint(hapi) != 0)) status = BC_PROTOCOL_ERROR;
            if (doc) yyjson_doc_free(doc);
        }
        probe->result.cleanup_status = status; probe->closing = 0;
        if (status == BC_OK) {
            probe->owned = 0; memset(probe->legacy_cookie, 0, sizeof(probe->legacy_cookie));
            bc_request_release(probe->launch_request); probe->launch_request = NULL;
            bc_request_release(probe->h5_request); probe->h5_request = NULL;
        }
        complete(probe, probe->pending_failure ? probe->pending_failure : status, probe->pending_failure ? probe->pending_http : response->http_status);
        goto done;
    }
    if (phase == PHASE_LEGACY_CSRF) {
        bc_status status = response->status;
        yyjson_doc *doc = legacy_object(response->body);
        yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
        char csrf[257];
        if (status == BC_OK && response->http_status != 200) status = BC_HTTP_ERROR;
        if (status == BC_OK && !safe_token(yyjson_obj_get(legacy_record(root, "WEBVAR_STRUCTNAME_GETCSRFTOKEN"), "CSRFTOKEN"), csrf, sizeof(csrf))) status = BC_PROTOCOL_ERROR;
        if (doc) yyjson_doc_free(doc);
        if (status == BC_OK) { probe->csrf = copy_text(text(csrf)); status = probe->csrf ? legacy_jnlp(probe) : BC_NO_MEMORY; }
        if (status != BC_OK) fail_status(probe, status, response->http_status);
        goto done;
    }
    if (phase == PHASE_SESSION) { h5_session_response(probe, response); goto done; }
    if (phase == PHASE_H5_CONFIG) {
        if (response->status == BC_OK && response->http_status == 200) {
            yyjson_doc *doc = yyjson_read((const char *)response->body.data, (size_t)response->body.length, 0);
            yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
            bc_status status = root && yyjson_is_obj(root) ? bc_megarac_discover_h5_config(response->body.data,
                (uint32_t)response->body.length, &probe->result.info, &probe->profile) : BC_PROTOCOL_ERROR;
            yyjson_doc_free(doc);
            if (status == BC_OK && !probe->result.info.token[0]) status = BC_PROTOCOL_ERROR;
            if (status == BC_OK && probe->forced_variant && probe->forced_variant != probe->profile.variant) status = BC_UNSUPPORTED;
            if (status == BC_OK) probe->profile.evidence |= probe->selected_evidence;
            if (status == BC_OK) {
                capture_cookie(probe, request);
                bc_request_retain(request); bc_request_release(probe->h5_request); probe->h5_request = request;
                probe->result.kind = BC_MEGARAC_HTTP_H5VIEWER;
                probe->result.info.kind = BC_MEGARAC_KVM_H5VIEWER;
                if (!probe->result.info.client_ip[0] && probe->host_copy)
                    snprintf(probe->result.info.client_ip, sizeof(probe->result.info.client_ip), "%s", probe->host_copy);
                status = submit(probe, PHASE_KEYBOARD_VIEWER, BC_HTTP_GET, "/viewer.min.js",
                    (bc_bytes){NULL, 0}, NULL, 0, (bc_string){NULL, 0});
                if (status != BC_OK) complete(probe, BC_OK, response->http_status);
                goto done;
            }
            save_error(probe, response);
            fail_status(probe, status, response->http_status);
            goto done;
        }
        if ((response->status == BC_OK || response->status == BC_HTTP_ERROR) &&
            (response->http_status == 404 || response->http_status == 405) &&
            (!probe->forced_variant || probe->forced_variant == BC_SERVICE_MEGARAC_KVM_H5_373)) {
            bc_status status = submit(probe, PHASE_SPLIT_VIEWER, BC_HTTP_GET, "/viewer.min.js",
                (bc_bytes){NULL, 0}, NULL, 0, (bc_string){NULL, 0});
            if (status != BC_OK) fail_status(probe, status, response->http_status);
            goto done;
        }
        save_error(probe, response);
        fail_status(probe, response->status == BC_OK ? BC_HTTP_ERROR : response->status, response->http_status);
        goto done;
    }
    if (phase == PHASE_LEGACY_SESSION) {
        int rpc = probe->structured == DISCOVERY_INSPUR_RPC;
        if ((response->status == BC_OK || (rpc && response->status == BC_OUTCOME_UNKNOWN &&
            (response->flags & BC_RESPONSE_EARLY_EOF))) &&
            (response->http_status == 200 || response->http_status == 201)) {
            yyjson_doc *doc = rpc ? rpc_object(response, "WEBVAR_JSONVAR_WEB_SESSION") : legacy_object(response->body);
            yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
            yyjson_val *hapi = yyjson_obj_get(root, "HAPI_STATUS");
            bc_status status = BC_OK;
            if ((rpc || hapi) && !yyjson_is_int(hapi)) status = rpc && !doc ? BC_OUTCOME_UNKNOWN : BC_PROTOCOL_ERROR;
            else if (hapi && (yyjson_get_sint(hapi) == -2 || (rpc && yyjson_get_sint(hapi) >= 0xe0 &&
                yyjson_get_sint(hapi) <= 0xe2))) status = BC_AUTHENTICATION_FAILED;
            else if (hapi && (yyjson_get_sint(hapi) == -3 || (rpc && yyjson_get_sint(hapi) == 3))) status = BC_BUSY;
            else if (hapi && yyjson_get_sint(hapi) != 0) status = BC_PROTOCOL_ERROR;
            yyjson_val *record = legacy_record(root, "WEBVAR_STRUCTNAME_WEB_SESSION");
            if (status == BC_OK && yyjson_obj_get(record, "SESSION_COOKIE") && !safe_token(yyjson_obj_get(record, "SESSION_COOKIE"), probe->legacy_cookie, sizeof(probe->legacy_cookie))) status = BC_PROTOCOL_ERROR;
            char csrf[257] = {0};
            if (rpc) safe_token(yyjson_obj_get(record, "CSRFTOKEN"), csrf, sizeof(csrf));
            if (doc) yyjson_doc_free(doc);
            if (status == BC_OK && (probe->legacy_cookie[0] || (!rpc && has_session_cookie(bc_request_cookie_header(request))))) {
                probe->owned = 1; probe->result.kind = BC_MEGARAC_HTTP_JVIEWER; capture_cookie(probe, request);
                if (probe->legacy_cookie[0]) status = bc_endpoint_set_cookie(probe->endpoint, text("SessionCookie"), text(probe->legacy_cookie));
                if (status == BC_OK && rpc) {
                    if (!csrf[0]) status = BC_PROTOCOL_ERROR;
                    else if (!(probe->csrf = copy_text(text(csrf)))) status = BC_NO_MEMORY;
                }
                if (status == BC_OK) status = probe->login_flags & BC_MEGARAC_LOGIN_CSRF_COOKIE ?
                    probe->legacy_cookie[0] ? legacy_csrf(probe) : BC_PROTOCOL_ERROR : legacy_jnlp(probe);
            } else if (status == BC_OK) status = BC_PROTOCOL_ERROR;
            if (status != BC_OK) fail_status(probe, status, response->http_status);
        } else {
            save_error(probe, response);
            fail_status(probe, response->http_status == 401 || response->http_status == 403 ? BC_AUTHENTICATION_FAILED :
                response->status == BC_OK ? BC_PROTOCOL_ERROR : response->status, response->http_status);
        }
        goto done;
    }
    if (phase == PHASE_LEGACY_JNLP) {
        if ((response->status == BC_OK || (probe->structured == DISCOVERY_INSPUR_RPC && response->status == BC_IO_ERROR &&
            (response->flags & BC_RESPONSE_EARLY_EOF))) && response->http_status == 200 && response->body.length <= 65536) {
            bc_status status = probe->structured ? bc_megarac_discover_jnlp(response->body.data,
                (uint32_t)response->body.length, &probe->result.info, &probe->profile) :
                bc_megarac_parse_jnlp(response->body.data, (uint32_t)response->body.length, &probe->result.info);
            if (status == BC_OK && (!probe->result.info.token[0] || probe->result.info.port > 65535)) status = BC_PROTOCOL_ERROR;
            if (status == BC_OK) {
                capture_cookie(probe, request);
                bc_request_retain(request); bc_request_release(probe->launch_request); probe->launch_request = request;
                probe->result.kind = BC_MEGARAC_HTTP_JVIEWER;
                probe->profile = (bc_service_profile){sizeof(probe->profile), BC_SERVICE_KVM,
                    BC_SERVICE_FAMILY_MEGARAC, probe->forced_variant,
                    BC_SERVICE_EVIDENCE_DESCRIPTOR | probe->selected_evidence};
                probe->result.info.kind = probe->nec ? BC_MEGARAC_KVM_JVIEWER_195 : BC_MEGARAC_KVM_JVIEWER;
                if (probe->structured && !probe->forced_variant) probe->result.info.kind = 0;
                if (!probe->result.info.host[0] && probe->host_copy)
                    snprintf(probe->result.info.host, sizeof(probe->result.info.host), "%s", probe->host_copy);
                complete(probe, BC_OK, response->http_status);
            } else fail_status(probe, status, response->http_status);
        } else {
            save_error(probe, response);
            fail_status(probe, response->http_status == 401 || response->http_status == 403 ? BC_AUTHENTICATION_FAILED : response->status == BC_OK ? BC_HTTP_ERROR : response->status, response->http_status);
        }
        goto done;
    }
done:
    if (--probe->refs == 0) probe_destroy(probe);
}
static void fill_result(bc_megarac_probe *probe) { probe->result.struct_size = sizeof(probe->result); probe->result.cleanup_status = BC_CANCELLED; }
static bc_status start_probe(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    const bc_service_profile *profile, int structured, const bc_megarac_login_contract *login, bc_bytes form,
    bc_megarac_probe_completion callback, void *userdata, bc_megarac_probe **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (profile && (!bc_service_profile_can_attempt(profile, BC_SERVICE_KVM) ||
        profile->family != BC_SERVICE_FAMILY_MEGARAC)) return BC_INVALID_ARGUMENT;
    if (login && (login->struct_size != sizeof(*login) ||
        (login->kind != BC_MEGARAC_LOGIN_LEGACY_RPC && login->kind != BC_MEGARAC_LOGIN_H5_SESSION) ||
        (login->flags & ~7u) || (login->kind == BC_MEGARAC_LOGIN_H5_SESSION && login->flags))) return BC_INVALID_ARGUMENT;
    if (login && (login->flags & BC_MEGARAC_LOGIN_TRANSPORT_TYPE)) {
        bc_string origin = bc_endpoint_origin(endpoint);
        if (!origin.data || origin.length < 8) return BC_INVALID_ARGUMENT;
        const char scheme[] = "https://";
        for (unsigned i = 0; i < 8; ++i) {
            unsigned char c = (unsigned char)origin.data[i];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != (unsigned char)scheme[i]) return BC_INVALID_ARGUMENT;
        }
    }
    if (!endpoint || !options || !callback || (options->struct_size != sizeof(*options) && options->struct_size != offsetof(bc_megarac_probe_options, client_id)) ||
        options->abi_version != BC_ABI_VERSION || !options->host.length || !options->username.length ||
        !options->password.length || options->host.length > 255 || options->username.length > 255 ||
        options->password.length > 1024 || !options->host.data || !options->username.data || !options->password.data ||
        memchr(options->host.data, 0, (size_t)options->host.length) || memchr(options->username.data, 0, (size_t)options->username.length) ||
        memchr(options->password.data, 0, (size_t)options->password.length)) return BC_INVALID_ARGUMENT;
    if (options->struct_size == sizeof(*options) && options->client_id.length) {
        if (options->client_id.length != 8 || !options->client_id.data) return BC_INVALID_ARGUMENT;
        for (unsigned i = 0; i < 8; ++i) if (options->client_id.data[i] < '0' || options->client_id.data[i] > '9') return BC_INVALID_ARGUMENT;
    }
    bc_megarac_probe *probe = calloc(1, sizeof(*probe));
    if (!probe) return BC_NO_MEMORY;
    fill_result(probe);
    probe->structured = structured; probe->explicit_login = login != NULL;
    probe->forced_variant = profile ? profile->variant : 0;
    probe->selected_evidence = profile ? profile->evidence & BC_SERVICE_EVIDENCE_MANUAL : 0;
    probe->nec = probe->forced_variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195;
    probe->login_flags = login ? login->flags : probe->nec ? EXTENDED_LOGIN : 0u;
    probe->host_copy = copy_text(options->host);
    probe->username_copy = copy_text(options->username);
    probe->password_copy = copy_text(options->password);
    probe->endpoint = endpoint;
    memcpy(&probe->options, options, options->struct_size);
    if (options->struct_size == sizeof(*options) && options->client_id.length) memcpy(probe->client_id, options->client_id.data, 8);
    probe->options.timeout_ms = options->timeout_ms ? options->timeout_ms : 5000;
    probe->callback = callback; probe->userdata = userdata;
    probe->refs = 1;
    BC_LOG_INFO(BC_LOG_CATEGORY_VENDOR, "megarac.probe.start", "host_len=%" PRIu64 " user_len=%" PRIu64
        " password=%u timeout_ms=%u", options->host.length, options->username.length,
        options->password.length != 0, probe->options.timeout_ms);
    if (!probe->host_copy || !probe->username_copy || !probe->password_copy) {
        free(probe->host_copy); free(probe->username_copy); free_secret(probe->password_copy); free(probe);
        return BC_NO_MEMORY;
    }
    bc_endpoint_retain(endpoint);
    bc_status status = form.length ? submit(probe, PHASE_SESSION, BC_HTTP_POST, "/api/session",
        form, NULL, 0, text("application/x-www-form-urlencoded")) : (!structured || structured >= 2) ? submit(probe, PHASE_IDENTIFY, BC_HTTP_GET, "/index.html",
        (bc_bytes){NULL, 0}, NULL, 0, (bc_string){NULL, 0}) :
        login ? login->kind == BC_MEGARAC_LOGIN_LEGACY_RPC ? legacy_session(probe) : h5_session(probe) :
        (profile && profile->variant != BC_SERVICE_MEGARAC_KVM_H5_438 &&
            profile->variant != BC_SERVICE_MEGARAC_KVM_H5_373) ? legacy_session(probe) : h5_session(probe);
    if (status != BC_OK) {
        bc_endpoint_release(endpoint);
        free(probe->host_copy); free(probe->username_copy); free_secret(probe->password_copy); free(probe);
        return status;
    }
    *out = probe;
    return BC_OK;
}
bc_status bc_megarac_probe_start(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    bc_megarac_probe_completion callback, void *userdata, bc_megarac_probe **out) {
    return start_probe(endpoint, options, NULL, 0, NULL, (bc_bytes){NULL, 0}, callback, userdata, out);
}
bc_status bc_inspur_kvm_probe_start(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    bc_megarac_probe_completion callback, void *userdata, bc_megarac_probe **out) {
    return start_probe(endpoint, options, NULL, 2, NULL, (bc_bytes){NULL, 0}, callback, userdata, out);
}
bc_status bc_inspur_rpc_kvm_probe_start(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    bc_megarac_probe_completion callback, void *userdata, bc_megarac_probe **out) {
    return start_probe(endpoint, options, NULL, DISCOVERY_INSPUR_RPC, NULL, (bc_bytes){0}, callback, userdata, out);
}
bc_status bc_megarac_probe_start_discovery(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    const bc_service_profile *profile, bc_megarac_probe_completion callback, void *userdata, bc_megarac_probe **out) {
    return start_probe(endpoint, options, profile, 1, NULL, (bc_bytes){NULL, 0}, callback, userdata, out);
}
bc_status bc_megarac_probe_start_with_login(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    const bc_megarac_login_contract *login, bc_megarac_probe_completion callback, void *userdata, bc_megarac_probe **out) {
    if (!login) { if (out) *out = NULL; return BC_INVALID_ARGUMENT; }
    return start_probe(endpoint, options, NULL, 1, login, (bc_bytes){NULL, 0}, callback, userdata, out);
}
bc_status bc_megarac_probe_start_with_login_profile(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    const bc_megarac_login_contract *login, const bc_service_profile *profile,
    bc_megarac_probe_completion callback, void *userdata, bc_megarac_probe **out) {
    if (!login) { if (out) *out = NULL; return BC_INVALID_ARGUMENT; }
    return start_probe(endpoint, options, profile, 1, login, (bc_bytes){NULL, 0}, callback, userdata, out);
}
bc_status bc_megarac_probe_start_form(bc_endpoint *endpoint, const bc_megarac_probe_options *options,
    bc_bytes form, bc_megarac_probe_completion callback, void *user, bc_megarac_probe **out) {
    bc_megarac_login_contract login = {sizeof(login), BC_MEGARAC_LOGIN_H5_SESSION, 0};
    return start_probe(endpoint, options, NULL, 1, &login, form, callback, user, out);
}
bc_request *bc_megarac_probe_launch_request(const bc_megarac_probe *probe) {
    return probe && probe->done && probe->owned && !probe->closing && probe->result.status == BC_OK ? probe->launch_request : NULL;
}
bc_endpoint *bc_megarac_probe_endpoint(const bc_megarac_probe *probe) {
    return probe && probe->done && probe->owned && !probe->closing && probe->result.status == BC_OK ? probe->endpoint : NULL;
}
uint32_t bc_megarac_probe_keyboard_mode(const bc_megarac_probe *probe) {
    return probe && probe->done && probe->owned && !probe->closing && probe->result.status == BC_OK ?
        probe->keyboard_mode : BC_MEGARAC_KEYBOARD_DEFAULT;
}
bc_status bc_megarac_probe_media_parameters(const bc_megarac_probe *probe, bc_megarac_media_parameters *out) {
    if (!probe || !out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!probe->done || !probe->owned || probe->closing || probe->result.status != BC_OK) return BC_UNSUPPORTED;
    if (probe->split_h5) {
        *out = probe->split_media;
        return out->struct_size ? BC_OK : BC_UNSUPPORTED;
    }
    const bc_response *response = bc_request_response(probe->result.kind == BC_MEGARAC_HTTP_H5VIEWER ?
        probe->h5_request : probe->launch_request);
    if (!response || response->status != BC_OK || response->http_status != 200) return BC_UNSUPPORTED;
    if (response->body.length > UINT32_MAX) return BC_LIMIT_EXCEEDED;
    if (probe->result.kind == BC_MEGARAC_HTTP_H5VIEWER)
        return bc_megarac_h5_media_parameters(response->body.data, (uint32_t)response->body.length, out);
    return bc_megarac_jviewer_media_parameters(response->body.data, (uint32_t)response->body.length, out);
}
bc_status bc_megarac_probe_logout(bc_megarac_probe *probe, bc_megarac_probe_completion callback, void *userdata) {
    if (!probe || !callback || !probe->done || !probe->owned || probe->closing) return BC_INVALID_ARGUMENT;
    probe->callback = callback; probe->userdata = userdata; probe->closing = 1; probe->done = 0;
    probe->pending_failure = BC_OK; probe->pending_http = 0;
    bc_status status = logout_request(probe);
    if (status != BC_OK) { probe->done = 1; probe->closing = 0; }
    return status;
}
const bc_megarac_probe_result *bc_megarac_probe_result_get(const bc_megarac_probe *probe) {
    return probe && probe->done ? &probe->result : NULL;
}
const bc_console_failure *bc_megarac_probe_failure_get(const bc_megarac_probe *probe) {
    return probe && probe->done && probe->failure.status != BC_OK ? &probe->failure : NULL;
}
const bc_service_profile *bc_megarac_probe_profile_get(const bc_megarac_probe *probe) {
    return probe && probe->done && probe->result.status == BC_OK ? &probe->profile : NULL;
}
void bc_megarac_probe_release(bc_megarac_probe *probe) {
    if (probe && --probe->refs == 0) probe_destroy(probe);
}

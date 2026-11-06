#include "internal.h"
#include "../avocent/web_internal.h"
#include "yyjson.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#define LOGIN 1u
#define CSRF 2u
#define LOGOUT 3u
struct bc_web_session {
    bc_endpoint *endpoint;
    bc_request *request;
    bc_web_session_result result;
    bc_web_session_completion callback;
    void *user;
    uint32_t refs, phase, timeout_ms, pending_http, kind;
    int owned, ready, closing, released, cancelled, cleanup_clock_set, cookie_ready, login_rejected;
    uint64_t started, last_time, cleanup_started, cleanup_last;
    uint64_t (*clock)(void *);
    void *clock_user;
    bc_status pending;
    char cookie_name[65], cookie[257], csrf[257], csrf_path[1025], st1[257];
};
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static void erase(void *p, size_t n) { volatile unsigned char *b = p; while (n--) *b++ = 0; }
static char *base64(bc_string value) {
    if(value.length>4096)return NULL;
    size_t size=4*(((size_t)value.length+2)/3)+1;
    char *out=malloc(size);if(!out)return NULL;
    EVP_EncodeBlock((unsigned char *)out,(const unsigned char *)value.data,(int)value.length);return out;
}
static void destroy(bc_web_session *s) {
    bc_request_release(s->request); bc_endpoint_release(s->endpoint); erase(s, sizeof(*s)); free(s);
}
static void complete(bc_web_session *s, bc_status status) {
    s->result.status = status; s->ready = 1;
    ++s->refs;
    if (s->callback) s->callback(s, s->user);
    if (!--s->refs) destroy(s);
}
static yyjson_doc *response_object(bc_bytes body, const char *name) {
    if (!body.data || !body.length || body.length > 65536) return NULL;
    const char *p = (const char *)body.data; size_t n = (size_t)body.length, at = 0;
    while (at < n && (p[at] == ' ' || p[at] == '\r' || p[at] == '\n' || p[at] == '\t')) ++at;
    if (at + 4 <= n && !memcmp(p + at, "var ", 4)) at += 4;
    while (at < n && (p[at] == ' ' || p[at] == '\t')) ++at;
    size_t len = name ? strlen(name) : 0;
    if (name) {
        if (at + len >= n || memcmp(p + at, name, len)) return NULL;
        at += len;
    } else {
        size_t begin = at;
        while (at < n && ((p[at] >= 'a' && p[at] <= 'z') || (p[at] >= 'A' && p[at] <= 'Z') || p[at] == '_' || (at > begin && p[at] >= '0' && p[at] <= '9'))) ++at;
        if (at == begin || at - begin > 64) return NULL;
    }
    while (at < n && (p[at] == ' ' || p[at] == '\t')) ++at;
    if (at == n || p[at++] != '=') return NULL;
    yyjson_doc *doc = yyjson_read(p + at, n - at, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR |
        YYJSON_READ_ALLOW_UNQUOTED_KEY | YYJSON_READ_ALLOW_TRAILING_COMMAS | YYJSON_READ_STOP_WHEN_DONE);
    if (!doc) return NULL;
    at += yyjson_doc_get_read_size(doc);
    if (at < n && p[at] == ';') ++at;
    while (at < n && (p[at] == ' ' || p[at] == '\r' || p[at] == '\n' || p[at] == '\t')) ++at;
    if (at != n || !yyjson_is_obj(yyjson_doc_get_root(doc))) { yyjson_doc_free(doc); return NULL; }
    return doc;
}
static bc_status hapi(yyjson_val *root) {
    yyjson_val *v = yyjson_obj_get(root, "HAPI_STATUS");
    if (!yyjson_is_int(v)) return BC_PROTOCOL_ERROR;
    int64_t code = yyjson_get_sint(v);
    return code == 0 ? BC_OK : code == -2 ? BC_AUTHENTICATION_FAILED : code == -3 ? BC_BUSY : BC_PROTOCOL_ERROR;
}
static int token(yyjson_val *root, const char *list, const char *key, char out[257]) {
    yyjson_val *array = yyjson_obj_get(root, list);
    if (!yyjson_is_arr(array) || !yyjson_arr_size(array) || yyjson_arr_size(array) > 16) return 0;
    yyjson_val *v = yyjson_obj_get(yyjson_arr_get_first(array), key);
    const char *p = yyjson_get_str(v); size_t n = yyjson_get_len(v);
    if (!p || !n || n > 256) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    memcpy(out, p, n); out[n] = 0; return 1;
}
static bc_status remaining(bc_web_session *s, uint32_t phase, uint32_t *budget) {
    uint64_t now = s->clock(s->clock_user), start = s->started, last = s->last_time;
    uint32_t limit = s->timeout_ms;
    if (phase == LOGOUT) {
        limit = limit < 5000 ? limit : 5000;
        if (!s->cleanup_clock_set) {
            s->cleanup_started = s->cleanup_last = now; s->cleanup_clock_set = 1;
        }
        start = s->cleanup_started; last = s->cleanup_last;
    }
    if (now < last) return BC_INVALID_ARGUMENT;
    if (phase == LOGOUT) s->cleanup_last = now; else s->last_time = now;
    if (now - start >= limit) return BC_TIMEOUT;
    *budget = limit - (uint32_t)(now - start); return BC_OK;
}
static const char *logout_path(const bc_web_session *s) {
    return s->kind == BC_WEB_LOGIN_ATEN_CGI ? "/cgi/logout.cgi" :
        s->kind == BC_WEB_LOGIN_APPWEB_XML ? "/data/logout" : "/rpc/WEBSES/logout.asp";
}
bc_status bc_web_session_submit(bc_web_session *s, const bc_http_options *options,
    bc_completion callback, void *user, bc_request **out) {
    if (!s || !options || !out) return BC_INVALID_ARGUMENT;
    bc_http_options request = *options;
    char path[8193], header[264]; bc_string headers[2];
    if (s->kind == BC_WEB_LOGIN_APPWEB_XML && s->st1[0] && s->csrf[0]) {
        if (!options->path.data || options->path.length > 7000 || options->header_count) return BC_INVALID_ARGUMENT;
        int n = snprintf(path, sizeof(path), "%.*s%cST1=%s", (int)options->path.length, options->path.data,
            memchr(options->path.data, '?', (size_t)options->path.length) ? '&' : '?', s->st1);
        if (n < 0 || (size_t)n >= sizeof(path)) return BC_LIMIT_EXCEEDED;
        snprintf(header, sizeof(header), "ST2: %s", s->csrf);
        headers[0] = text(header); request.headers = headers; request.header_count = 1; request.path = text(path);
    }
    if (s->kind == BC_WEB_LOGIN_ATEN_CGI && s->owned && !options->header_count) {
        bc_string origin = bc_endpoint_origin(s->endpoint);
        int n = snprintf(path, sizeof(path), "Referer: %.*s/cgi/url_redirect.cgi?url_name=man_ikvm", (int)origin.length, origin.data);
        if (n < 0 || (size_t)n >= sizeof(path)) return BC_LIMIT_EXCEEDED;
        headers[0] = text(path); request.headers = headers; request.header_count = 1;
    }
    return bc_http_submit(s->endpoint, &request, callback, user, out);
}
static void done(bc_request *, const bc_response *, void *);
static bc_status submit(bc_web_session *s, uint32_t phase, const char *path, const char *body) {
    bc_http_options o = {0}; o.struct_size = sizeof(o); o.abi_version = BC_ABI_VERSION;
    uint32_t budget; bc_status status = remaining(s, phase, &budget);
    if (status != BC_OK) return status;
    o.path = text(path); o.method = body ? BC_HTTP_POST : BC_HTTP_GET; o.timeout_ms = budget;
    o.body = (bc_bytes){(const uint8_t *)body, body ? strlen(body) : 0};
    if (body) o.content_type = text("application/x-www-form-urlencoded");
    bc_request *request = NULL;
    status = bc_web_session_submit(s, &o, done, s, &request);
    if (status == BC_OK) {
        s->phase = phase; ++s->refs;
        bc_request_release(s->request); s->request = request;
    }
    return status;
}
static void fail(bc_web_session *s, bc_status status) {
    if (s->owned) {
        if (!s->cookie_ready) { s->result.cleanup_status = BC_OUTCOME_UNKNOWN; complete(s, status); return; }
        s->pending = status; s->pending_http = s->result.http_status; s->closing = 1;
        bc_status cleanup = submit(s, LOGOUT, logout_path(s), NULL);
        if (cleanup == BC_OK) return;
        s->result.cleanup_status = cleanup;
    } else {
        s->result.cleanup_status = s->phase == LOGIN && !s->login_rejected ? BC_OUTCOME_UNKNOWN : BC_OK;
    }
    complete(s, status);
}
static void capture_cookie(bc_web_session *s, const bc_request *request) {
    bc_string header = bc_request_cookie_header(request); size_t name = strlen(s->cookie_name);
    for (uint64_t i = 0; i + name + 1 < header.length; ++i) {
        if ((i && header.data[i - 1] != ' ' && header.data[i - 1] != ';') ||
            memcmp(header.data + i, s->cookie_name, name) || header.data[i + name] != '=') continue;
        uint64_t begin = i + name + 1, end = begin;
        while (end < header.length && header.data[end] != ';' && header.data[end] != ' ') ++end;
        if (end == begin || end - begin > 256) return;
        for (uint64_t j = begin; j < end; ++j) {
            unsigned char c = (unsigned char)header.data[j];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return;
        }
        memcpy(s->cookie, header.data + begin, (size_t)(end - begin)); s->cookie[end - begin] = 0; s->owned = 1; return;
    }
}
typedef struct { char st1[257], st2[257]; unsigned found; } csrf_tokens;
static bc_status csrf_link(void *user, uint32_t kind, bc_string value) {
    if (kind != BC_WEB_LINK_INLINE) return BC_OK;
    csrf_tokens *tokens = user; char st1[257], st2[257];
    bc_status status = bc_web_login_csrf_tokens((const uint8_t *)value.data, (uint32_t)value.length, st1, st2);
    if (status == BC_OK) {
        if (++tokens->found != 1) return BC_PROTOCOL_ERROR;
        strcpy(tokens->st1, st1); strcpy(tokens->st2, st2);
    }
    erase(st1, sizeof(st1)); erase(st2, sizeof(st2));
    return status == BC_UNSUPPORTED ? BC_OK : status;
}
static bc_status appweb_done(bc_web_session *s, bc_request *request, const bc_response *response, bc_status status) {
    uint32_t phase = s->phase;
    bc_avocent_web_reply reply = {0};
    if (phase != CSRF && status == BC_OK) {
        status = bc_avocent_web_parse(response->body, phase == LOGIN, &reply);
        if (status == BC_OK && reply.status) status = BC_PROTOCOL_ERROR;
        if (phase == LOGIN && status == BC_OK && reply.auth_result) {
            s->login_rejected = 1;
            status = reply.auth_result == 7 ? BC_BUSY : BC_AUTHENTICATION_FAILED;
        }
    }
    if (phase == LOGIN) {
        s->login_rejected |= response->http_status == 401 || response->http_status == 403;
        /* A rejected/duplicate login never grants ownership of a returned cookie. */
        if (!s->login_rejected) capture_cookie(s, request);
        if (status == BC_OK && !s->owned) status = BC_PROTOCOL_ERROR;
        if (s->owned) {
            bc_status cookie_status = bc_endpoint_set_cookie(s->endpoint, text(s->cookie_name), text(s->cookie));
            s->cookie_ready = cookie_status == BC_OK;
            if (status == BC_OK) status = cookie_status;
        }
        if (status == BC_OK && reply.forward[0]) {
            char resolved[1025];
            if (!bc_web_login_resolve_path(text("/"), text(reply.forward), resolved)) status = BC_PROTOCOL_ERROR;
            else strcpy(s->result.landing_path, resolved);
        }
        uint32_t budget; bc_status elapsed = remaining(s, LOGIN, &budget);
        if (status == BC_OK) status = elapsed;
        if (s->cancelled || s->released) status = BC_CANCELLED;
        if (status == BC_OK) status = submit(s, CSRF, s->result.landing_path, NULL);
    } else if (phase == CSRF) {
        csrf_tokens tokens = {0};
        if (status == BC_OK) status = bc_web_login_html_links(response->body.data, (uint32_t)response->body.length, csrf_link, &tokens);
        if (status == BC_OK && tokens.found != 1) status = BC_UNSUPPORTED;
        if (status == BC_OK) { strcpy(s->st1, tokens.st1); strcpy(s->csrf, tokens.st2); }
        erase(&tokens, sizeof(tokens));
        uint32_t budget; bc_status elapsed = remaining(s, CSRF, &budget);
        if (status == BC_OK) status = elapsed;
        if (s->cancelled || s->released) status = BC_CANCELLED;
        if (status == BC_OK) complete(s, BC_OK);
    } else {
        uint32_t budget; bc_status elapsed = remaining(s, LOGOUT, &budget);
        if (status == BC_OK) status = elapsed;
        s->result.cleanup_status = status; s->closing = 0;
        if (status == BC_OK) { s->owned = 0; erase(s->cookie, sizeof(s->cookie)); erase(s->csrf, sizeof(s->csrf)); erase(s->st1, sizeof(s->st1)); }
        if (s->pending) s->result.http_status = s->pending_http;
        complete(s, s->cancelled ? BC_CANCELLED : s->pending ? s->pending : status);
    }
    erase(&reply, sizeof(reply)); return status;
}
typedef struct { int success, rejected, root; } aten_reply;
static bc_status aten_link(void *user, uint32_t kind, bc_string value) {
    aten_reply *r = user;
    if (kind == BC_WEB_LINK_INLINE) return bc_web_login_script_links((const uint8_t *)value.data, (uint32_t)value.length, aten_link, user);
    char path[1025];
    if (!bc_web_login_resolve_path(text("/cgi/login.cgi"), value, path)) return BC_OK;
    if (!strcmp(path,"/cgi/url_redirect.cgi?url_name=mainmenu")) r->success=1;
    if (!strncmp(path,"/cgi/url_redirect.cgi?url_name=login_alert",40)) r->rejected=1;
    if (!strcmp(path,"/")) r->root=1;
    return BC_OK;
}
static bc_status aten_done(bc_web_session *s, bc_request *request, const bc_response *response, bc_status status) {
    aten_reply reply={0};
    if(status==BC_OK)status=bc_web_login_html_links(response->body.data,(uint32_t)response->body.length,aten_link,&reply);
    if(s->phase==LOGIN) {
        s->login_rejected=response->http_status==401 || response->http_status==403 || reply.rejected || reply.root;
        if(s->login_rejected)status=BC_AUTHENTICATION_FAILED;
        if(!s->login_rejected)capture_cookie(s,request);
        if(status==BC_OK && (!reply.success || !s->owned))status=BC_PROTOCOL_ERROR;
        if(s->owned) {
            bc_status result=bc_endpoint_set_cookie(s->endpoint,text("SID"),text(s->cookie));
            s->cookie_ready=result==BC_OK;
            if(status==BC_OK)status=result;
            if(status==BC_OK)status=bc_endpoint_set_cookie(s->endpoint,text("langSetFlag"),text("0"));
            if(status==BC_OK)status=bc_endpoint_set_cookie(s->endpoint,text("language"),text("English"));
        }
        uint32_t budget;
        if(status==BC_OK)status=remaining(s,LOGIN,&budget);
        if(s->cancelled || s->released)status=BC_CANCELLED;
        if(status==BC_OK)complete(s,BC_OK);
    } else {
        bc_web_login_hint hint;
        if(status==BC_OK && !reply.root && bc_web_login_form_hint(response->body.data,(uint32_t)response->body.length,&hint)!=BC_OK)
            status=BC_OUTCOME_UNKNOWN;
        s->result.cleanup_status=status;s->closing=0;
        if(status==BC_OK){s->owned=0;erase(s->cookie,sizeof(s->cookie));}
        if(s->pending)s->result.http_status=s->pending_http;
        complete(s,s->pending?s->pending:status);
    }
    return status;
}
static void done(bc_request *request, const bc_response *response, void *user) {
    bc_web_session *s = user; uint32_t phase = s->phase;
    bc_status status = response->status;
    if (request != s->request) status = BC_PROTOCOL_ERROR;
    if ((status == BC_OK || status == BC_HTTP_ERROR) && response->http_status != 200 && !(phase == LOGIN && response->http_status == 201))
        status = response->http_status == 401 || response->http_status == 403 ? BC_AUTHENTICATION_FAILED : BC_HTTP_ERROR;
    s->result.http_status = response->http_status;
    if (s->kind == BC_WEB_LOGIN_APPWEB_XML || s->kind == BC_WEB_LOGIN_ATEN_CGI) {
        status = s->kind == BC_WEB_LOGIN_ATEN_CGI ? aten_done(s, request, response, status) : appweb_done(s, request, response, status);
        if (phase != LOGOUT && status != BC_OK) fail(s, status);
        if (!--s->refs) destroy(s);
        return;
    }
    yyjson_doc *doc = status == BC_OK ? response_object(response->body,
        phase == LOGIN ? "WEBVAR_JSONVAR_WEB_SESSION" : phase == CSRF ? "WEBVAR_JSONVAR_GETCSRFTOKEN" : NULL) : NULL;
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    if (status == BC_OK) status = hapi(root);
    if (phase == LOGIN) {
        yyjson_val *answer = yyjson_obj_get(root, "HAPI_STATUS");
        s->login_rejected = (yyjson_is_int(answer) && yyjson_get_sint(answer) != 0) ||
            response->http_status == 401 || response->http_status == 403;
        capture_cookie(s, request);
        if (root && token(root, "WEBVAR_STRUCTNAME_WEB_SESSION", "SESSION_COOKIE", s->cookie)) s->owned = 1;
        if (status == BC_OK && !s->owned) status = BC_PROTOCOL_ERROR;
        if (s->owned) {
            bc_status cookie_status = bc_endpoint_set_cookie(s->endpoint, text(s->cookie_name), text(s->cookie));
            s->cookie_ready = cookie_status == BC_OK;
            if (status == BC_OK && cookie_status != BC_OK) status = cookie_status;
        }
        uint32_t budget; bc_status elapsed = remaining(s, LOGIN, &budget);
        if (status == BC_OK && elapsed != BC_OK) status = elapsed;
        if (s->cancelled || s->released) status = BC_CANCELLED;
        if (status == BC_OK) {
            char body[288]; snprintf(body, sizeof(body), "SESSION_COOKIE=%s", s->cookie);
            status = submit(s, CSRF, s->csrf_path, body); erase(body, sizeof(body));
        }
    } else if (phase == CSRF) {
        if (status == BC_OK && !token(root, "WEBVAR_STRUCTNAME_GETCSRFTOKEN", "CSRFTOKEN", s->csrf)) status = BC_PROTOCOL_ERROR;
        uint32_t budget; bc_status elapsed = remaining(s, CSRF, &budget);
        if (status == BC_OK && elapsed != BC_OK) status = elapsed;
        if (s->cancelled || s->released) status = BC_CANCELLED;
        if (status == BC_OK) complete(s, BC_OK);
    } else {
        uint32_t budget; bc_status elapsed = remaining(s, LOGOUT, &budget);
        if (status == BC_OK && elapsed != BC_OK) status = elapsed;
        s->result.cleanup_status = status; s->closing = 0;
        if (status == BC_OK) {
            s->owned = 0; erase(s->cookie, sizeof(s->cookie)); erase(s->csrf, sizeof(s->csrf));
        }
        if (s->pending) s->result.http_status = s->pending_http;
        complete(s, s->cancelled ? BC_CANCELLED : s->pending ? s->pending : status);
    }
    if (doc) yyjson_doc_free(doc);
    if (phase != LOGOUT && status != BC_OK) fail(s, status);
    if (!--s->refs) destroy(s);
}
static char *encode(bc_string value) {
    if (value.length > 2048 || (!value.data && value.length)) return NULL;
    char *out = malloc((size_t)value.length * 3 + 1); if (!out) return NULL;
    size_t at = 0; const char *hex = "0123456789ABCDEF";
    for (uint64_t i = 0; i < value.length; ++i) {
        unsigned char c = (unsigned char)value.data[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') out[at++] = (char)c;
        else { out[at++] = '%'; out[at++] = hex[c >> 4]; out[at++] = hex[c & 15]; }
    }
    out[at] = 0; return out;
}
bc_status bc_web_session_start(bc_web_login_contract *permit, const bc_web_session_options *o,
    bc_web_session_completion callback, void *user, bc_web_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!permit || !o || o->struct_size != sizeof(*o) || o->abi_version != BC_ABI_VERSION || !callback ||
        !o->timeout_ms || o->timeout_ms > 60000 || !o->clock_ms || !o->username.data || !o->password.data ||
        !o->username.length || o->username.length > 255 || !o->password.length || o->password.length > 1024 ||
        memchr(o->username.data, 0, (size_t)o->username.length) || memchr(o->password.data, 0, (size_t)o->password.length)) return BC_INVALID_ARGUMENT;
    if (permit->consumed) return BC_BUSY;
    bc_status status = bc_web_login_contract_validate(permit); if (status != BC_OK) return status;
    if (permit->flags & BC_WEB_LOGIN_CLIENT_ID) {
        if (!o->client_id.data || o->client_id.length != 8) return BC_INVALID_ARGUMENT;
        for (unsigned i = 0; i < 8; ++i) if (o->client_id.data[i] < '0' || o->client_id.data[i] > '9') return BC_INVALID_ARGUMENT;
    }
    bc_web_session *s = calloc(1, sizeof(*s)); if (!s) return BC_NO_MEMORY;
    s->kind = permit->kind; s->refs = 1; s->callback = callback; s->user = user; s->timeout_ms = o->timeout_ms;
    s->clock = o->clock_ms; s->clock_user = o->clock_user; s->started = s->last_time = s->clock(s->clock_user);
    s->result.struct_size = sizeof(s->result); s->result.status = BC_BUSY; s->result.cleanup_status = BC_CANCELLED;
    strcpy(s->result.landing_path, permit->landing_path); strcpy(s->cookie_name, permit->cookie_name); strcpy(s->csrf_path, permit->csrf_path);
    bc_auth_options auth = {0}; auth.struct_size = sizeof(auth); auth.abi_version = BC_ABI_VERSION; auth.mode = BC_AUTH_NONE;
    status = bc_endpoint_with_auth(permit->endpoint, &auth, &s->endpoint);
    if (status == BC_OK) status = bc_endpoint_cookie_jar_available(s->endpoint);
    char *encoded_user=NULL,*encoded_password=NULL;
    bc_string login_user=o->username,login_password=o->password;
    if(s->kind==BC_WEB_LOGIN_ATEN_CGI && (permit->flags&BC_WEB_LOGIN_ATEN_BASE64)) {
        encoded_user=base64(o->username);encoded_password=base64(o->password);
        if(!encoded_user || !encoded_password)status=BC_NO_MEMORY;
        else {login_user=text(encoded_user);login_password=text(encoded_password);}
    }
    char *escaped = s->kind == BC_WEB_LOGIN_APPWEB_XML ? bc_avocent_web_password(o->password) : NULL;
    char *username = encode(login_user), *password = s->kind == BC_WEB_LOGIN_APPWEB_XML ?
        (escaped ? encode(text(escaped)) : NULL) : encode(login_password), *body = NULL;
    if(encoded_user){erase(encoded_user,strlen(encoded_user));free(encoded_user);}
    if(encoded_password){erase(encoded_password,strlen(encoded_password));free(encoded_password);}
    if (escaped) { erase(escaped, strlen(escaped)); free(escaped); }
    if (status == BC_OK && (!username || !password)) status = BC_NO_MEMORY;
    if (status == BC_OK) {
        size_t capacity = strlen(username) + strlen(password) + 100; body = malloc(capacity);
        if (!body) status = BC_NO_MEMORY;
        else {
            snprintf(body, capacity, s->kind == BC_WEB_LOGIN_ATEN_CGI ? "name=%s&pwd=%s" : s->kind == BC_WEB_LOGIN_APPWEB_XML ? "user=%s&password=%s" : "WEBVAR_USERNAME=%s&WEBVAR_PASSWORD=%s", username, password);
            if(s->kind==BC_WEB_LOGIN_ATEN_CGI && (permit->flags&BC_WEB_LOGIN_ATEN_BASE64))strcat(body,"&check=00");
            if (permit->flags & BC_WEB_LOGIN_CLIENT_ID) {
                strcat(body, "&WEBVAR_IPADDR="); strncat(body, o->client_id.data, 8);
            }
            if (permit->flags & BC_WEB_LOGIN_TRANSPORT_TYPE) strcat(body, "&WEBVAR_TYPE=Https");
            permit->consumed = 1; status = submit(s, LOGIN, s->kind == BC_WEB_LOGIN_ATEN_CGI ? "/cgi/login.cgi" : s->kind == BC_WEB_LOGIN_APPWEB_XML ? "/data/login" : "/rpc/WEBSES/create.asp", body);
        }
    }
    if (username) { erase(username, strlen(username)); free(username); }
    if (password) { erase(password, strlen(password)); free(password); }
    if (body) { erase(body, strlen(body)); free(body); }
    if (status != BC_OK) { destroy(s); return status; }
    *out = s; return BC_OK;
}
const bc_web_session_result *bc_web_session_result_get(const bc_web_session *s) { return s && s->ready ? &s->result : NULL; }
bc_endpoint *bc_web_session_endpoint(const bc_web_session *s) { return s && s->ready && s->owned && !s->closing && s->result.status == BC_OK ? s->endpoint : NULL; }
bc_status bc_web_session_cancel(bc_web_session *s) {
    if (!s || s->released) return BC_INVALID_ARGUMENT;
    if (s->ready) return s->owned ? BC_BUSY : BC_UNSUPPORTED;
    if (s->cancelled) return BC_OK;
    s->cancelled = 1;
    /* A submitted login may already have created a session; observe its bounded
     * response rather than deleting the only way to identify our owner. */
    if (s->phase == CSRF && !s->closing) return bc_request_cancel(s->request);
    return BC_OK;
}
bc_status bc_web_session_close(bc_web_session *s, bc_web_session_completion callback, void *user) {
    if (!s || !callback) return BC_INVALID_ARGUMENT;
    if (!s->ready || s->closing) return BC_BUSY;
    if (!s->owned) return BC_UNSUPPORTED;
    if (!s->cookie_ready) {
        bc_status status = bc_endpoint_set_cookie(s->endpoint, text(s->cookie_name), text(s->cookie));
        if (status != BC_OK) { s->result.cleanup_status = BC_OUTCOME_UNKNOWN; return status; }
        s->cookie_ready = 1;
    }
    s->callback = callback; s->user = user; s->ready = 0; s->closing = 1; s->pending = BC_OK; s->cancelled = 0;
    bc_status status = submit(s, LOGOUT, logout_path(s), NULL);
    if (status != BC_OK) { s->closing = 0; s->ready = 1; s->result.cleanup_status = status; }
    return status;
}
void bc_web_session_release(bc_web_session *s) {
    if (!s || s->released) return;
    if (!s->ready && !s->closing) (void)bc_web_session_cancel(s);
    s->released = 1; s->callback = NULL; s->user = NULL;
    if (s->ready && s->owned && !s->closing) {
        if (!s->cookie_ready) s->cookie_ready = bc_endpoint_set_cookie(s->endpoint, text(s->cookie_name), text(s->cookie)) == BC_OK;
        s->closing = 1;
        s->result.cleanup_status = s->cookie_ready ? submit(s, LOGOUT, logout_path(s), NULL) : BC_OUTCOME_UNKNOWN;
    }
    if (!--s->refs) destroy(s);
}

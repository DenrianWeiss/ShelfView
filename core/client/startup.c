#define _POSIX_C_SOURCE 200809L
#include "bcontrol/media_offer_provider.h"
#include "internal.h"
#include "bcontrol/console_entry.h"
#include "bcontrol/ilo.h"
#include "bcontrol/zte.h"
#include <curl/curl.h>
#include <limits.h>
#include <openssl/rand.h>
#include "yyjson.h"

static void completed(bc_request *r, const bc_response *v, void *u) { (void)r; (void)v; (void)u; }
static void auth_completed(bc_redfish_auth_operation *o, const bc_redfish_auth_result *r, void *u) { (void)o; (void)r; (void)u; }
static void web_completed(bc_web_session *o, void *u) { (void)o; (void)u; }
static void graph_completed(bc_web_entry_graph *o, void *u) { (void)o; (void)u; }
static void artifact_completed(bc_jviewer_artifact *o, void *u) { (void)o; (void)u; }
static void probe_completed(bc_megarac_probe *o, const bc_megarac_probe_result *r, void *u) { (void)o; (void)r; (void)u; }
static void launch_completed(bc_huawei_launch *o, void *u) { (void)o; (void)u; }
uint64_t client_clock(void *user) { (void)user; return bc_monotonic_ms(); }
int client_cancelled(bc_console_client *s) { return s->options.cancelled && s->options.cancelled(s->options.user); }
uint32_t client_remaining(bc_console_client *s) {
    uint64_t now = bc_monotonic_ms();
    return now < s->deadline ? (uint32_t)(s->deadline-now) : 0;
}
static int ready(bc_console_client *s, uint32_t kind, void *op, bc_endpoint *endpoint, uint64_t generation) {
    (void)s;
    switch(kind) {
    case 0: return bc_redfish_auth_result_get(op) != NULL;
    case 1: return bc_web_session_result_get(op) != NULL;
    case 2: return bc_web_entry_result_get(op, endpoint, generation) != NULL;
    case 3: return bc_jviewer_artifact_result_get(op, endpoint, generation) != NULL;
    case 4: return bc_megarac_probe_result_get(op) != NULL;
    case 5: return bc_huawei_launch_result_get(op, endpoint, generation) != NULL;
    default: return 0;
    }
}
static bc_status wait_operation(bc_console_client *s, uint32_t kind, void *op, bc_endpoint *endpoint, uint64_t generation) {
    while (!ready(s,kind,op,endpoint,generation)) {
        if (client_cancelled(s)) return BC_CANCELLED;
        if (!client_remaining(s)) return BC_TIMEOUT;
        bc_status status = bc_context_poll(s->context, 10);
        if (status != BC_OK) return status;
    }
    return client_cancelled(s) ? BC_CANCELLED : client_remaining(s) ? BC_OK : BC_TIMEOUT;
}
static void redfish_completed(bc_redfish_operation *o, const bc_redfish_result *r, void *u) { (void)o; (void)r; (void)u; }
bc_status client_wait_request(bc_console_client *s, bc_request *request) {
    while (!bc_request_response(request)) {
        if (client_cancelled(s) || !client_remaining(s)) {
            bc_request_cancel(request);
            return client_cancelled(s) ? BC_CANCELLED : BC_TIMEOUT;
        }
        bc_status status = bc_context_poll(s->context, 10);
        if (status != BC_OK) return status;
    }
    if (client_cancelled(s)) return BC_CANCELLED;
    if (!client_remaining(s)) return BC_TIMEOUT;
    const bc_response *response = bc_request_response(request);
    if (response->status != BC_OK) return response->status;
    return response->http_status >= 200 && response->http_status < 300 ? BC_OK : BC_HTTP_ERROR;
}
bc_status client_wait_redfish(bc_console_client *s, bc_redfish_operation *op) {
    while (!bc_redfish_result_get(op)) {
        if (client_cancelled(s) || !client_remaining(s)) {
            bc_redfish_cancel(op);
            return client_cancelled(s) ? BC_CANCELLED : BC_TIMEOUT;
        }
        bc_status status = bc_context_poll(s->context, 10);
        if (status != BC_OK) return status;
    }
    if (client_cancelled(s)) return BC_CANCELLED;
    if (!client_remaining(s)) return BC_TIMEOUT;
    return bc_redfish_result_get(op)->status;
}
char *client_copy(bc_string value, uint32_t limit) {
    if ((value.length && !value.data) || value.length > limit || (value.length && memchr(value.data, 0, (size_t)value.length))) return NULL;
    char *copy = malloc((size_t)value.length+1);
    if (!copy) return NULL;
    if (value.length) memcpy(copy, value.data, (size_t)value.length);
    copy[value.length] = 0; return copy;
}
bc_status client_cookie(bc_console_client *s, bc_string cookie) {
    char *copy = client_copy(cookie, 8180);
    if (!copy) return BC_LIMIT_EXCEEDED;
    if (s->cookie) { memset(s->cookie, 0, strlen(s->cookie)); free(s->cookie); }
    s->cookie = copy; return BC_OK;
}
bc_status client_url(bc_console_client *s, const char *scheme, uint32_t port, const char *path, char **out) {
    if (!port || port > 65535 || !path) return BC_INVALID_ARGUMENT;
    size_t capacity = strlen(s->host)+strlen(path)+strlen(scheme)+32;
    char *url = malloc(capacity);
    if (!url) return BC_NO_MEMORY;
    int bracket = strchr(s->host, ':') && s->host[0] != '[';
    snprintf(url, capacity, "%s://%s%s%s:%u%s", scheme, bracket ? "[" : "", s->host, bracket ? "]" : "", port, path);
    free(*out); *out = url; return BC_OK;
}
static bc_status endpoint_open(bc_console_client *s) {
    bc_endpoint_options o = {0}; o.struct_size = sizeof(o); o.abi_version = BC_ABI_VERSION;
    o.device_id = str("console"); o.endpoint_id = str("console"); o.origin = str(s->origin);
    o.ca_file = str(s->ca_file); o.cert_policy = s->options.cert_policy;
    o.tls_min = s->options.tls_min; o.tls_max = s->options.tls_max; o.flags = BC_ENDPOINT_COOKIE_JAR;
    return s->options.proxy ? bc_endpoint_create_proxy(s->context, &o, &s->proxy, &s->public_endpoint) : bc_endpoint_create(s->context, &o, &s->public_endpoint);
}
bc_status client_http_open(bc_console_client *s) {
    bc_status created = bc_curl_transport_create(&s->http);
    if (created != BC_OK) return created;
    CURLU *url = curl_url();
    if (!url) return BC_NO_MEMORY;
    char *scheme = NULL, *host = NULL, *port = NULL, *path = NULL, *part = NULL;
    bc_status status = BC_INVALID_ARGUMENT;
    if (curl_url_set(url, CURLUPART_URL, s->address, 0) || curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) ||
        (strcmp(scheme, "https") && strcmp(scheme, "http")) || curl_url_get(url, CURLUPART_HOST, &host, 0) ||
        curl_url_get(url, CURLUPART_PATH, &path, 0) || strcmp(path, "/")) goto done;
    if (!curl_url_get(url, CURLUPART_USER, &part, 0) || !curl_url_get(url, CURLUPART_PASSWORD, &part, 0) ||
        !curl_url_get(url, CURLUPART_QUERY, &part, 0) || !curl_url_get(url, CURLUPART_FRAGMENT, &part, 0)) goto done;
    s->host = client_copy(str(host), 255);
    if (!s->host) { status = BC_NO_MEMORY; goto done; }
    s->port = !curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) ? (uint32_t)strtoul(port, NULL, 10) : 0;
    s->origin = client_copy(str(s->address), 8192);
    if (!s->origin) { status = BC_NO_MEMORY; goto done; }
    size_t n = strlen(s->origin); if (n && s->origin[n-1] == '/') s->origin[n-1] = 0;
    bc_context_options options = {sizeof(options), BC_ABI_VERSION, s->http, 16u*1024u*1024u, 8, 0};
    status = bc_context_create(&options, &s->context);
    if (status == BC_OK) status = endpoint_open(s);
done:
    curl_free(scheme); curl_free(host); curl_free(port); curl_free(path); curl_free(part); curl_url_cleanup(url);
    return status;
}
bc_status client_redfish_get(bc_console_client *s, const char *path, bc_request **out) {
    if (++s->reads > 128 || !client_remaining(s)) return BC_TIMEOUT;
    bc_http_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = str(path); options.method = BC_HTTP_GET; options.timeout_ms = client_remaining(s);
    bc_status status = bc_http_submit(s->endpoint, &options, completed, NULL, out);
    return status == BC_OK ? client_wait_request(s, *out) : status;
}
static bc_status redfish_login(bc_console_client *s) {
    bc_redfish_login_options options = {sizeof(options), BC_ABI_VERSION, BC_REDFISH_LOGIN_AUTO,
        client_remaining(s), str(s->username), str(s->password)};
    bc_redfish_auth_operation *operation = NULL;
    bc_status status = bc_redfish_login(s->public_endpoint, &options, auth_completed, NULL, &operation);
    if (status == BC_OK) status = wait_operation(s, 0, operation, NULL, 0);
    const bc_redfish_auth_result *result = bc_redfish_auth_result_get(operation);
    if (result && result->connection) { s->redfish = result->connection; bc_redfish_connection_retain(s->redfish); s->endpoint = bc_redfish_connection_endpoint(s->redfish); }
    if (status == BC_OK) status = result ? result->status : BC_PROTOCOL_ERROR;
    if (status == BC_OK && (result->flags & BC_REDFISH_AUTH_INSPUR_LEGACY)) s->generation = 1;
    if(status==BC_AUTHENTICATION_FAILED && result)s->info.failure=(bc_console_failure){sizeof(bc_console_failure),status,BC_CONSOLE_PHASE_LOGIN,BC_CONSOLE_CAUSE_CREDENTIALS,0,result->http_status,0,BC_SERVICE_KVM,0};
    if (status != BC_OK) bc_redfish_auth_cancel(operation);
    bc_redfish_auth_release(operation);
    if (status != BC_OK && !result) s->info.cleanup_status=BC_OUTCOME_UNKNOWN;
    return status;
}
static bc_status redfish_logout(bc_console_client *s) {
    if (!s->redfish) return BC_OK;
    const bc_redfish_connection_info *connection = bc_redfish_connection_info_get(s->redfish);
    if (connection && connection->mode != BC_REDFISH_LOGIN_SESSION) {
        bc_redfish_connection_release(s->redfish); s->redfish=NULL; s->endpoint=NULL; return BC_OK;
    }
    uint32_t timeout = s->irmc ? 15000 : 3000;
    uint32_t remaining = client_remaining(s);
    if (s->generation == 1 && remaining > timeout) timeout = remaining < 15000 ? remaining : 15000;
    bc_redfish_auth_operation *operation = NULL;
    bc_status status = bc_redfish_logout(s->redfish, timeout, auth_completed, NULL, &operation);
    if (status == BC_OK) {
        uint64_t until = bc_monotonic_ms()+timeout;
        while (!bc_redfish_auth_result_get(operation) && bc_monotonic_ms() < until) { status = bc_context_poll(s->context, 10); if (status != BC_OK) break; }
        const bc_redfish_auth_result *result = bc_redfish_auth_result_get(operation);
        status = result ? result->status : BC_OUTCOME_UNKNOWN;
    }
    if (status != BC_OK) bc_redfish_auth_cancel(operation);
    bc_redfish_auth_release(operation); bc_redfish_connection_release(s->redfish); s->redfish = NULL; s->endpoint = NULL;
    return status;
}
static bc_status managers(bc_console_client *s, char paths[32][1025], uint32_t *count) {
    bc_redfish_collection_options options = {sizeof(options), BC_ABI_VERSION, client_remaining(s), 32};
    bc_redfish_operation *op = NULL;
    bc_status status = bc_redfish_discover_managers(s->endpoint, &options, redfish_completed, NULL, &op);
    if (status == BC_OK) status = client_wait_redfish(s, op);
    const bc_redfish_collection_info *info = bc_redfish_collection_info_get(op);
    if (status == BC_OK && (!info || info->member_count > 32)) status = BC_LIMIT_EXCEEDED;
    *count = 0;
    if (status == BC_OK) for (uint32_t i = 0; i < info->member_count; ++i) {
        if (info->members[i].length > 1024) { status = BC_LIMIT_EXCEEDED; break; }
        memcpy(paths[i], info->members[i].data, (size_t)info->members[i].length); paths[i][info->members[i].length] = 0; ++*count;
    }
    bc_redfish_release(op); return status;
}
static bc_status metadata(bc_console_client *s, bc_request **zte, int *no_match) {
    if (no_match) *no_match = 0;
    bc_request *root = NULL;
    bc_status status = client_redfish_get(s, "/redfish/v1/", &root);
    if (status != BC_OK) { bc_request_release(root); return status; }
    bc_bytes body = bc_request_response(root)->body; uint32_t generation = 0;
    status = bc_ilo_discover_generation(body.data, (uint32_t)body.length, &generation);
    int is_ilo=status==BC_OK && generation==5;
    if (status != BC_UNSUPPORTED && status != BC_OK) { bc_request_release(root); return status; }
    int is_zte = bc_zte_service_root_matches(body.data, (uint32_t)body.length);
    s->irmc = bc_irmc_service_root_matches(body);
    bc_request_release(root);
    if (s->irmc) return !is_ilo && !is_zte && !s->options.http_contract ? BC_OK : BC_UNSUPPORTED;
    char paths[32][1025]; uint32_t count = 0;
    status = managers(s, paths, &count); if (status != BC_OK) return status;
    if (is_zte && is_ilo) return BC_UNSUPPORTED;
    if (is_zte) {
        if (count != 1) return BC_UNSUPPORTED;
        char path[1060]; snprintf(path, sizeof(path), "%s/KvmService", paths[0]);
        status = client_redfish_get(s, path, zte); if (status == BC_OK) s->generation = 2;
        return status;
    }
    uint32_t found = 0, downloads = 0, huawei_count = 0, candidates = 0;
    for (uint32_t i = 0; i < count; ++i) {
        bc_request *request = NULL; status = client_redfish_get(s, paths[i], &request);
        if (status != BC_OK) { bc_request_release(request); return status; }
        body = bc_request_response(request)->body;
        bc_huawei_download_action download = {0}; download.struct_size = sizeof(download);
        bc_status parsed = bc_huawei_manager_download_parse(body.data, (uint32_t)body.length, str(paths[i]), &download);
        if (parsed == BC_OK) { s->download = download; ++downloads; }
        else if (parsed != BC_UNSUPPORTED) { bc_request_release(request); return parsed; }
        bc_console_metadata_link links[32]; uint32_t written = 0;
        parsed = bc_console_manager_metadata_links(body.data, (uint32_t)body.length, str(paths[i]), links, 32, &written);
        bc_request_release(request);
        if (parsed != BC_OK && parsed != BC_UNSUPPORTED) return parsed;
        candidates += written;
        for (uint32_t j = 0; j < written; ++j) {
            request = NULL; status = client_redfish_get(s, links[j].uri, &request);
            if (status != BC_OK) { bc_request_release(request); return status; }
            body = bc_request_response(request)->body;
            if (links[j].kind == BC_CONSOLE_METADATA_ATTRIBUTES) {
                bc_service_profile profile;
                parsed = bc_idrac_kvm_discover_attributes(body.data, (uint32_t)body.length, &profile);
                if (parsed == BC_OK) { found |= 1; s->info.profile = profile; }
            } else {
                bc_huawei_kvm_resource resource = {0}; resource.struct_size = sizeof(resource);
                parsed = bc_huawei_kvm_resource_parse(body.data, (uint32_t)body.length, str(links[j].uri), &resource);
                if (parsed == BC_OK) { if (++huawei_count > 1) parsed = BC_UNSUPPORTED; else { found |= 2; s->resource = resource; } }
            }
            bc_request_release(request);
            if (parsed != BC_OK && parsed != BC_UNSUPPORTED) return parsed;
        }
    }
    if (is_ilo && !found) s->protocol=BC_CONSOLE_PROTOCOL_ILO;
    else if (is_ilo) return BC_UNSUPPORTED;
    else if (found == 1) s->protocol = BC_CONSOLE_PROTOCOL_IDRAC;
    else if (found == 2 && downloads <= 1 && huawei_count == 1) s->protocol = BC_CONSOLE_PROTOCOL_HUAWEI;
    else {
        if (no_match && !found && !downloads && !candidates) *no_match = 1;
        return BC_UNSUPPORTED;
    }
    return BC_OK;
}
static bc_status ilo_launch(bc_console_client *s) {
    uint8_t token[32]; uint32_t size = 0;
    bc_status status = bc_endpoint_copy_auth_token(s->endpoint, token, sizeof(token), &size);
    if (status == BC_OK && size != 32) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) status = bc_console_launch_from_token(BC_CONSOLE_PROTOCOL_ILO, 5, (bc_string){(const char *)token, size}, &s->launch);
    if (status == BC_OK) {
        char cookie[64]; snprintf(cookie, sizeof(cookie), "sessionKey=%.*s", (int)size, token);
        status = client_cookie(s, str(cookie)); memset(cookie, 0, sizeof(cookie));
    }
    if (status == BC_OK && s->options.service == BC_CLIENT_MEDIA) status = bc_media_offer_from_token(BC_CONSOLE_PROTOCOL_ILO, 0, (bc_string){(const char *)token,size}, &s->offer);
    memset(token, 0, sizeof(token));
    s->channels = s->options.service == BC_CLIENT_MEDIA ? 1 : 2;
    if (status == BC_OK) status = client_url(s, "wss", s->port,
        s->options.service == BC_CLIENT_MEDIA ? "/wss/vmport" : "/wss/ircport", &s->urls[0]);
    if (status == BC_OK && s->channels == 2) s->urls[1] = client_copy(str(s->urls[0]), 8192);
    return status;
}
static bc_status idrac_launch(bc_console_client *s) {
    bc_status status = redfish_logout(s); if (status != BC_OK) return status;
    s->endpoint = s->public_endpoint;
    status = bc_idrac_http_login(s->endpoint, str(s->username), str(s->password), client_remaining(s), completed, NULL, &s->login);
    if (status == BC_OK) status = client_wait_request(s, s->login);
    if (status == BC_OK) status = bc_idrac_http_login_status(s->login);
    if(status==BC_AUTHENTICATION_FAILED)s->info.failure=(bc_console_failure){sizeof(bc_console_failure),status,BC_CONSOLE_PHASE_LOGIN,BC_CONSOLE_CAUSE_CREDENTIALS,0,0,0,BC_SERVICE_KVM,BC_SERVICE_FAMILY_IDRAC};
    if (status != BC_OK) return status;
    status = client_cookie(s, bc_request_cookie_header(s->login)); if (status != BC_OK) return status;
    bc_request *request = NULL;
    status = bc_idrac_http_submit(s->endpoint, s->login, BC_IDRAC_HTTP_LAUNCH, client_remaining(s), completed, NULL, &request);
    if (status == BC_OK) status = client_wait_request(s, request);
    CURLU *url = curl_url(); char *scheme = NULL, *host = NULL, *port = NULL, *path = NULL, *query = NULL;
    bc_idrac_console_launch launch = {0}; launch.struct_size = sizeof(launch);
    if (status == BC_OK) {
        const bc_response *r = bc_request_response(request); char location[8193]; uint32_t written = 0;
        status = bc_idrac_kvm_launch_location(r->body.data, (uint32_t)r->body.length, location, sizeof(location), &written);
        if (status == BC_OK) {
            location[written] = 0;
            if (!url || curl_url_set(url, CURLUPART_URL, s->origin, 0) || curl_url_set(url, CURLUPART_URL, (const char *)location, 0) ||
                curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) || curl_url_get(url, CURLUPART_HOST, &host, 0) ||
                curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) || curl_url_get(url, CURLUPART_PATH, &path, 0) ||
                curl_url_get(url, CURLUPART_QUERY, &query, 0)) status = BC_PROTOCOL_ERROR;
        }
        memset(location, 0, sizeof(location));
    }
    if (status == BC_OK) {
        bc_idrac_launch_uri uri = {sizeof(uri), 0, str(scheme), str(host), str(path), str(query), (uint32_t)strtoul(port, NULL, 10)};
        char *extra = NULL;
        if (!curl_url_get(url, CURLUPART_USER, &extra, 0)) { uri.flags |= BC_IDRAC_LAUNCH_USERINFO; curl_free(extra); extra = NULL; }
        if (!curl_url_get(url, CURLUPART_FRAGMENT, &extra, 0)) { uri.flags |= BC_IDRAC_LAUNCH_FRAGMENT; curl_free(extra); }
        status = bc_idrac_kvm_discover_launch(&uri, str(s->host), s->port, &launch, &s->info.profile);
        if (status == BC_OK) status = bc_console_launch_from_idrac(&launch, &s->launch);
        char *key = status == BC_OK ? curl_easy_escape(NULL, launch.primary_key, 0) : NULL;
        if (status == BC_OK && !key) status = BC_NO_MEMORY;
        if (status == BC_OK) {
            char route[2048]; snprintf(route, sizeof(route), "/vnc/vconsole?vck=%s", key);
            status = client_url(s, "wss", launch.kvm_port, route, &s->urls[0]);
            snprintf(route, sizeof(route), "/vnc/vmedia?vmk=%s", key);
            if (status == BC_OK) status = client_url(s, "wss", launch.kvm_port, route, &s->media_url);
            memset(route, 0, sizeof(route));
        }
        curl_free(key);
    }
    memset(&launch, 0, sizeof(launch)); curl_free(scheme); curl_free(host); curl_free(port); curl_free(path); curl_free(query);
    curl_url_cleanup(url); bc_request_release(request); s->channels = 1;
    return status;
}
static bc_status huawei_launch(bc_console_client *s) {
    bc_request *request = NULL;
    bc_status status = client_redfish_get(s, s->resource.action_info_uri, &request);
    if (status != BC_OK) { bc_request_release(request); return status; }
    bc_bytes body = bc_request_response(request)->body;
    status = bc_huawei_launch_request_format(body.data, (uint32_t)body.length, &s->format, &s->modes);
    bc_request_release(request);
    if (status != BC_OK) return status;
    char nonce[33]; uint8_t random[16]; if (RAND_bytes(random, sizeof(random)) != 1) return BC_IO_ERROR;
    for (uint32_t i = 0; i < sizeof(random); ++i) snprintf(nonce+2*i, 3, "%02x", random[i]);
    memset(random, 0, sizeof(random));
    for (uint32_t attempt = 0; attempt < 2; ++attempt) {
        bc_huawei_launch_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
        options.contract = s->format; options.timeout_ms = client_remaining(s); options.modes = s->modes;
        options.export_uri = str(s->resource.export_uri); options.download_uri = str(s->download.uri);
        options.nonce = str(nonce); options.generation = attempt+1; options.clock_ms = client_clock;
        bc_huawei_launch *operation = NULL;
        status = attempt ? bc_huawei_launch_start_private(s->endpoint, &options, 1, launch_completed, NULL, &operation) :
            bc_huawei_launch_start(s->endpoint, &options, launch_completed, NULL, &operation);
        if (status == BC_OK) status = wait_operation(s, 5, operation, s->endpoint, attempt+1);
        const bc_huawei_launch_result *result = bc_huawei_launch_result_get(operation, s->endpoint, attempt+1);
        int eligible = 0;
        if (status == BC_OK && result) {
            status = result->status; s->info.failure = result->failure;
            if (status == BC_OK && result->descriptor) {
                s->huawei = result->descriptor->huawei; s->info.profile = result->descriptor->profile;
                status = bc_console_launch_from_huawei(&s->huawei, &s->launch);
            } else eligible = bc_huawei_launch_private_eligible(&result->failure, result->flags, s->modes, (int)attempt);
        }
        if (status != BC_OK) bc_huawei_launch_cancel(operation);
        bc_huawei_launch_release(operation);
        if (status == BC_OK || !eligible || !s->options.confirm || !client_remaining(s)) break;
        if (!s->options.confirm(s->options.user, client_remaining(s))) { status = client_cancelled(s) ? BC_CANCELLED : client_remaining(s) ? BC_CANCELLED : BC_TIMEOUT; break; }
        request = NULL; status = client_redfish_get(s, s->resource.action_info_uri, &request);
        if (status == BC_OK) { body = bc_request_response(request)->body; uint32_t format, modes;
            status = bc_huawei_launch_request_format(body.data, (uint32_t)body.length, &format, &modes);
            if (status == BC_OK && (format != s->format || modes != s->modes)) status = BC_UNSUPPORTED;
        }
        bc_request_release(request); if (status != BC_OK) break;
    }
    memset(nonce, 0, sizeof(nonce));
    if (status == BC_OK) status = client_url(s, "wss", s->huawei.port, "/websocket", &s->urls[0]);
    s->channels = 1; return status;
}
static void capture_assets(bc_console_client *s,bc_jviewer_artifact *artifact,bc_endpoint *endpoint) {
    for(uint32_t kind=1;kind<=2;++kind){
        bc_request *request=bc_jviewer_artifact_asset_request_get(artifact,endpoint,3,kind);
        const bc_response *response=bc_request_response(request);
        uint64_t limit=kind==1?65536u:16u*1024u*1024u;
        if(!response||!response->body.data||!response->body.length||response->body.length>limit)continue;
        uint8_t *bytes=malloc((size_t)response->body.length);if(!bytes)continue;
        memcpy(bytes,response->body.data,(size_t)response->body.length);
        uint8_t **target=kind==1?&s->diagnostic_startup:&s->diagnostic_archive;
        uint32_t *size=kind==1?&s->diagnostic_startup_size:&s->diagnostic_archive_size;
        if(*target){memset(*target,0,*size);free(*target);}*target=bytes;*size=(uint32_t)response->body.length;
    }
}
static bc_status artifact(bc_console_client *s, bc_endpoint *endpoint, bc_request *request) {
    bc_jviewer_artifact_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.generation = 3; options.timeout_ms = client_remaining(s); options.clock_ms = client_clock;
    bc_jviewer_artifact *operation = NULL;
    bc_status status = bc_jviewer_artifact_start(endpoint, request, &options, artifact_completed, NULL, &operation);
    if (status == BC_OK) status = wait_operation(s, 3, operation, endpoint, 3);
    if (status == BC_OK) status = bc_jviewer_artifact_resolve(operation, endpoint, 3, &s->mega, &s->info.profile);
    if (status == BC_OK && s->irmc) {
        bc_megarac_media_parameters media = {0};
        if (bc_jviewer_artifact_media_parameters(operation, endpoint, 3, &media) == BC_OK &&
            media.single_port == 1 && media.secure == 1 && media.devices && !media.token_type &&
            (media.flags & (BC_MEGARAC_MEDIA_SECURE_PRESENT | BC_MEGARAC_MEDIA_DEVICES_PRESENT)) ==
                (BC_MEGARAC_MEDIA_SECURE_PRESENT | BC_MEGARAC_MEDIA_DEVICES_PRESENT))
            s->media_parameters = media;
    } else if (status == BC_OK) {
        bc_service_profile media;
        bc_jviewer_artifact_media_resolve(operation, endpoint, 3, &media, &s->media_parameters);
    }
    capture_assets(s,operation,endpoint);
    if (status != BC_OK) bc_jviewer_artifact_cancel(operation);
    bc_jviewer_artifact_release(operation); return status;
}
static bc_status aten_resource_path(bc_console_client *s,const char *name,char *out,size_t capacity) {
    if(!*name)return BC_UNSUPPORTED;
    CURLU *url=curl_url();if(!url)return BC_NO_MEMORY;
    bc_status status=BC_UNSUPPORTED;
    char *host=NULL,*port=NULL,*scheme=NULL,*path=NULL,*extra=NULL;
    if(curl_url_set(url,CURLUPART_URL,s->origin,0))goto done;
    if(s->aten.codebase[0]) {
        char base[1027];size_t n=strlen(s->aten.codebase);
        snprintf(base,sizeof(base),"%s%s",s->aten.codebase,s->aten.codebase[n-1]=='/'?"":"/");
        if(curl_url_set(url,CURLUPART_URL,base,0))goto done;
    }
    if(curl_url_set(url,CURLUPART_URL,name,0) || curl_url_get(url,CURLUPART_HOST,&host,0) ||
        curl_url_get(url,CURLUPART_PORT,&port,CURLU_DEFAULT_PORT) || curl_url_get(url,CURLUPART_SCHEME,&scheme,0) ||
        curl_url_get(url,CURLUPART_PATH,&path,0))goto done;
    if(!curl_url_get(url,CURLUPART_USER,&extra,0) || !curl_url_get(url,CURLUPART_PASSWORD,&extra,0) ||
        !curl_url_get(url,CURLUPART_QUERY,&extra,0) || !curl_url_get(url,CURLUPART_FRAGMENT,&extra,0))goto done;
    if(strcmp(host,s->host) || (strcmp(scheme,"http") && strcmp(scheme,"https")))goto done;
    /* Keep the authenticated endpoint, including HTTPS when old JNLP advertises HTTP. */
    uint32_t resource_port=(uint32_t)strtoul(port,NULL,10);
    if(resource_port!=s->port && !(strstr(s->origin,"https://")==s->origin && !strcmp(scheme,"http") && resource_port==80))goto done;
    if(!*path || strlen(path)+9>=capacity) {status=BC_LIMIT_EXCEEDED;goto done;}
    strcpy(out,path);status=BC_OK;
done:
    curl_free(host);curl_free(port);curl_free(scheme);curl_free(path);curl_free(extra);curl_url_cleanup(url);return status;
}
static bc_status aten_resource(bc_console_client *s,const char *name,bc_request **out) {
    char plain[2049],path[2057];bc_status resolved=aten_resource_path(s,name,plain,sizeof(plain));
    if(resolved!=BC_OK)return resolved;
    snprintf(path,sizeof(path),"%s%s",plain,s->aten.pack_enabled?".pack.gz":"");
    bc_status status=client_redfish_get(s,path,out);
    const bc_response *response=*out?bc_request_response(*out):NULL;
    if(status==BC_HTTP_ERROR && response && (response->http_status==404 || response->http_status==406) && s->aten.pack_enabled) {
        bc_request_release(*out);*out=NULL;snprintf(path,sizeof(path),"%s",plain);
        status=client_redfish_get(s,path,out);
    }
    return status;
}
bc_status client_aten_identity(bc_console_client *s,const bc_aten_launch *launch) {
    bc_request *request=NULL;bc_status status=aten_resource(s,launch->jar_path,&request);
    const bc_response *response=request?bc_request_response(request):NULL;
    if(status==BC_OK)status=response && response->body.length<=16u*1024u*1024u?
        bc_aten_identity_extract(response->body.data,(uint32_t)response->body.length,&s->aten_identity):BC_LIMIT_EXCEEDED;
    bc_request_release(request);return status;
}
static bc_status aten_media_layout(bc_console_client *s) {
    bc_request *request=NULL;bc_status status=aten_resource(s,s->aten.native_path,&request);
    const bc_response *response=request?bc_request_response(request):NULL;
    if(status==BC_OK)status=response && response->body.length<=16u*1024u*1024u?
        bc_aten_native_jar_media_layout(response->body.data,(uint32_t)response->body.length,&s->aten.media_layout):BC_LIMIT_EXCEEDED;
    bc_request_release(request);return status;
}
bc_status client_aten_media_offer(bc_console_client *s) {
    const bc_aten_launch *launch = &s->aten;
    uint32_t port = launch->tls ? launch->media_tls_port : launch->media_port;
    if (!launch->media_enabled || !port || !launch->native_path[0]) return BC_UNSUPPORTED;
    bc_status status = aten_media_layout(s);
    if (status != BC_OK) return status;
    uint32_t layout = launch->media_layout;
    if (layout == BC_SERVICE_ATEN_MEDIA_CD_3_HMAC && (!launch->tls || !s->aten_peer[0])) return BC_UNSUPPORTED;
    if (launch->tls && !s->aten_peer[0])
        status = client_aten_identity(s, launch);
    if (status != BC_OK) return status;
    bc_aten_media_ticket ticket = {*launch, layout};
    bc_media_offer_info offer = {sizeof(offer), BC_MEDIA_OFFER_READY, port};
    status = bc_media_offer_create(BC_MEDIA_OFFER_ATEN, &offer, &ticket, sizeof(ticket), &s->offer);
    OPENSSL_cleanse(&ticket, sizeof(ticket));
    if (status == BC_OK) status = client_url(s, "tcp", port, "", &s->urls[0]);
    if (status == BC_OK)
        s->info.profile = (bc_service_profile){sizeof(bc_service_profile), BC_SERVICE_LOCAL_MEDIA,
            BC_SERVICE_FAMILY_ATEN, layout, BC_SERVICE_EVIDENCE_DESCRIPTOR};
    return status;
}
bc_status client_aten_mouse_layout(bc_console_client *s) {
    if(!s->aten.native_path[0])return BC_OK;
    bc_request *request=NULL;bc_status status=aten_resource(s,s->aten.native_path,&request);
    const bc_response *response=request?bc_request_response(request):NULL;
    if(status==BC_OK) {
        status=response && response->body.length<=16u*1024u*1024u?
            bc_aten_native_jar_mouse_bytes(response->body.data,(uint32_t)response->body.length,&s->aten.mouse_bytes):BC_LIMIT_EXCEEDED;
        if(status==BC_OK) {
            bc_status cipher=bc_aten_native_jar_mouse_cipher(response->body.data,(uint32_t)response->body.length,&s->aten.mouse_cipher);
            if(cipher!=BC_UNSUPPORTED)status=cipher;
        }
        if(status==BC_UNSUPPORTED)status=BC_OK;
    }
    bc_request_release(request);return status;
}

bc_status client_web_login(bc_console_client *s, uint32_t *kind) {
    bc_web_entry_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.generation = 1; options.timeout_ms = client_remaining(s); options.max_requests = 32; options.max_depth = 8;
    options.max_bytes = 8u*1024u*1024u; options.clock_ms = client_clock;
    bc_web_entry_graph *graph = NULL;
    bc_status status = bc_web_entry_start(s->public_endpoint, &options, graph_completed, NULL, &graph);
    if (status == BC_OK) status = wait_operation(s, 2, graph, s->public_endpoint, 1);
    const bc_web_entry_result *result = bc_web_entry_result_get(graph, s->public_endpoint, 1);
    if (status == BC_OK) status = result ? result->status : BC_PROTOCOL_ERROR;
    uint32_t login_kind = result && status == BC_OK ? result->hint.kind : 0;
    bc_web_login_contract *contract = NULL;
    if (status == BC_OK) status = bc_web_login_contract_from_graph(graph, s->public_endpoint, 1, &contract);
    if (status != BC_OK) bc_web_entry_cancel(graph);
    if (status != BC_OK && bc_console_entry_can_select_manually(status, 0)) s->info.flags |= BC_CLIENT_HTTP_CHOICE;
    if (status == BC_OK) {
        uint32_t value = 0; char identifier[9]; if (RAND_bytes((unsigned char *)&value, sizeof(value)) != 1) status = BC_IO_ERROR;
        snprintf(identifier, sizeof(identifier), "%08u", value%100000000u);
        bc_web_session_options login = {sizeof(login), BC_ABI_VERSION, client_remaining(s), str(s->username), str(s->password), str(identifier), client_clock, NULL};

        if (status == BC_OK) status = bc_web_session_start(contract, &login, web_completed, NULL, &s->web);
        if (status == BC_OK) status = wait_operation(s, 1, s->web, NULL, 0);
        const bc_web_session_result *authenticated = bc_web_session_result_get(s->web);
        if (status == BC_OK) status = authenticated ? authenticated->status : BC_PROTOCOL_ERROR;
        if(status==BC_AUTHENTICATION_FAILED && authenticated && authenticated->http_status>=200 && authenticated->http_status<300)s->info.failure=(bc_console_failure){sizeof(bc_console_failure),status,BC_CONSOLE_PHASE_LOGIN,BC_CONSOLE_CAUSE_CREDENTIALS,0,authenticated->http_status,0,BC_SERVICE_KVM,0};
        if (status != BC_OK) bc_web_session_cancel(s->web);
    }
    bc_web_login_contract_release(contract); bc_web_entry_release(graph);
    if (status != BC_OK) return status;
    s->endpoint = bc_web_session_endpoint(s->web);
    *kind = login_kind;
    return BC_OK;
}

static bc_status web_launch(bc_console_client *s) {
    uint32_t login_kind;
    bc_status status = client_web_login(s, &login_kind);
    if (status != BC_OK) return status;
    if (login_kind == BC_WEB_LOGIN_ATEN_CGI) {
        int matched;
        status = client_supermicro_launch(s, &matched);
        if (matched) return status;
    }
    bc_web_entry_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.generation = 2; options.timeout_ms = client_remaining(s); options.max_depth = 16;
    options.max_requests = 32; options.max_bytes = 8u*1024u*1024u; options.clock_ms = client_clock;
    bc_web_entry_graph *graph = NULL;
    status = bc_web_entry_start_owned_service(s->web, &options, s->options.service == BC_CLIENT_MEDIA ? BC_SERVICE_LOCAL_MEDIA : BC_SERVICE_KVM, graph_completed, NULL, &graph);
    if (status == BC_OK) status = wait_operation(s, 2, graph, s->endpoint, 2);
    const bc_web_entry_result *result = bc_web_entry_result_get(graph, s->endpoint, 2);
    if (status == BC_OK) status = result ? result->status : BC_PROTOCOL_ERROR;
    if (status == BC_OK) {
        bc_request *request = bc_web_entry_launch_request_get(graph, s->endpoint, 2);
        bc_console_discovery *descriptor = NULL;
        status = request ? bc_console_discovery_from_request(s->endpoint, 2, request, &descriptor) : BC_UNSUPPORTED;
        const bc_console_discovery_result *discovered = bc_console_discovery_result_get(descriptor, s->endpoint, 2);
        if (status == BC_OK && discovered && discovered->format == BC_CONSOLE_DESCRIPTOR_AVOCENT && discovered->status == BC_OK) {
            s->info.profile = discovered->profile;
            status = s->options.service == BC_CLIENT_PREPARE && discovered->profile.service == BC_SERVICE_KVM ? BC_OK : BC_UNSUPPORTED;
            const bc_avocent_launch *launch = bc_console_discovery_avocent_get(descriptor, s->endpoint, 2);
            if (launch && launch->service == BC_AVOCENT_MEDIA && s->options.service == BC_CLIENT_MEDIA) {
                bc_media_offer_info offer = {sizeof(offer), BC_MEDIA_OFFER_READY, launch->port};
                status = bc_media_offer_create(BC_MEDIA_OFFER_AVOCENT, &offer, launch, sizeof(*launch), &s->offer);
                s->protocol = BC_CONSOLE_PROTOCOL_AVOCENT; s->channels = 1;
                s->info.profile.variant = BC_SERVICE_AVOCENT_MEDIA_AVMP_CD;
                if (status == BC_OK) status = client_url(s, "tcp", launch->port, "", &s->urls[0]);
            }
        } else if (status == BC_OK && discovered && discovered->format == BC_CONSOLE_DESCRIPTOR_ATEN && discovered->status == BC_OK) {
            const bc_aten_launch *launch = bc_console_discovery_aten_get(descriptor, s->endpoint, 2);
            if (!launch) status = BC_PROTOCOL_ERROR;
            else {
                s->aten = *launch; s->info.profile = discovered->profile; s->protocol = BC_CONSOLE_PROTOCOL_ATEN; s->channels = 1;
                if (s->options.service == BC_CLIENT_MEDIA) status = client_aten_media_offer(s);
                else {
                    status=client_aten_mouse_layout(s);
                    if(status==BC_OK && launch->tls)status=client_aten_identity(s,launch);
                    if(status==BC_OK)status=client_url(s,"tcp",launch->tls?launch->tls_port:launch->port,"",&s->urls[0]);
                }
            }
        } else if (status == BC_OK) status = artifact(s, s->endpoint, request);
        bc_console_discovery_release(descriptor);
        if (request) client_cookie(s, bc_request_cookie_header(request));
    }
    if (status != BC_OK) bc_web_entry_cancel(graph);
    bc_web_entry_release(graph); return status;
}
static bc_status irmc_launch(bc_console_client *s) {
    bc_request *request = NULL;
    bc_status status = client_redfish_get(s, BC_IRMC_AVR_JNLP, &request);
    if (status == BC_OK) status = artifact(s, s->endpoint, request);
    bc_request_release(request);
    if (status != BC_OK) return status;
    if (!s->mega.secure || !s->mega.single_port || s->mega.port != s->port ||
        strcmp(s->mega.host, s->host) || !s->mega.cookie[0]) return BC_UNSUPPORTED;
    if (s->mega.kind != BC_MEGARAC_KVM_JVIEWER) return BC_UNSUPPORTED;
    s->kind = BC_MEGARAC_KVM_JVIEWER_IRMC;
    s->channels = 1;
    s->protocol = BC_CONSOLE_PROTOCOL_MEGARAC;
    return client_url(s, "tls", s->port, "", &s->urls[0]);
}

static bc_status mega_launch(bc_console_client *s, bc_request *zte) {
    bc_status status = BC_OK;
    if (!s->generation && !s->options.http_contract) {
        status = web_launch(s);
        if (s->info.profile.family == BC_SERVICE_FAMILY_AVOCENT || s->info.profile.family == BC_SERVICE_FAMILY_ATEN) return status;
    }
    else {
        if (s->redfish) { status = redfish_logout(s); if (status != BC_OK) return status; }
        s->endpoint = s->public_endpoint;
        uint32_t value = 0; char identifier[9]; if (RAND_bytes((unsigned char *)&value, sizeof(value)) != 1) return BC_IO_ERROR;
        snprintf(identifier, sizeof(identifier), "%08u", value%100000000u);
        bc_megarac_probe_options options = {sizeof(options), BC_ABI_VERSION, str(s->host), str(s->username), str(s->password), client_remaining(s), str(identifier)};

        if (s->generation == 1) status = bc_inspur_kvm_probe_start(s->endpoint, &options, probe_completed, NULL, &s->probe);
        else if (s->generation == 2 && zte) { bc_bytes body = bc_request_response(zte)->body; status = bc_zte_kvm_probe_start(s->endpoint, &options, body.data, (uint32_t)body.length, probe_completed, NULL, &s->probe); }
        else if (s->generation == 3) status = bc_inspur_rpc_kvm_probe_start(s->endpoint, &options, probe_completed, NULL, &s->probe);
        else {
            bc_megarac_login_contract contract = {sizeof(contract), s->options.http_contract == 1 ? BC_MEGARAC_LOGIN_H5_SESSION : BC_MEGARAC_LOGIN_LEGACY_RPC,
                s->options.http_contract == 1 ? 0 : BC_MEGARAC_LOGIN_CLIENT_ID|BC_MEGARAC_LOGIN_TRANSPORT_TYPE};
            status = bc_megarac_probe_start_with_login_profile(s->endpoint, &options, &contract,
                s->options.preferred.struct_size ? &s->options.preferred : NULL, probe_completed, NULL, &s->probe);
        }
        if (status == BC_OK) status = wait_operation(s, 4, s->probe, NULL, 0);
        const bc_megarac_probe_result *result = bc_megarac_probe_result_get(s->probe);
        if (status == BC_OK) status = result ? result->status : BC_PROTOCOL_ERROR;
        if(status!=BC_OK){const bc_console_failure *failure=bc_megarac_probe_failure_get(s->probe);if(failure)s->info.failure=*failure;}
        if (status == BC_OK) {
            s->mega = result->info; s->kind = result->info.kind; status = client_cookie(s, result->cookie);
            const bc_service_profile *profile = bc_megarac_probe_profile_get(s->probe); if (profile) s->info.profile = *profile;
            bc_megarac_probe_media_parameters(s->probe, &s->media_parameters);
            s->keyboard_mode = bc_megarac_probe_keyboard_mode(s->probe);
            if (!s->info.profile.variant) {
                bc_request *request = bc_megarac_probe_launch_request(s->probe);
                status = request ? artifact(s, bc_megarac_probe_endpoint(s->probe), request) : BC_UNSUPPORTED;
                if (status == BC_UNSUPPORTED) s->info.flags |= BC_CLIENT_LAYOUT_CHOICE;
            }
        }
    }
    if (status != BC_OK) return status;
    if (s->generation == 3 && !s->mega.single_port && s->info.profile.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195) {
        if (!s->mega.cookie[0]) return BC_PROTOCOL_ERROR;
        s->kind = BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION;
    }
    if (!s->kind) s->kind = s->info.profile.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195 ? BC_MEGARAC_KVM_JVIEWER_195 :
        s->info.profile.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_373 ? BC_MEGARAC_KVM_JVIEWER :
        s->info.profile.variant == BC_SERVICE_MEGARAC_KVM_H5_373 ? BC_MEGARAC_KVM_H5VIEWER_373 : BC_MEGARAC_KVM_H5VIEWER;
    s->channels = 1; s->protocol = BC_CONSOLE_PROTOCOL_MEGARAC;
    int websocket = s->kind == BC_MEGARAC_KVM_H5VIEWER || s->kind == BC_MEGARAC_KVM_H5VIEWER_373;
    status = client_url(s, websocket ? (strncmp(s->origin,"https:",6) ? "ws" : "wss") : (s->mega.secure ? "tls" : "tcp"),
        websocket ? s->port : s->mega.port, websocket ? "/kvm" : "", &s->urls[0]);
    return status;
}
bc_status client_startup(bc_console_client *s) {
    if (s->options.http_contract && s->options.http_contract != 3) return mega_launch(s, NULL);
    bc_redfish_options options = {sizeof(options), BC_ABI_VERSION, client_remaining(s), 32};
    bc_redfish_operation *probe = NULL;
    bc_status status = bc_redfish_probe(s->public_endpoint, &options, redfish_completed, NULL, &probe);
    if (status == BC_OK) status = client_wait_redfish(s, probe);
    uint32_t http = bc_redfish_result_get(probe) ? bc_redfish_result_get(probe)->http_status : 0;
    bc_redfish_release(probe);
    if (!s->options.http_contract && s->options.service != BC_CLIENT_MEDIA && http == 302 &&
        (status == BC_HTTP_ERROR || status == BC_IO_ERROR)) {
        s->generation = 3;
        return mega_launch(s, NULL);
    }
    if (status != BC_OK) return !s->options.http_contract && bc_console_entry_can_select_manually(status,http) ? mega_launch(s, NULL) : status;
    status = redfish_login(s); if (status != BC_OK) return status;
    bc_request *zte = NULL;
    int no_match = 0;
    if (!s->generation) status = metadata(s, &zte, &no_match);
    if (status == BC_UNSUPPORTED && no_match && !s->options.http_contract) {
        status = redfish_logout(s);
        if (status == BC_OK && client_cancelled(s)) status = BC_CANCELLED;
        if (status == BC_OK && !client_remaining(s)) status = BC_TIMEOUT;
        if (status == BC_OK) status = mega_launch(s, NULL);
        bc_request_release(zte);
        return status;
    }
    if (status == BC_OK && s->options.service==BC_CLIENT_MEDIA && (s->generation || (s->protocol!=BC_CONSOLE_PROTOCOL_ILO && s->protocol!=BC_CONSOLE_PROTOCOL_IDRAC))) status=BC_UNSUPPORTED;
    if (status == BC_OK) {
        if (s->irmc) status = irmc_launch(s);
        else if (s->generation) status = mega_launch(s, zte);
        else if (s->protocol == BC_CONSOLE_PROTOCOL_ILO) status = ilo_launch(s);
        else if (s->protocol == BC_CONSOLE_PROTOCOL_IDRAC) status = idrac_launch(s);
        else if (s->protocol == BC_CONSOLE_PROTOCOL_HUAWEI) status = huawei_launch(s);
        else status = BC_UNSUPPORTED;
    }
    bc_request_release(zte); return status;
}
bc_status client_http_close(bc_console_client *s) {
    bc_status status = redfish_logout(s);
    uint64_t saved = s->deadline; s->deadline = bc_monotonic_ms()+3000;
    if (s->login && bc_request_csrf_token(s->login).length) {
        bc_request *request = NULL;
        bc_status result = bc_idrac_http_submit(s->endpoint, s->login, BC_IDRAC_HTTP_LOGOUT, 3000, completed, NULL, &request);
        if (result == BC_OK) { while (!bc_request_response(request) && client_remaining(s)) bc_context_poll(s->context,10); const bc_response *response = bc_request_response(request);
            result = response ? response->status : BC_OUTCOME_UNKNOWN;
            if (result == BC_OK && (response->http_status < 200 || response->http_status >= 300)) result = BC_HTTP_ERROR; }
        if (result != BC_OK) status = result;
        if (result != BC_OK) bc_request_cancel(request);
        bc_request_release(request);
    }
    if (s->probe) {
        bc_status result = bc_megarac_probe_logout(s->probe, probe_completed, NULL);
        if (result == BC_OK) { while (!bc_megarac_probe_result_get(s->probe) && client_remaining(s)) bc_context_poll(s->context,10); const bc_megarac_probe_result *r=bc_megarac_probe_result_get(s->probe); result = r ? r->cleanup_status : BC_OUTCOME_UNKNOWN; }
        if (result != BC_OK) status = result;
    }
    if (s->web && bc_web_session_endpoint(s->web)) {
        bc_status result = bc_web_session_close(s->web, web_completed, NULL);
        if (result == BC_OK) { while (!bc_web_session_result_get(s->web) && client_remaining(s)) bc_context_poll(s->context,10); const bc_web_session_result *r=bc_web_session_result_get(s->web); result=r ? r->cleanup_status : BC_OUTCOME_UNKNOWN; }
        if (result != BC_OK) status = result;
    }
    s->deadline = saved; return status;
}

bc_status bc_console_client_choices(bc_console_client_choice *choices, uint32_t capacity, uint32_t *count) {
    if(!count)return BC_INVALID_ARGUMENT;*count=2;
    if(!choices||capacity<2)return BC_LIMIT_EXCEEDED;
    memset(choices,0,2*sizeof(*choices));
    choices[0].id=BC_SERVICE_MEGARAC_KVM_JVIEWER_195;
    choices[1].id=BC_SERVICE_MEGARAC_KVM_JVIEWER_373;
    for(uint32_t i=0;i<2;++i)choices[i].profile=(bc_service_profile){sizeof(bc_service_profile),BC_SERVICE_KVM,BC_SERVICE_FAMILY_MEGARAC,choices[i].id,BC_SERVICE_EVIDENCE_MANUAL};
    snprintf(choices[0].title,sizeof(choices[0].title),"MegaRAC JViewer 195");
    snprintf(choices[1].title,sizeof(choices[1].title),"MegaRAC JViewer 373");return BC_OK;
}
bc_status bc_console_client_detect_media(bc_context *context, bc_endpoint *endpoint, uint32_t timeout, bc_detection_result *out) {
    if(!context||!endpoint||!out||out->struct_size!=sizeof(*out)||!timeout||timeout>INT32_MAX)return BC_INVALID_ARGUMENT;
    bc_console_client s={0};s.context=context;s.endpoint=endpoint;s.deadline=bc_monotonic_ms()+timeout;
    bc_request *zte=NULL;bc_status status=metadata(&s,&zte,NULL);bc_request_release(zte);
    uint32_t evidence=0;
    if(status==BC_OK){if(s.protocol==BC_CONSOLE_PROTOCOL_IDRAC||s.protocol==BC_CONSOLE_PROTOCOL_ILO)evidence=BC_DETECTION_DESCRIPTOR;else status=BC_UNSUPPORTED;}
    bc_status result=bc_detection_result_set(out,BC_FEATURE_LOCAL_MEDIA,evidence,status,BC_OK);
    return result==BC_OK?BC_OK:result;
}

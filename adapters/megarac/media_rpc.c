#define _POSIX_C_SOURCE 200809L
#include "../../core/client/internal.h"
#include "rpc.h"
#include "../web_login/internal.h"
#include <curl/curl.h>
#include <stdio.h>
#include "yyjson.h"

#define CD_TYPE 1u

static void completed(bc_request *request, const bc_response *response, void *user) {
    (void)request; (void)response; (void)user;
}

static bc_status rpc(bc_console_client *client, const char *path, const char *body,
    const char *assignment, yyjson_doc **out) {
    *out = NULL;
    if (!client->closing && client_cancelled(client)) return BC_CANCELLED;
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = str(path); options.timeout_ms = client_remaining(client);
    if (!options.timeout_ms) return BC_TIMEOUT;
    if (body) {
        options.method = BC_HTTP_POST;
        options.content_type = str("application/x-www-form-urlencoded");
        options.body = (bc_bytes){(const uint8_t *)body, strlen(body)};
    }
    bc_request *request = NULL;
    bc_status status = bc_web_session_submit(client->web, &options, completed, NULL, &request);
    if (status != BC_OK) return status;
    status = client_wait_request(client, request);
    const bc_response *response = bc_request_response(request);
    if (status == BC_OK || (response && response->http_status == 200 &&
        (response->flags & BC_RESPONSE_EARLY_EOF) && (status == BC_IO_ERROR || status == BC_OUTCOME_UNKNOWN))) {
        bc_bytes data = bc_megarac_rpc_payload(response->body, assignment);
        if (data.length) *out = yyjson_read((const char *)data.data, (size_t)data.length,
            YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_UNQUOTED_KEY | YYJSON_READ_ALLOW_TRAILING_COMMAS);
        yyjson_val *code = yyjson_obj_get(yyjson_doc_get_root(*out), "HAPI_STATUS");
        if (!yyjson_is_int(code)) status = body ? BC_OUTCOME_UNKNOWN : BC_PROTOCOL_ERROR;
        else status = yyjson_get_sint(code) == 0 ? BC_OK : BC_REDFISH_ERROR;
    } else if (response && (response->http_status == 401 || response->http_status == 403)) {
        status = BC_AUTHENTICATION_FAILED;
    } else if (body) status = BC_OUTCOME_UNKNOWN;
    bc_request_release(request);
    return status;
}

static int byte_field(yyjson_val *record, const char *key, uint32_t *out) {
    yyjson_val *v = yyjson_obj_get(record, key);
    if (!yyjson_is_int(v) || yyjson_get_sint(v) < 0 || yyjson_get_sint(v) > 255) return 0;
    *out = (uint32_t)yyjson_get_sint(v);
    return 1;
}

bc_status client_rpc_media_confirm_removed(bc_console_client *client) {
    if (client->rpc_media_removed || !(client->info.flags & BC_CLIENT_REMOVAL_UNCONFIRMED)) return BC_OK;
    bc_kvm_transport_destroy(client->links[0]);
    client->links[0] = NULL;
    bc_status status;
    do {
        yyjson_doc *doc = NULL;
        status = rpc(client, "/rpc/getvmediacfg.asp", NULL, "WEBVAR_JSONVAR_GETVMEDIACFG", &doc);
        if (status == BC_OK) {
            yyjson_val *list = yyjson_obj_get(yyjson_doc_get_root(doc), "WEBVAR_STRUCTNAME_GETVMEDIACFG");
            uint32_t active;
            if (!byte_field(yyjson_arr_get_first(list), "V_ACTIVE_CD_SESSIONS", &active)) status = BC_PROTOCOL_ERROR;
            else if (!active) client->rpc_media_removed = 1;
            else status = BC_BUSY;
        }
        yyjson_doc_free(doc);
        if (status != BC_BUSY || !client_remaining(client)) break;
        status = bc_context_poll(client->context, 100);
    } while (status == BC_OK);
    return client->rpc_media_removed ? BC_OK : BC_OUTCOME_UNKNOWN;
}

static const char *string_field(yyjson_val *record, const char *key, size_t max) {
    yyjson_val *v = yyjson_obj_get(record, key);
    const char *s = yyjson_get_str(v);
    size_t n = yyjson_get_len(v);
    if (!s || !n || n > max || memchr(s, 0, n)) return NULL;
    for (size_t i = 0; i < n; ++i)
        if ((unsigned char)s[i] < 32 || (unsigned char)s[i] == 127 || s[i] == '\\') return NULL;
    return s;
}

typedef struct {
    char host[256], directory[1025];
} share;

static bc_status read_share(bc_console_client *client, share *out, uint32_t *flags) {
    yyjson_doc *doc = NULL;
    bc_status status = rpc(client, "/rpc/getmediacfg.asp", NULL, "WEBVAR_JSONVAR_GETMEDIACFG", &doc);
    if (status == BC_OK) {
        yyjson_val *list = yyjson_obj_get(yyjson_doc_get_root(doc), "WEBVAR_STRUCTNAME_GETMEDIACFG");
        yyjson_val *record;
        size_t i, count;
        status = yyjson_is_arr(list) ? BC_UNSUPPORTED : BC_PROTOCOL_ERROR;
        yyjson_arr_foreach(list, i, count, record) {
            uint32_t type, enabled, protocol, mounted;
            if (!byte_field(record, "RMEDIA_TYPE", &type) || type != CD_TYPE) continue;
            if (status == BC_OK) { status = BC_PROTOCOL_ERROR; break; }
            if (!byte_field(record, "RMEDIAENABLE", &enabled) || !byte_field(record, "SHR_TYPE", &protocol) ||
                !byte_field(record, "START_MOUNT", &mounted)) { status = BC_PROTOCOL_ERROR; break; }
            *flags |= BC_MEGARAC_NFS_MATCHED;
            if (enabled != 1 || protocol != 0 || !mounted) continue;
            const char *host = string_field(record, "IP_ADDR", sizeof(out->host) - 1);
            const char *path = string_field(record, "SRC_PATH", sizeof(out->directory) - 1);
            if (!host || strpbrk(host, "/?#@%") || !path || path[0] != '/') { status = BC_PROTOCOL_ERROR; break; }
            strcpy(out->host, host); strcpy(out->directory, path);
            status = BC_OK;
        }
    }
    yyjson_doc_free(doc);
    return status;
}

static int safe_path(const char *path) {
    if (!path || path[0] != '/' || strstr(path, "//") || strchr(path, '\\')) return 0;
    while (*path) {
        size_t n = strcspn(++path, "/");
        if ((n == 1 && path[0] == '.') || (n == 2 && !memcmp(path, "..", 2))) return 0;
        path += n;
    }
    return 1;
}

static int format_image_url(const char *host, const char *path, char out[2048]) {
    if (!safe_path(path)) return 0;
    char bracketed[258];
    if (strchr(host, ':') && host[0] != '[') {
        snprintf(bracketed, sizeof(bracketed), "[%s]", host);
        host = bracketed;
    }
    CURLU *uri = curl_url();
    char *url = NULL;
    int valid = uri && !curl_url_set(uri, CURLUPART_SCHEME, "nfs", CURLU_NON_SUPPORT_SCHEME) &&
        !curl_url_set(uri, CURLUPART_HOST, host, 0) &&
        !curl_url_set(uri, CURLUPART_PATH, path, CURLU_URLENCODE) &&
        !curl_url_get(uri, CURLUPART_URL, &url, 0) && strlen(url) < 2048;
    if (valid) strcpy(out, url);
    curl_free(url); curl_url_cleanup(uri);
    return valid;
}

static int image_url(const share *config, const char *name, char out[2048]) {
    if (!name || strchr(name, '/') || strchr(name, '\\') || !strcmp(name, ".") || !strcmp(name, "..")) return 0;
    char path[1540];
    size_t n = strlen(config->directory);
    int length = snprintf(path, sizeof(path), "%s%s%s", config->directory,
        config->directory[n - 1] == '/' ? "" : "/", name);
    return length >= 0 && (size_t)length < sizeof(path) && format_image_url(config->host, path, out);
}

bc_status bc_megarac_nfs_image_url(bc_string image, char *out, uint32_t capacity) {
    char input[2048], normalized[2048];
    if (!out || !capacity || !image.data || image.length < 7 || image.length >= sizeof(input) ||
        memchr(image.data, 0, (size_t)image.length) || memcmp(image.data, "nfs://", 6)) return BC_INVALID_ARGUMENT;
    memcpy(input, image.data, (size_t)image.length); input[image.length] = 0;
    if (strpbrk(input, "?#")) return BC_INVALID_ARGUMENT;
    CURLU *uri = curl_url();
    char *host = NULL, *path = NULL, *part = NULL;
    int valid = uri && !curl_url_set(uri, CURLUPART_URL, input, CURLU_NON_SUPPORT_SCHEME | CURLU_PATH_AS_IS) &&
        curl_url_get(uri, CURLUPART_USER, &part, 0) == CURLUE_NO_USER &&
        curl_url_get(uri, CURLUPART_PASSWORD, &part, 0) == CURLUE_NO_PASSWORD &&
        curl_url_get(uri, CURLUPART_PORT, &part, 0) == CURLUE_NO_PORT &&
        !curl_url_get(uri, CURLUPART_HOST, &host, 0) && strlen(host) <= 255 &&
        !curl_url_get(uri, CURLUPART_PATH, &path, CURLU_URLDECODE) && format_image_url(host, path, normalized);
    curl_free(host); curl_free(path); curl_free(part); curl_url_cleanup(uri);
    if (!valid) return BC_INVALID_ARGUMENT;
    size_t length = strlen(normalized) + 1;
    if (length > capacity) return BC_LIMIT_EXCEEDED;
    memcpy(out, normalized, length);
    return BC_OK;
}

static bc_status read_slot(bc_console_client *client, const share *config, bc_megarac_nfs_info *out, uint32_t *index) {
    yyjson_doc *doc = NULL;
    bc_status status = rpc(client, "/rpc/getrmediacfg.asp", NULL, "WEBVAR_JSONVAR_GETRMEDIACFG", &doc);
    out->flags &= ~(BC_MEGARAC_NFS_STATE_KNOWN | BC_MEGARAC_NFS_INSERTED);
    out->image[0] = 0;
    if (status == BC_OK) {
        yyjson_val *list = yyjson_obj_get(yyjson_doc_get_root(doc), "WEBVAR_STRUCTNAME_GETRMEDIACFG");
        yyjson_val *record;
        size_t i, count;
        status = yyjson_is_arr(list) ? BC_UNSUPPORTED : BC_PROTOCOL_ERROR;
        yyjson_arr_foreach(list, i, count, record) {
            uint32_t type, redirect;
            if (!byte_field(record, "IMAGE_TYPE", &type) || type != CD_TYPE) continue;
            if (status != BC_UNSUPPORTED || !byte_field(record, "IMAGE_REDIRECT", &redirect) ||
                !byte_field(record, "IMAGE_TYPE_INDEX", index)) { status = BC_PROTOCOL_ERROR; break; }
            status = redirect == 100 ? BC_BUSY : BC_OK;
            if (redirect == 1) {
                out->flags |= BC_MEGARAC_NFS_INSERTED;
                image_url(config, string_field(record, "IMAGE_NAME", 255), out->image);
            }
        }
        if (status == BC_OK) out->flags |= BC_MEGARAC_NFS_STATE_KNOWN;
    }
    yyjson_doc_free(doc);
    return status;
}

static bc_status find_image(bc_console_client *client, const share *config, const char *wanted, uint32_t *index) {
    yyjson_doc *doc = NULL;
    bc_status status = rpc(client, "/rpc/getrmediaimages.asp", NULL, "WEBVAR_JSONVAR_GETRMEDIAIMAGES", &doc);
    if (status == BC_OK) {
        yyjson_val *list = yyjson_obj_get(yyjson_doc_get_root(doc), "WEBVAR_STRUCTNAME_GETRMEDIAIMAGES");
        yyjson_val *record;
        size_t i, count;
        status = yyjson_is_arr(list) ? BC_UNSUPPORTED : BC_PROTOCOL_ERROR;
        yyjson_arr_foreach(list, i, count, record) {
            uint32_t type;
            char url[2048];
            if (!byte_field(record, "IMAGE_TYPE", &type) || type != CD_TYPE ||
                !image_url(config, string_field(record, "IMAGE_NAME", 255), url) || strcmp(wanted, url)) continue;
            if (status == BC_OK || !byte_field(record, "IMAGE_INDEX", index)) { status = BC_PROTOCOL_ERROR; break; }
            status = BC_OK;
        }
    }
    yyjson_doc_free(doc);
    return status;
}

static bc_status operate(bc_console_client *client, uint32_t action, const char *image, bc_megarac_nfs_info *out) {
    share config = {0};
    bc_status status = read_share(client, &config, &out->flags);
    if (status == BC_UNSUPPORTED && action == BC_MEGARAC_NFS_STATUS) return BC_OK;
    if (status != BC_OK) return status;
    out->flags |= BC_MEGARAC_NFS_CONFIGURED;
    uint32_t index = 0;
    status = read_slot(client, &config, out, &index);
    if (action == BC_MEGARAC_NFS_STATUS) return status == BC_BUSY ? BC_OK : status;
    if (status != BC_OK) return status;
    int insert = action == BC_MEGARAC_NFS_INSERT;
    if (out->flags & BC_MEGARAC_NFS_INSERTED) {
        if (insert) return out->image[0] && !strcmp(image, out->image) ? BC_OK : BC_BUSY;
    } else if (!insert) return BC_OK;
    if (insert) {
        status = find_image(client, &config, image, &index);
        if (status == BC_UNSUPPORTED) out->flags |= BC_MEGARAC_NFS_IMAGE_MISSING;
        if (status != BC_OK) return status;
    }

    char body[96];
    snprintf(body, sizeof(body), "MEDIA_TYPE=1&IMAGE_TYPE=1&IMAGE_INDEX=%u&START_BIT=%u", index, (unsigned)insert);
    yyjson_doc *doc = NULL;
    status = rpc(client, "/rpc/startredirection.asp", body, "WEBVAR_JSONVAR_STARTREDIRECTION", &doc);
    yyjson_doc_free(doc);
    if (status != BC_OK) return status;
    do {
        status = read_slot(client, &config, out, &index);
        if (status == BC_OK && (insert ? out->image[0] && !strcmp(image, out->image) :
            !(out->flags & BC_MEGARAC_NFS_INSERTED))) return BC_OK;
        if (status != BC_BUSY || client_cancelled(client) || !client_remaining(client)) break;
        status = bc_context_poll(client->context, 100);
    } while (status == BC_OK);
    return BC_OUTCOME_UNKNOWN;
}

bc_status bc_console_client_megarac_nfs(const bc_console_client_options *options, uint32_t action,
    bc_string image, bc_megarac_nfs_info *out) {
    if (!options || !out || out->struct_size != sizeof(*out) || action > BC_MEGARAC_NFS_EJECT) return BC_INVALID_ARGUMENT;
    *out = (bc_megarac_nfs_info){sizeof(*out), 0, BC_OK, {0}};
    char url[sizeof(out->image)] = {0};
    if (action == BC_MEGARAC_NFS_INSERT) {
        bc_status status = bc_megarac_nfs_image_url(image, url, sizeof(url));
        if (status != BC_OK) return status;
    }
    bc_console_client *client = NULL;
    bc_status status = bc_console_client_create(options, &client);
    if (status != BC_OK) return status;
    client->deadline = bc_monotonic_ms() + client->options.timeout_ms;
    status = client_http_open(client);
    uint32_t kind = 0;
    if (status == BC_OK) status = client_web_login(client, 1, &kind);
    if (status == BC_OK) status = operate(client, action, url, out);
    out->cleanup_status = bc_console_client_close(client);
    bc_console_client_destroy(client);
    return status;
}


bc_status bc_emag_nfs_image_url(bc_string image, char *out, uint32_t capacity) {
    return bc_megarac_nfs_image_url(image, out, capacity);
}
bc_status bc_console_client_emag_nfs(const bc_console_client_options *options, uint32_t action,
    bc_string image, bc_emag_nfs_info *out) {
    return bc_console_client_megarac_nfs(options, action, image, out);
}

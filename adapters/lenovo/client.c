#include "../../core/client/internal.h"
#include "bcontrol/media_offer_provider.h"
#include "yyjson.h"
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

static yyjson_val *field(yyjson_val *v, const char *key) { return yyjson_obj_get(v, key); }
static int child_path(yyjson_val *v, const char *parent, char out[1025]) {
    const char *path = yyjson_get_str(v);
    size_t length = yyjson_get_len(v), prefix = strlen(parent);
    if (!path || length <= prefix || length > 1024 || strlen(path) != length ||
        strncmp(path, parent, prefix) || path[prefix] != '/' || strstr(path, "..") ||
        strpbrk(path, "?#%\\")) return 0;
    memcpy(out, path, length + 1); return 1;
}
bc_status client_lenovo_discover(bc_console_client *s, bc_bytes body, const char *manager) {
    yyjson_doc *doc = yyjson_read((const char *)body.data, (size_t)body.length, 0);
    if (!doc) return BC_PROTOCOL_ERROR;
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *remote = field(field(field(root, "Oem"), "Lenovo"), "RemoteControl");
    bc_status status = BC_UNSUPPORTED;
    if (remote) {
        if (s->lenovo_remote[0]) status = BC_PROTOCOL_ERROR;
        else if (!child_path(field(remote, "@odata.id"), manager, s->lenovo_remote) ||
            !child_path(field(field(root, "NetworkProtocol"), "@odata.id"), manager, s->lenovo_network))
            status = BC_PROTOCOL_ERROR;
        else {
            status = BC_OK;
            s->lenovo_xcc3 = yyjson_equals_str(field(root, "Model"), "Lenovo XClarity Controller 3");
            if (s->lenovo_xcc3) {
                const char *uri = yyjson_get_str(field(field(root, "VirtualMedia"), "@odata.id"));
                if (uri && strlen(uri) <= 1024 && bc_redfish_uri_supported(str(uri)))
                    snprintf(s->lenovo_media, sizeof(s->lenovo_media), "%s", uri);
            }
        }
    }
    yyjson_doc_free(doc); return status;
}
static bc_status document(bc_console_client *s, const char *path, yyjson_doc **out) {
    bc_request *request = NULL;
    bc_status status = client_redfish_get(s, path, &request);
    if (status == BC_OK) {
        bc_bytes body = bc_request_response(request)->body;
        *out = yyjson_read((const char *)body.data, (size_t)body.length, 0);
        if (!*out) status = BC_PROTOCOL_ERROR;
    }
    bc_request_release(request); return status;
}
static bc_status xcc3_media(bc_console_client *s, uint32_t *slot) {
    if (!s->lenovo_media[0]) return BC_UNSUPPORTED;
    yyjson_doc *doc = NULL;
    bc_status status = document(s, s->lenovo_media, &doc);
    if (status != BC_OK) return status;
    yyjson_val *members = field(yyjson_doc_get_root(doc), "Members");
    if (!yyjson_is_arr(members) || yyjson_arr_size(members) > 32) { yyjson_doc_free(doc); return BC_PROTOCOL_ERROR; }
    char paths[4][1025] = {{0}};
    size_t i, count; yyjson_val *item;
    yyjson_arr_foreach(members, i, count, item) {
        char path[1025];
        if (!child_path(field(item, "@odata.id"), s->lenovo_media, path)) continue;
        const char *id = path + strlen(s->lenovo_media) + 1;
        if (strlen(id) == 7 && !strncmp(id, "Remote", 6) && id[6] >= '1' && id[6] <= '4')
            snprintf(paths[id[6] - '1'], sizeof(paths[0]), "%s", path);
    }
    yyjson_doc_free(doc);
    int busy = 0;
    for (unsigned n = 0; n < 4; ++n) {
        if (!paths[n][0]) continue;
        doc = NULL; status = document(s, paths[n], &doc);
        if (status != BC_OK) return status;
        yyjson_val *root = yyjson_doc_get_root(doc);
        int empty = yyjson_is_false(field(root, "Inserted")) &&
            yyjson_equals_str(field(root, "ConnectedVia"), "NotConnected");
        if (yyjson_is_true(field(root, "Inserted"))) busy = 1;
        yyjson_doc_free(doc);
        if (empty) {
            if (slot) { *slot = n + 1; snprintf(s->media_uri, sizeof(s->media_uri), "%s", paths[n]); }
            return BC_OK;
        }
    }
    return busy ? BC_BUSY : BC_UNSUPPORTED;
}
static void completed(bc_request *request, const bc_response *response, void *user) {
    (void)request; (void)response; (void)user;
}
static bc_status token_launch(bc_console_client *s, const char *token) {
    if (!token || strlen(token) > 1024) return BC_PROTOCOL_ERROR;
    char values[2][97] = {{0}};
    bc_status status = BC_OK;
    unsigned found = 0;
    while (*token && status == BC_OK) {
        const char *end = strchr(token, '&');
        size_t length = end ? (size_t)(end - token) : strlen(token);
        unsigned index; size_t prefix;
        if (length > 5 && !strncmp(token, "user=", 5)) { index = 0; prefix = 5; }
        else if (length > 9 && !strncmp(token, "password=", 9)) { index = 1; prefix = 9; }
        else { status = BC_PROTOCOL_ERROR; break; }
        int decoded_length = 0;
        char *decoded = curl_easy_unescape(NULL, token + prefix, (int)(length - prefix), &decoded_length);
        if (!decoded) status = BC_NO_MEMORY;
        else if ((found & (1u << index)) || decoded_length < 1 || decoded_length > 96 ||
            memchr(decoded, 0, (size_t)decoded_length)) status = BC_PROTOCOL_ERROR;
        else { memcpy(values[index], decoded, (size_t)decoded_length); found |= 1u << index; }
        if (decoded) { OPENSSL_cleanse(decoded, (size_t)decoded_length); curl_free(decoded); }
        if (!end) break;
        token = end + 1;
    }
    uint32_t client_id = 0;
    if (status == BC_OK && found != 3) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK && RAND_bytes((unsigned char *)&client_id, sizeof(client_id)) != 1) status = BC_IO_ERROR;
    if (status == BC_OK && s->options.service == BC_CLIENT_MEDIA) {
        bc_avocent_launch ticket = {0};
        ticket.struct_size = sizeof(ticket); ticket.service = BC_AVOCENT_MEDIA;
        ticket.apcp = BC_AVOCENT_APCP_WEBSOCKET_MEDIA;
        memcpy(ticket.username, values[0], sizeof(values[0])); memcpy(ticket.password, values[1], sizeof(values[1]));
        bc_media_offer_info offer = {sizeof(offer), BC_MEDIA_OFFER_READY, 0};
        status = bc_media_offer_create(BC_MEDIA_OFFER_AVOCENT, &offer, &ticket, sizeof(ticket), &s->offer);
        OPENSSL_cleanse(&ticket, sizeof(ticket));
    } else if (status == BC_OK) status = bc_console_launch_from_avocent(str(values[0]), str(values[1]), client_id, &s->launch);
    OPENSSL_cleanse(values, sizeof(values)); return status;
}
static bc_status capability(bc_console_client *s, int media, uint32_t *port_out, char action[1025], int *media_enabled) {
    yyjson_doc *doc = NULL;
    bc_status status = document(s, s->lenovo_network, &doc);
    if (status != BC_OK) return status;
    yyjson_val *kvm = field(yyjson_doc_get_root(doc), media && !s->lenovo_xcc3 ? "VirtualMedia" : "KVMIP");
    yyjson_val *vm = field(yyjson_doc_get_root(doc), "VirtualMedia");
    uint64_t vm_port = yyjson_get_uint(field(vm, "Port"));
    *media_enabled = yyjson_is_true(field(vm, "ProtocolEnabled")) && vm_port && vm_port <= 65535;
    uint64_t port = yyjson_get_uint(field(kvm, "Port"));
    if (!yyjson_is_true(field(kvm, "ProtocolEnabled")) || !port || port > 65535) status = BC_UNSUPPORTED;
    yyjson_doc_free(doc); doc = NULL;
    if (status != BC_OK) return status;
    status = document(s, s->lenovo_remote, &doc);
    if (status != BC_OK) return status;
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_true(field(root, "ServiceEnabled"))) status = BC_UNSUPPORTED;
    else if (!child_path(field(field(field(root, "Actions"), "#LenovoRemoteControlService.GetRemoteConsoleToken"), "target"), s->lenovo_remote, action)) status = BC_UNSUPPORTED;
    yyjson_doc_free(doc);
    if (status != BC_OK) return status;
    if (s->lenovo_xcc3) *media_enabled = xcc3_media(s, NULL) == BC_OK;
    *port_out = (uint32_t)port;
    return BC_OK;
}
bc_status client_lenovo_probe_media(bc_console_client *s) {
    char action[1025]; uint32_t port = 0; int enabled = 0;
    bc_status status = capability(s, 1, &port, action, &enabled);
    return status == BC_OK && s->lenovo_xcc3 ? xcc3_media(s, NULL) : status;
}
bc_status client_lenovo_launch(bc_console_client *s) {
    char action[1025]; uint32_t port = 0; int media_enabled = 0;
    int media = s->options.service == BC_CLIENT_MEDIA;
    bc_status status = capability(s, media, &port, action, &media_enabled);
    if (status != BC_OK) return status;
    if (s->lenovo_xcc3) {
        uint8_t token[4096]; uint32_t length = 0;
        status = bc_endpoint_copy_auth_token(s->endpoint, token, sizeof(token), &length);
        OPENSSL_cleanse(token, sizeof(token));
        if (status != BC_OK || !length) return status == BC_OK ? BC_UNSUPPORTED : status;
        s->protocol = BC_CONSOLE_PROTOCOL_RFB; s->channels = 1;
        if (media) {
            uint32_t slot = 0;
            status = xcc3_media(s, &slot);
            char path[64]; snprintf(path, sizeof(path), "/nbd/%u/bcontrol.iso", slot);
            if (status == BC_OK) status = client_url(s, "wss", port, path, &s->urls[0]);
            bc_media_offer_info info = {sizeof(info), BC_MEDIA_OFFER_READY, 0};
            if (status == BC_OK) status = bc_media_offer_create(BC_MEDIA_OFFER_NBD, &info, &slot, sizeof(slot), &s->offer);
        } else {
            status = bc_console_launch_from_token(BC_CONSOLE_PROTOCOL_RFB, 0, str(""), &s->launch);
            if (status == BC_OK) status = client_url(s, "wss", port, "/kvm/0/multi", &s->urls[0]);
            if (media_enabled) s->info.flags |= BC_CLIENT_LOCAL_MEDIA;
        }
        if (status == BC_OK) s->info.profile = (bc_service_profile){sizeof(bc_service_profile),
            media ? BC_SERVICE_LOCAL_MEDIA : BC_SERVICE_KVM, BC_SERVICE_FAMILY_OPENBMC,
            media ? BC_SERVICE_OPENBMC_MEDIA_NBD : BC_SERVICE_OPENBMC_KVM_RFB, BC_SERVICE_EVIDENCE_DESCRIPTOR};
        return status;
    }
    yyjson_doc *doc = NULL;
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.method = BC_HTTP_POST; options.path = str(action); options.timeout_ms = client_remaining(s);
    options.content_type = str("application/json"); options.body = (bc_bytes){(const uint8_t *)"{}", 2};
    bc_request *request = NULL;
    status = bc_http_submit(s->endpoint, &options, completed, NULL, &request);
    if (status == BC_OK) status = client_wait_request(s, request);
    if (status == BC_OK) {
        bc_bytes body = bc_request_response(request)->body;
        doc = yyjson_read((const char *)body.data, (size_t)body.length, 0);
        status = doc ? token_launch(s, yyjson_get_str(field(yyjson_doc_get_root(doc), "Token"))) : BC_PROTOCOL_ERROR;
        yyjson_doc_free(doc);
    }
    bc_request_release(request);
    if (status == BC_OK && media_enabled) s->info.flags |= BC_CLIENT_LOCAL_MEDIA;
    s->channels = media ? 1 : 2;
    if (status == BC_OK) status = client_url(s, "wss", (uint32_t)port, "/", &s->urls[0]);
    if (status == BC_OK && !media) status = client_url(s, "wss", (uint32_t)port, "/", &s->urls[1]);
    if (status == BC_OK) s->info.profile = (bc_service_profile){sizeof(bc_service_profile),
        media ? BC_SERVICE_LOCAL_MEDIA : BC_SERVICE_KVM, BC_SERVICE_FAMILY_AVOCENT,
        media ? BC_SERVICE_AVOCENT_MEDIA_WEBSOCKET_114 : BC_SERVICE_AVOCENT_KVM_WEBSOCKET_241,
        BC_SERVICE_EVIDENCE_DESCRIPTOR};
    return status;
}

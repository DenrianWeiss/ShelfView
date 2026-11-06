#define _POSIX_C_SOURCE 200809L
#include "../../core/client/internal.h"
#include "supermicro.h"
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/wire.h"
#include <openssl/crypto.h>

static void completed(bc_request *request, const bc_response *response, void *user) {
    (void)request; (void)response; (void)user;
}

static bc_status submit(bc_console_client *s, const char *path, const char *csrf,
    const char *body, const char *page, bc_request **out) {
    uint32_t remaining = client_remaining(s);
    if (client_cancelled(s)) return BC_CANCELLED;
    if (!remaining) return BC_TIMEOUT;
    char referer[8256], token[280];
    int length = snprintf(referer, sizeof(referer), "Referer: %s%s", s->origin, page);
    if (length < 0 || (size_t)length >= sizeof(referer)) return BC_LIMIT_EXCEEDED;
    bc_string headers[3] = {str(referer)};
    bc_http_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.path = str(path); options.timeout_ms = remaining;
    options.headers = headers; options.header_count = 1; options.method = BC_HTTP_GET;
    if (csrf) {
        snprintf(token, sizeof(token), "CSRF-TOKEN: %s", csrf);
        headers[1] = str(token);
        headers[2] = str("X-Requested-With: XMLHttpRequest");
        options.header_count = 3; options.method = BC_HTTP_POST;
        options.body = (bc_bytes){(const uint8_t *)body, strlen(body)};
        options.content_type = str("application/x-www-form-urlencoded");
    }
    bc_status status = bc_http_submit(s->endpoint, &options, completed, NULL, out);
    OPENSSL_cleanse(token, sizeof(token));
    return status == BC_OK ? client_wait_request(s, *out) : status;
}

static bc_status html5_launch(bc_console_client *s, bc_request *request) {
    const bc_response *response = bc_request_response(request);
    int media = s->options.service == BC_CLIENT_MEDIA;
    if (media) {
        int enabled;
        bc_status status = bc_supermicro_html5_media_enabled(response->body, &enabled);
        if (status != BC_OK) return status;
        if (!enabled) {
            s->info.failure = (bc_console_failure){sizeof(bc_console_failure), BC_UNSUPPORTED,
                BC_CONSOLE_PHASE_MEDIA, BC_CONSOLE_CAUSE_LICENSE_REQUIRED, BC_SERVICE_ATEN_MEDIA_HTML5,
                response->http_status, 0, BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_ATEN};
            return BC_UNSUPPORTED;
        }
        if (strncmp(s->origin, "https://", 8)) return BC_UNSUPPORTED;
    }
    bc_status status = bc_supermicro_console_ticket(response->body, s->aten.username);
    if (status == BC_OK) status = client_cookie(s, bc_request_cookie_header(request));
    if (status != BC_OK) return status;
    s->aten.struct_size = sizeof(s->aten);
    s->aten.mouse_bytes = 3;
    s->aten_websocket = 1;
    status = client_url(s, "wss", s->port, media ? "/vm" : "/", &s->urls[0]);
    if (status != BC_OK || !media) return status;

    bc_aten_media_ticket ticket = {s->aten, BC_SERVICE_ATEN_MEDIA_HTML5};
    memcpy(ticket.launch.password, ticket.launch.username + 15, 10);
    OPENSSL_cleanse(ticket.launch.username + 15, sizeof(ticket.launch.username) - 15);
    OPENSSL_cleanse(s->aten.username, sizeof(s->aten.username));
    bc_media_offer_info offer = {sizeof(offer), BC_MEDIA_OFFER_READY, s->port};
    status = bc_media_offer_create(BC_MEDIA_OFFER_ATEN, &offer, &ticket, sizeof(ticket), &s->offer);
    OPENSSL_cleanse(&ticket, sizeof(ticket));
    if (status == BC_OK)
        s->info.profile = (bc_service_profile){sizeof(bc_service_profile), BC_SERVICE_LOCAL_MEDIA,
            BC_SERVICE_FAMILY_ATEN, BC_SERVICE_ATEN_MEDIA_HTML5, BC_SERVICE_EVIDENCE_DESCRIPTOR};
    return status;
}

static bc_status html5_media_query(bc_console_client *s, uint8_t tag, uint8_t reply_tag,
    uint8_t *body, uint32_t length) {
    uint8_t reply[12];
    if (length > sizeof(reply) - 8) return BC_INVALID_ARGUMENT;
    bc_kvm_transport *transport = NULL;
    bc_status status = client_network_open(s, s->urls[0], "binary", &transport);
    uint8_t query[8] = {0, 0, 0, tag};
    if (status == BC_OK) status = bc_kvm_transport_send(transport, query, sizeof(query));
    uint32_t used = 0, total = 8 + length;
    while (status == BC_OK && used < total) {
        uint32_t remaining = client_remaining(s), received = 0;
        if (client_cancelled(s)) status = BC_CANCELLED;
        else if (!remaining) status = BC_TIMEOUT;
        else {
            status = bc_kvm_transport_recv(transport, reply + used, total - used, &received,
                remaining < 100 ? remaining : 100);
            if (status == BC_TIMEOUT) status = BC_OK;
            else if (status == BC_OK && !received) status = BC_PROTOCOL_ERROR;
            used += received;
            if (status == BC_OK && used >= 8 &&
                (reply[0] || reply[1] || reply[2] || (reply_tag && reply[3] != reply_tag) ||
                 bc_wire_read_le(reply + 4, 4) != length)) status = BC_PROTOCOL_ERROR;
        }
    }
    bc_kvm_transport_destroy(transport);
    if (status != BC_OK) return status;
    memcpy(body, reply + 8, length);
    return BC_OK;
}

bc_status client_supermicro_html5_media_prepare(bc_console_client *s) {
    uint8_t slots[4], port[2];
    bc_status status = html5_media_query(s, 8, 9, slots, sizeof(slots));
    if (status != BC_OK) return status;
    if (slots[1] != 255) return BC_BUSY;
    /* The stock viewer queries the port but opens the media socket on the page origin. */
    return html5_media_query(s, 10, 0, port, sizeof(port));
}

static bc_status java_launch(bc_console_client *s, bc_bytes body) {
    if (body.length > 65536) return BC_LIMIT_EXCEEDED;
    bc_status status = bc_aten_launch_parse_with_peer(body.data, (uint32_t)body.length, &s->aten, s->aten_peer);
    if (status != BC_OK) return status;
    if (strcmp(s->aten.host, s->host)) return BC_UNSUPPORTED;
    if (s->options.service == BC_CLIENT_MEDIA) return client_aten_media_offer(s);
    if (s->aten_peer[0]) {
        s->aten.mouse_bytes = 3;
    } else {
        status = client_aten_mouse_layout(s);
        if (status == BC_OK && s->aten.tls) status = client_aten_identity(s, &s->aten);
    }
    if (status != BC_OK) return status;
    return client_url(s, "tcp", s->aten.tls ? s->aten.tls_port : s->aten.port, "", &s->urls[0]);
}

static bc_status console_csrf(bc_console_client *s, int settings, char csrf[257]) {
    bc_request *request = NULL;
    const char *path = settings ? BC_SUPERMICRO_MODE_PAGE : BC_SUPERMICRO_CONSOLE_PAGE;
    bc_status status = submit(s, path, NULL, NULL, BC_SUPERMICRO_CONSOLE_PAGE, &request);
    const bc_response *response = bc_request_response(request);
    if (status == BC_HTTP_ERROR && response && response->http_status == 404) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = bc_supermicro_console_csrf(response->body, settings, csrf);
    bc_request_release(request);
    return status;
}

static bc_status console_mode(bc_console_client *s, const char *csrf, const char *page, uint32_t *mode) {
    bc_request *request = NULL;
    bc_status status = submit(s, "/cgi/ipmi.cgi", csrf, "op=GET_IKVM_INTERFACE.XML&r=%280%2C0%29", page, &request);
    uint32_t raw = 0;
    if (status == BC_OK) status = bc_supermicro_console_mode(bc_request_response(request)->body, &raw);
    if (status == BC_OK) *mode = raw ? BC_CONSOLE_MODE_HTML5 : BC_CONSOLE_MODE_JAVA;
    bc_request_release(request);
    return status;
}

bc_status client_supermicro_mode(bc_console_client *s, uint32_t expected, uint32_t target,
    bc_console_mode_info *info) {
    uint32_t *observed = &info->current;
    char csrf[257] = {0};
    bc_status status = console_csrf(s, 1, csrf);
    if (status == BC_OK) status = console_mode(s, csrf, BC_SUPERMICRO_MODE_PAGE, observed);
    if (status == BC_OK)
        info->supported_modes = BC_CONSOLE_MODE_SUPPORT_HTML5 | BC_CONSOLE_MODE_SUPPORT_JAVA;
    if (status == BC_OK && target && *observed != target) {
        if (*observed != expected) status = BC_BUSY;
        else {
            const char *body = target == BC_CONSOLE_MODE_JAVA ?
                "op=remote_console&ikvm_setting=0" : "op=remote_console&ikvm_setting=1";
            bc_request *request = NULL;
            status = submit(s, "/cgi/op.cgi", csrf, body, BC_SUPERMICRO_MODE_PAGE, &request);
            if (request) {
                bc_request_release(request);
                *observed = 0;
                bc_status readback = console_csrf(s, 1, csrf);
                if (readback == BC_OK) readback = console_mode(s, csrf, BC_SUPERMICRO_MODE_PAGE, observed);
                if (readback != BC_OK) status = BC_OUTCOME_UNKNOWN;
                else if (*observed == target) status = BC_OK;
                else if (status == BC_OK) status = BC_BUSY;
            }
        }
    }
    OPENSSL_cleanse(csrf, sizeof(csrf));
    return status;
}

bc_status client_supermicro_launch(bc_console_client *s, int *matched) {
    char csrf[257] = {0};
    bc_status status = console_csrf(s, 0, csrf);
    *matched = status != BC_UNSUPPORTED;
    uint32_t mode = 0;
    if (status == BC_OK) status = console_mode(s, csrf, BC_SUPERMICRO_CONSOLE_PAGE, &mode);
    OPENSSL_cleanse(csrf, sizeof(csrf));
    if (status != BC_OK) return status;
    bc_request *request = NULL;
    int html5 = mode == BC_CONSOLE_MODE_HTML5;
    status = submit(s, html5 ? BC_SUPERMICRO_HTML5_PAGE : BC_SUPERMICRO_JNLP, NULL, NULL,
        BC_SUPERMICRO_CONSOLE_PAGE, &request);
    if (status == BC_OK)
        status = html5 ? html5_launch(s, request) : java_launch(s, bc_request_response(request)->body);
    bc_request_release(request);
    if (status == BC_OK) {
        s->protocol = BC_CONSOLE_PROTOCOL_ATEN;
        s->channels = 1;
        if (s->options.service != BC_CLIENT_MEDIA)
            s->info.profile = (bc_service_profile){sizeof(bc_service_profile), BC_SERVICE_KVM,
                BC_SERVICE_FAMILY_ATEN, 0, BC_SERVICE_EVIDENCE_DESCRIPTOR};
    }
    return status;
}

#include "supermicro.h"
#include "../launch_xml.h"
#include "../web_login/internal.h"
#include <string.h>

typedef struct { int mode, change; char *token; } console_page;

static bc_status console_script(void *user, uint32_t kind, bc_string source) {
    if (kind != BC_WEB_LINK_INLINE || !source.length) return BC_OK;
    console_page *page = user;
    bc_status status = bc_web_login_supermicro_script(source, &page->mode, &page->change, page->token);
    return status == BC_UNSUPPORTED ? BC_OK : status;
}

bc_status bc_supermicro_console_csrf(bc_bytes body, int require_change, char token[257]) {
    memset(token, 0, 257);
    if (!body.length) return BC_UNSUPPORTED;
    if (body.length > 262144) return BC_LIMIT_EXCEEDED;
    console_page page = {.token = token};
    bc_status status = bc_web_login_html_links(body.data, (uint32_t)body.length, console_script, &page);
    if (status == BC_OK)
        status = !page.mode || (require_change && !page.change) ? BC_UNSUPPORTED :
            !token[0] ? BC_PROTOCOL_ERROR : BC_OK;
    if (status != BC_OK) memset(token, 0, 257);
    return status;
}

bc_status bc_supermicro_console_ticket(bc_bytes body, char ticket[25]) {
    memset(ticket, 0, 25);
    if (body.length > 262144) return BC_LIMIT_EXCEEDED;
    bc_status status = bc_web_login_hidden_value(body.data, (uint32_t)body.length, "entry_value", ticket, 25);
    if (status != BC_OK) return status;
    size_t length = strlen(ticket);
    if (length == 24 && strspn(ticket, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_=-") == length)
        return BC_OK;
    memset(ticket, 0, 25);
    return BC_PROTOCOL_ERROR;
}

bc_status bc_supermicro_html5_media_enabled(bc_bytes page, int *enabled) {
    if (page.length > 262144) return BC_LIMIT_EXCEEDED;
    return bc_web_login_menu_enabled(page.data, (uint32_t)page.length, "menuVM",
        "SW license is missing. Please enable DCMS license!", enabled);
}

typedef struct {
    int info, capture, found;
    uint32_t length;
    char value[12];
} mode_document;

static bc_status mode_event(void *user, enum bc_launch_xml_event kind, uint32_t depth, const char *name, const char *value) {
    mode_document *doc = user;
    if (kind == BC_XML_START) {
        if (depth == 1 && strcmp(name, "IPMI")) return BC_PROTOCOL_ERROR;
        if (depth == 2) doc->info = !strcmp(name, "IKVM_INFO");
    } else if (kind == BC_XML_ATTRIBUTE && depth == 2 && doc->info && !strcmp(name, "ikvm_interface")) {
        if (doc->found++) return BC_PROTOCOL_ERROR;
        doc->capture = 1;
    } else if (kind == BC_XML_ATTRIBUTE_VALUE && doc->capture) {
        return bc_launch_append(doc->value, &doc->length, sizeof(doc->value), value);
    } else if (kind == BC_XML_ATTRIBUTE_END) {
        doc->capture = 0;
    }
    return BC_OK;
}

bc_status bc_supermicro_console_mode(bc_bytes xml, uint32_t *mode) {
    if (xml.length > 4096) return BC_LIMIT_EXCEEDED;
    mode_document doc = {0};
    bc_status status = bc_launch_xml_parse(xml.data, (uint32_t)xml.length, mode_event, &doc);
    if (status != BC_OK) return status;
    if (!doc.found || doc.length != 1 || (doc.value[0] != '0' && doc.value[0] != '1')) return BC_UNSUPPORTED;
    *mode = (uint32_t)(doc.value[0] - '0');
    return BC_OK;
}

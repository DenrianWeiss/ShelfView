#include "internal.h"
#include <string.h>
typedef struct { const uint8_t *p; uint32_t n; } span;
static uint8_t lower(uint8_t c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; }
static int equal(span a, const char *b) {
    if (a.n != strlen(b)) return 0;
    for (uint32_t i = 0; i < a.n; ++i) if (lower(a.p[i]) != (uint8_t)b[i]) return 0;
    return 1;
}
static int same(span a, span b) {
    if (a.n != b.n) return 0;
    for (uint32_t i = 0; i < a.n; ++i) if (lower(a.p[i]) != lower(b.p[i])) return 0;
    return 1;
}
static int space(uint8_t c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f'; }
static int name(uint8_t c) { c = lower(c); return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == ':'; }
static bc_status attribute_link(bc_web_link_callback callback,void *user,uint32_t kind,span value) {
    char decoded[1025];uint32_t used=0;
    for(uint32_t i=0;i<value.n;++i) {
        uint32_t c=value.p[i];
        if(c=='&') {
            uint32_t left=value.n-i;
            if(left>=5 && (!memcmp(value.p+i,"&amp;",5) || !memcmp(value.p+i,"&AMP;",5))) {c='&';i+=4;}
            else if(left>=3 && value.p[i+1]=='#') {
                uint32_t j=i+2,base=10,n=0,digits=0;
                if(j<value.n && (value.p[j]=='x' || value.p[j]=='X')) {base=16;++j;}
                for(;j<value.n && value.p[j]!=';';++j) {
                    uint8_t digit=lower(value.p[j]);uint32_t d=digit>='0'&&digit<='9'?digit-'0':digit>='a'&&digit<='f'?digit-'a'+10:99;
                    if(d>=base || ++digits>8 || n>127/base)return BC_UNSUPPORTED;
                    n=n*base+d;
                }
                if(!digits || j==value.n || n<33 || n>126)return BC_UNSUPPORTED;
                c=n;i=j;
            }
        }
        if(used==1024)return BC_LIMIT_EXCEEDED;
        decoded[used++]=(char)c;
    }
    decoded[used]=0;return callback(user,kind,(bc_string){decoded,used});
}
static int authority_escape(const char *p, uint32_t left) {
    if (left < 3 || p[0] != '%') return 0;
    uint8_t a = lower((uint8_t)p[1]), b = lower((uint8_t)p[2]);
    return (a == '3' && b == 'a') || (a == '5' && (b == 'b' || b == 'd'));
}
static int path(span page, span relative, char out[1025]) {
    if (!page.n || page.p[0] != '/' || !relative.n || relative.n > 1024 || relative.p[0] == '#' ||
        (relative.n > 1 && relative.p[0] == '/' && relative.p[1] == '/')) return 0;
    if (relative.n == 1 && relative.p[0] == '/') { strcpy(out, "/"); return 1; }
    char combined[2049]; uint32_t used = 0;
    if (relative.p[0] != '/') {
        uint32_t end = 0;
        while (end < page.n && page.p[end] != '?') ++end;
        while (end && page.p[end - 1] != '/') --end;
        if (end > 1024) return 0;
        memcpy(combined, page.p, end); used = end;
    }
    memcpy(combined + used, relative.p, relative.n); used += relative.n;
    uint32_t output = 1; out[0] = '/';
    for (uint32_t i = 1; i <= used;) {
        uint32_t start = i;
        while (i < used && combined[i] != '/' && combined[i] != '?') {
            uint8_t c = (uint8_t)combined[i];
            if (!((name(c) && c != ':') || c == '.' || c == '~' || c == '(' || c == ')' || c == '@' || c == ':')) return 0;
            ++i;
        }
        uint32_t n = i - start;
        if (!n) return 0;
        if (n == 1 && combined[start] == '.') { }
        else if (n == 2 && combined[start] == '.' && combined[start + 1] == '.') {
            if (output == 1) return 0;
            --output; while (output > 1 && out[output - 1] != '/') --output;
        } else {
            if (output + n + 1 > 1024) return 0;
            memcpy(out + output, combined + start, n); output += n; out[output++] = '/';
        }
        if (i == used || combined[i] == '?') {
            if (output > 1) --output;
            if (i < used) {
                if (output + used - i > 1024) return 0;
                for (uint32_t j = i; j < used; ++j) {
                    uint8_t c = (uint8_t)combined[j];
                    if (!((name(c) && c != ':') || c == '.' || c == '~' || c == '?' || c == '=' || c == '&' || c == '(' || c == ')' || c == '@' || c == ':' || authority_escape(combined + j,used - j))) return 0;
                    out[output++] = (char)c;
                }
            }
            out[output] = 0; return 1;
        }
        ++i;
    }
    return 0;
}
static int text_id(span value, const char *id) { return value.n == strlen(id) && !memcmp(value.p, id, value.n); }
typedef struct {
    const char *id, *disabled_title;
    char *out;
    size_t capacity;
    int found, *menu_enabled;
} element_probe;
static bc_status scan(const uint8_t *data, uint32_t length, bc_string page_path,
    bc_string script_path, const bc_web_login_hint *hint, bc_web_link_callback callback, void *user, bc_web_login_hint *form_hint, element_probe *probe) {
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > 262144) return BC_LIMIT_EXCEEDED;
    uint32_t scripts = 0, username = 0, password = 0, tags = 0, forms = 0, fields = 0, aten_check = 0, text_password = 0;
    int in_form = 0, login_form = 0, appweb_script = 0, scripted_form = 0;
    for (uint32_t i = 0; i < length;) {
        if (!data[i]) return BC_PROTOCOL_ERROR;
        if (data[i++] != '<') continue;
        if (i + 2 < length && !memcmp(data + i, "!--", 3)) {
            i += 3;
            while (i + 2 < length && memcmp(data + i, "-->", 3)) ++i;
            if (i + 2 >= length) return BC_PROTOCOL_ERROR;
            i += 3; continue;
        }
        if (i < length && data[i] == '!') { while (i < length && data[i] != '>') ++i; if (i < length) ++i; continue; }
        if (i < length && data[i] == '/') {
            if (form_hint && i + 5 < length && equal((span){data + i + 1, 4}, "form") && (space(data[i + 5]) || data[i + 5] == '>')) {
                if (login_form) {
                    if (fields != 3 || (text_password && !aten_check) || ++forms != 1) return BC_UNSUPPORTED;
                    form_hint->struct_size = sizeof(*form_hint); form_hint->kind = (uint32_t)login_form;
                    if(aten_check)form_hint->flags |= BC_WEB_LOGIN_ATEN_BASE64;
                    strcpy(form_hint->path, login_form == BC_WEB_LOGIN_ATEN_CGI ? "/cgi/login.cgi" : "/data/login");
                }
                in_form = login_form = 0;
            }
            while (i < length && data[i] != '>') ++i; if (i < length) ++i; continue; }
        uint32_t start = i;
        while (i < length && name(data[i])) ++i;
        span tag = {data + start, i - start};
        if (!tag.n || tag.n > 32 || ++tags > 4096) return BC_PROTOCOL_ERROR;
        if (equal(tag, "base") || equal(tag, "template") || equal(tag, "svg") || equal(tag, "math") || equal(tag, "object")) return BC_UNSUPPORTED;
        if (equal(tag, "plaintext")) break;
        span action = {0}, method = {0}, field_name = {0}, onsubmit = {0}, field_value = {0}, title = {0};
        span names[32], id = {0}, type = {0}, src = {0}, href = {0}, refresh = {0}, content = {0}, classes = {0}; uint32_t attrs = 0; int disabled = 0, asynchronous = 0;
        for (;;) {
            while (i < length && space(data[i])) ++i;
            if (i >= length) return BC_PROTOCOL_ERROR;
            if (data[i] == '>') { ++i; break; }
            if (data[i] == '/' && i + 1 < length && data[i + 1] == '>') { i += 2; break; }
            start = i;
            while (i < length && name(data[i])) ++i;
            span key = {data + start, i - start}, value = {0};
            if (!key.n || attrs == 32) return BC_PROTOCOL_ERROR;
            for (uint32_t j = 0; j < attrs; ++j) {
                if (names[j].n != key.n) continue;
                int match = 1;
                for (uint32_t k = 0; k < key.n; ++k) if (lower(names[j].p[k]) != lower(key.p[k])) match = 0;
                if (match && (!probe || equal(tag, "input") || (probe->menu_enabled && equal(tag, "li"))))
                    return BC_PROTOCOL_ERROR;
            }
            names[attrs++] = key;
            while (i < length && space(data[i])) ++i;
            if (i < length && data[i] == '=') {
                ++i; while (i < length && space(data[i])) ++i;
                if (i == length) return BC_PROTOCOL_ERROR;
                uint8_t quote = data[i] == '\'' || data[i] == '"' ? data[i++] : 0;
                start = i;
                while (i < length && (quote ? data[i] != quote : !space(data[i]) && data[i] != '>')) {
                    if (!data[i] || (!quote && (data[i] == '<' || data[i] == '\'' || data[i] == '"' || data[i] == '='))) return BC_PROTOCOL_ERROR;
                    ++i;
                }
                value = (span){data + start, i - start};
                if (quote) { if (i == length) return BC_PROTOCOL_ERROR; ++i; }
            }
            if (equal(key, "value")) field_value = value;
            else if (equal(key, "onsubmit")) onsubmit = value;
            else if (equal(key, "action")) action = value;
            else if (equal(key, "method")) method = value;
            else if (equal(key, "name")) field_name = value;
            else if (equal(key, "id")) id = value;
            else if (equal(key, "type")) type = value;
            else if (equal(key, "class")) classes = value;
            else if (equal(key, "title")) title = value;
            else if (equal(key, "src")) src = value;
            else if (equal(key, "href")) href = value;
            else if (equal(key, "disabled")) disabled = 1;
            else if (equal(key, "http-equiv")) refresh = value;
            else if (equal(key, "content")) content = value;
            else if (equal(key, "async") || equal(key, "defer")) asynchronous = 1;
        }
        if (probe && text_id(id, probe->id)) {
            if (probe->found++) return BC_PROTOCOL_ERROR;
            if (probe->menu_enabled) {
                if (!equal(tag, "li")) return BC_PROTOCOL_ERROR;
                for (uint32_t at = 0; at < classes.n;) {
                    while (at < classes.n && space(classes.p[at])) ++at;
                    uint32_t begin = at;
                    while (at < classes.n && !space(classes.p[at])) ++at;
                    if (text_id((span){classes.p + begin, at - begin}, "disabled")) disabled = 1;
                }
                if (disabled && !text_id(title, probe->disabled_title)) return BC_UNSUPPORTED;
                *probe->menu_enabled = !disabled;
            } else {
                if (!equal(tag, "input") || !equal(type, "hidden") || disabled ||
                    !field_value.n || field_value.n >= probe->capacity) return BC_PROTOCOL_ERROR;
                memcpy(probe->out, field_value.p, field_value.n);
                probe->out[field_value.n] = 0;
            }
        }
        if (form_hint && equal(tag, "form")) {
            if (in_form) return BC_UNSUPPORTED;
            in_form = 1; fields = aten_check = text_password = 0;
            login_form = ((text_id(action, "/data/login") || text_id(action, "data/login")) && equal(method, "post")) ? BC_WEB_LOGIN_APPWEB_XML : 0;
            if (text_id(action, "/cgi/login.cgi") && equal(method, "post") && !onsubmit.n) login_form = BC_WEB_LOGIN_ATEN_CGI;
            if (!action.n && text_id(onsubmit, "sendLoginRequest();") && text_id(field_name, "auth") && equal(method, "post")) {
                login_form = BC_WEB_LOGIN_APPWEB_XML; scripted_form = 1;
            }
        }
        if (form_hint && login_form && equal(tag, "input")) {
            uint32_t bit = text_id(field_name, login_form == BC_WEB_LOGIN_ATEN_CGI ? "name" : "user") ? 1u :
                text_id(field_name, login_form == BC_WEB_LOGIN_ATEN_CGI ? "pwd" : "password") ? 2u : 0;
            if(login_form==BC_WEB_LOGIN_ATEN_CGI && text_id(field_name,"check")) {
                if(aten_check || disabled || !equal(type,"hidden") || !text_id(field_value,"00"))return BC_UNSUPPORTED;
                aten_check=1;
            }
            if (bit) {
                int text_pwd=login_form==BC_WEB_LOGIN_ATEN_CGI && bit==2 && equal(type,"text");
                if ((fields & bit) || disabled || (!text_pwd && !equal(type, bit == 1 ? "text" : "password"))) return BC_UNSUPPORTED;
                if(text_pwd)text_password=1;
                fields |= bit;
            }
        }
        if (hint && equal(tag, "input")) {
            if (text_id(id, hint->username_input)) { if (++username != 1 || disabled || !equal(type, "text")) return BC_UNSUPPORTED; }
            if (text_id(id, hint->password_input)) { if (++password != 1 || disabled || !equal(type, "password")) return BC_UNSUPPORTED; }
        }
        if (callback && equal(tag, "a") && href.n) {
            bc_status status = attribute_link(callback,user,BC_WEB_LINK_NAVIGATION,href);
            if (status != BC_OK) return status;
        }
        if (callback && (equal(tag, "frame") || equal(tag, "iframe")) && src.n) {
            bc_status status = attribute_link(callback,user,BC_WEB_LINK_HTML,src);
            if (status != BC_OK) return status;
        }
        if (callback && equal(tag, "meta") && equal(refresh, "refresh")) {
            uint32_t at = 0;
            while (at < content.n && space(content.p[at])) ++at;
            if (at == content.n || content.p[at++] != '0') return BC_UNSUPPORTED;
            while (at < content.n && space(content.p[at])) ++at;
            if (at == content.n || content.p[at++] != ';') return BC_UNSUPPORTED;
            while (at < content.n && space(content.p[at])) ++at;
            if (at + 3 > content.n || !equal((span){content.p + at, 3}, "url")) return BC_UNSUPPORTED;
            at += 3; while (at < content.n && space(content.p[at])) ++at;
            if (at == content.n || content.p[at++] != '=') return BC_UNSUPPORTED;
            while (at < content.n && space(content.p[at])) ++at;
            span target = {content.p + at, content.n - at};
            if (target.n > 1 && (target.p[0] == '\'' || target.p[0] == '"') && target.p[target.n - 1] == target.p[0]) { ++target.p; target.n -= 2; }
            bc_status status = attribute_link(callback,user,BC_WEB_LINK_HTML,target);
            if (status != BC_OK) return status;
        }
        if (equal(tag, "script") || equal(tag, "style") || equal(tag, "noscript") ||
            equal(tag, "textarea") || equal(tag, "title") || equal(tag, "xmp") || equal(tag, "iframe") || equal(tag, "noframes")) {
            if (equal(tag, "script") && src.n && (!type.n || equal(type, "text/javascript") || equal(type, "application/javascript"))) {
                if (callback) {
                    bc_status status = attribute_link(callback,user,BC_WEB_LINK_SCRIPT,src);
                    if (status != BC_OK) return status;
                }
                char resolved[1025];
                if (hint && path((span){(const uint8_t *)page_path.data, (uint32_t)page_path.length}, src, resolved) &&
                    script_path.length == strlen(resolved) && !memcmp(script_path.data, resolved, script_path.length)) {
                    if (asynchronous) return BC_UNSUPPORTED;
                    ++scripts;
                }
            }
            int closed = 0; uint32_t body = i;
            while (i + tag.n + 2 < length) {
                if (data[i] == '<' && data[i + 1] == '/' &&
                    same((span){data + i + 2, tag.n}, tag)) {
                    uint32_t end = i + 2 + tag.n;
                    while (end < length && space(data[end])) ++end;
                    if (end < length && data[end] == '>') {
                        if (form_hint && equal(tag, "script") && !src.n &&
                            bc_web_login_appweb_script(data + body, i - body) == BC_OK) ++appweb_script;
                        if (callback && equal(tag, "script") && !src.n && (!type.n || equal(type, "text/javascript") || equal(type, "application/javascript"))) {
                            bc_status status = callback(user, BC_WEB_LINK_INLINE, (bc_string){(const char *)data + body, i - body});
                            if (status != BC_OK) return status;
                        }
                        i = end + 1; closed = 1; break;
                    }
                }
                ++i;
            }
            if (!closed) return BC_PROTOCOL_ERROR;
        }
    }
    if (form_hint && (in_form || forms != 1 || (scripted_form && appweb_script != 1))) return BC_UNSUPPORTED;
    return !hint || (scripts == 1 && username == 1 && password == 1) ? BC_OK : BC_UNSUPPORTED;
}

int bc_web_login_resolve_path(bc_string page, bc_string relative, char out[1025]) {
    if (!page.data || page.length > 1024 || !relative.data || relative.length > 1024) return 0;
    return path((span){(const uint8_t *)page.data, (uint32_t)page.length},
        (span){(const uint8_t *)relative.data, (uint32_t)relative.length}, out);
}
bc_status bc_web_login_page_matches(const uint8_t *data, uint32_t length, bc_string page_path,
    bc_string script_path, const bc_web_login_hint *hint) {
    if (!page_path.data || !page_path.length || page_path.length > 1024 ||
        !script_path.data || !script_path.length || script_path.length > 1024 || !hint) return BC_INVALID_ARGUMENT;
    return scan(data, length, page_path, script_path, hint, NULL, NULL, NULL, NULL);
}
static bc_status validate_link(void *user, uint32_t kind, bc_string value) {
    (void)user; (void)kind; (void)value; return BC_OK;
}
bc_status bc_web_login_html_links(const uint8_t *data, uint32_t length, bc_web_link_callback callback, void *user) {
    if (!callback) return BC_INVALID_ARGUMENT;
    /* Validate the entire page before exposing any links to the scheduler. */
    bc_status status = scan(data, length, (bc_string){0}, (bc_string){0}, NULL, validate_link, NULL, NULL, NULL);
    if (status != BC_OK) return status;
    return scan(data, length, (bc_string){0}, (bc_string){0}, NULL, callback, user, NULL, NULL);
}
typedef struct { bc_string page, library, login; uint32_t order, library_at, login_at; } library_order;
static bc_status ordered_script(void *user, uint32_t kind, bc_string path) {
    library_order *order = user;
    if (kind != BC_WEB_LINK_SCRIPT) return BC_OK;
    char resolved[1025]; ++order->order;
    if (!bc_web_login_resolve_path(order->page, path, resolved)) return BC_OK;
    size_t n = strlen(resolved);
    if (n == order->library.length && !memcmp(resolved, order->library.data, n)) order->library_at = order->order;
    if (n == order->login.length && !memcmp(resolved, order->login.data, n)) order->login_at = order->order;
    return BC_OK;
}
bc_status bc_web_login_page_library_matches(const uint8_t *data, uint32_t length, bc_string page_path,
    bc_string library_path, bc_string login_path, const bc_web_login_hint *hint) {
    bc_status status = bc_web_login_page_matches(data, length, page_path, library_path, hint);
    if (status == BC_OK) status = bc_web_login_page_matches(data, length, page_path, login_path, hint);
    library_order order = {page_path, library_path, login_path, 0, 0, 0};
    if (status == BC_OK) status = bc_web_login_html_links(data, length, ordered_script, &order);
    if (status == BC_OK && (!order.library_at || !order.login_at || order.library_at >= order.login_at)) status = BC_UNSUPPORTED;
    return status;
}

bc_status bc_web_login_form_hint(const uint8_t *data, uint32_t length, bc_web_login_hint *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    bc_status status = scan(data, length, (bc_string){0}, (bc_string){0}, NULL, NULL, NULL, out, NULL);
    if (status != BC_OK) memset(out, 0, sizeof(*out));
    return status;
}

bc_status bc_web_login_hidden_value(const uint8_t *data, uint32_t length, const char *id, char *out, size_t capacity) {
    element_probe hidden = {.id = id, .out = out, .capacity = capacity};
    bc_status status = scan(data, length, (bc_string){0}, (bc_string){0}, NULL, NULL, NULL, NULL, &hidden);
    if (status == BC_OK && !hidden.found) status = BC_UNSUPPORTED;
    if (status != BC_OK) memset(out, 0, capacity);
    return status;
}

bc_status bc_web_login_menu_enabled(const uint8_t *data, uint32_t length, const char *id,
    const char *disabled_title, int *enabled) {
    *enabled = 0;
    element_probe menu = {.id = id, .disabled_title = disabled_title, .menu_enabled = enabled};
    bc_status status = scan(data, length, (bc_string){0}, (bc_string){0}, NULL, NULL, NULL, NULL, &menu);
    return status == BC_OK && !menu.found ? BC_UNSUPPORTED : status;
}

#include "internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#define TOKEN_LIMIT 65536u
#define SOURCE_LIMIT 262144u
#define IDENT 256u
#define STRING 257u
#define NUMBER 258u
#define REGEX 259u
typedef struct { const uint8_t *data; uint32_t length, kind, pair; } token;
typedef struct { token *t; uint32_t count; } script;
static int alpha(uint8_t c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$'; }
static int digit(uint8_t c) { return c >= '0' && c <= '9'; }
static int equal(const token *t, const char *s) { return t->length == strlen(s) && !memcmp(t->data, s, t->length); }
static int same(const token *a, const token *b) { return a->kind == b->kind && a->length == b->length && !memcmp(a->data, b->data, a->length); }
static int expression_start(const token *t) {
    return !t || t->kind == '(' || t->kind == '=' || t->kind == ':' || t->kind == ',' ||
        t->kind == '[' || t->kind == '!' || t->kind == '&' || t->kind == '|' ||
        (t->kind == IDENT && (equal(t, "return") || equal(t, "throw")));
}
static bc_status lex(const uint8_t *p, uint32_t n, script *s) {
    uint32_t *stack = malloc(TOKEN_LIMIT * sizeof(*stack)), depth = 0;
    if (!stack) return BC_NO_MEMORY;
    bc_status status = BC_OK;
    for (uint32_t i = 0; i < n;) {
        uint8_t c = p[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { ++i; continue; }
        if (!c || c == '`') { status = BC_UNSUPPORTED; break; }
        if ((c == '/' && i + 1 < n && p[i + 1] == '/') ||
            (c == '<' && n - i >= 4 && !memcmp(p + i, "<!--", 4))) {
            while (i < n && p[i] != '\n' && p[i] != '\r') ++i;
            continue;
        }
        if (c == '/' && i + 1 < n && p[i + 1] == '*') {
            i += 2; while (i + 1 < n && !(p[i] == '*' && p[i + 1] == '/')) ++i;
            if (i + 1 >= n) { status = BC_PROTOCOL_ERROR; break; } i += 2; continue;
        }
        if (s->count == TOKEN_LIMIT) { status = BC_LIMIT_EXCEEDED; break; }
        token *t = &s->t[s->count]; *t = (token){p + i, 1, c, UINT32_MAX};
        if (c == '\'' || c == '"') {
            uint32_t start = ++i; int escaped = 0;
            while (i < n && p[i] != c) {
                if (p[i] == '\\') { escaped = 1; if (++i == n) break; }
                if (p[i] == '\n' || p[i] == '\r' || !p[i]) break;
                ++i;
            }
            if (i == n || p[i] != c) { status = BC_PROTOCOL_ERROR; break; }
            t->data = p + start; t->length = i++ - start;
            t->kind = escaped ? REGEX : STRING;
        } else if (alpha(c)) {
            uint32_t start = i++;
            while (i < n && (alpha(p[i]) || digit(p[i]))) ++i;
            t->length = i - start; t->kind = IDENT;
        } else if (digit(c)) {
            uint32_t start = i++;
            while (i < n && (alpha(p[i]) || digit(p[i]) || p[i] == '.')) ++i;
            t->length = i - start; t->kind = NUMBER;
        } else if (c == '/' && expression_start(s->count ? t - 1 : NULL)) {
            uint32_t start = i++; int in_class = 0, closed = 0;
            while (i < n && p[i] != '\n' && p[i] != '\r') {
                if (p[i] == '\\') { if (++i == n) break; ++i; continue; }
                if (p[i] == '[') in_class = 1;
                else if (p[i] == ']') in_class = 0;
                else if (p[i] == '/' && !in_class) { ++i; closed = 1; break; }
                ++i;
            }
            if (!closed) { status = BC_UNSUPPORTED; break; }
            while (i < n && alpha(p[i])) ++i;
            t->length = i - start; t->kind = REGEX;
        } else {
            if (c < 33 || c > 126 || c == '\\') { status = BC_UNSUPPORTED; break; }
            ++i;
            if (c == '(' || c == '[' || c == '{') {
                if (depth == 256) { status = BC_LIMIT_EXCEEDED; break; }
                stack[depth++] = s->count;
            }
            else if (c == ')' || c == ']' || c == '}') {
                uint32_t expected = c == ')' ? '(' : c == ']' ? '[' : '{';
                if (!depth || s->t[stack[depth - 1]].kind != expected) { status = BC_PROTOCOL_ERROR; break; }
                uint32_t open = stack[--depth]; t->pair = open; s->t[open].pair = s->count;
            }
        }
        ++s->count;
    }
    if (status == BC_OK && depth) status = BC_PROTOCOL_ERROR;
    free(stack); return status;
}
static int seq(const script *s, uint32_t i, const char *const *words, uint32_t n) {
    if (n > s->count - i) return 0;
    for (uint32_t j = 0; j < n; ++j) {
        const token *t = s->t + i + j;
        if (!equal(t, words[j]) || (alpha((uint8_t)words[j][0]) ? t->kind != IDENT : t->kind != (uint8_t)words[j][0])) return 0;
    }
    return 1;
}
bc_status bc_web_login_supermicro_script(bc_string source, int *mode, int *change, char csrf[257]) {
    if (source.length > SOURCE_LIMIT) return BC_LIMIT_EXCEEDED;
    script s = {calloc(TOKEN_LIMIT, sizeof(token)), 0};
    if (!s.t) return BC_NO_MEMORY;
    bc_status status = lex((const uint8_t *)source.data, (uint32_t)source.length, &s);
    if (status == BC_OK) for (uint32_t i = 0; i < s.count; ++i) {
        const token *t = s.t + i;
        if (t->kind == STRING && equal(t, "op=GET_IKVM_INTERFACE.XML&r=(0,0)")) *mode = 1;
        if (t->kind == STRING && equal(t, "op=remote_console&ikvm_setting=")) *change = 1;
        if (t->kind != IDENT || !equal(t, "SmcCsrfInsert") || (i && t[-1].kind == '.')) continue;
        if (s.count - i < 7 || t[1].kind != '(' || t[2].kind != STRING || !equal(t + 2, "CSRF-TOKEN") ||
            t[3].kind != ',' || t[4].kind != STRING || t[5].kind != ')' || t[6].kind != ';' ||
            !t[4].length || t[4].length > 256 || csrf[0]) { status = BC_PROTOCOL_ERROR; break; }
        for (uint32_t j = 0; j < t[4].length; ++j) {
            uint8_t c = t[4].data[j];
            if ((!alpha(c) && !digit(c) && c != '+' && c != '/' && c != '=' && c != '-') || c == '$')
                status = BC_PROTOCOL_ERROR;
        }
        if (status != BC_OK) break;
        memcpy(csrf, t[4].data, t[4].length);
        csrf[t[4].length] = 0;
    }
    free(s.t);
    return status;
}
static int copy(char *out, uint32_t cap, const token *t) {
    if (t->kind != STRING || !t->length || t->length >= cap) return 0;
    memcpy(out, t->data, t->length); out[t->length] = 0; return 1;
}
static int callback_declared(const script *s, const token *name) {
    unsigned found = 0;
    for (uint32_t i = 0; i + 5 < s->count; ++i) {
        if (s->t[i].kind != IDENT || !equal(s->t + i, "function") || !same(s->t + i + 1, name)) continue;
        if (s->t[i + 2].kind != '(' || s->t[i + 3].kind != IDENT || s->t[i + 4].kind != ')' || s->t[i + 5].kind != '{') return 0;
        ++found;
    }
    return found == 1;
}
static int selector(const script *s, uint32_t at, uint32_t end, const token *name, char out[65]) {
    const char *const pattern[] = {"=", "$", "(", "", ")", ".", "val", "(", ")", ";"};
    unsigned found = 0;
    for (uint32_t i = at; i + 11 < end; ++i) {
        if (!same(s->t + i, name) || s->t[i + 1].kind != '=') continue;
        if (!i || s->t[i - 1].kind != IDENT || !equal(s->t + i - 1, "var")) return 0;
        for (uint32_t j = 0; j < 10; ++j) {
            if (j == 3) continue;
            const token *t = s->t + i + 1 + j;
            if (!equal(t, pattern[j]) || (alpha((uint8_t)pattern[j][0]) ? t->kind != IDENT : t->kind != (uint8_t)pattern[j][0])) return 0;
        }
        const token *id = s->t + i + 4;
        if (id->kind != STRING || id->length < 2 || id->length > 65 || id->data[0] != '#') return 0;
        token value = *id; ++value.data; --value.length;
        for (uint32_t j = 0; j < value.length; ++j) if (!alpha(value.data[j]) && !digit(value.data[j]) && value.data[j] != '-') return 0;
        if (!copy(out, 65, &value) || ++found != 1) return 0;
    }
    return found == 1;
}
/* The selected request object must have only direct add/send uses. This proves
 * a local construction relationship, not arbitrary JavaScript control flow. */
static bc_status candidate(const script *s, uint32_t begin, uint32_t end, uint32_t at, bc_web_login_hint *out) {
    const token *object = s->t + at;
    const char *const start[] = {"=", "xmit", ".", "getset", "(", "{"};
    if (object->kind != IDENT || !at || s->t[at - 1].kind != IDENT || !equal(s->t + at - 1, "var") || !seq(s, at + 1, start, 6)) return BC_UNSUPPORTED;
    uint32_t close = s->t[at + 6].pair;
    if (close == UINT32_MAX || close + 2 >= end || s->t[close + 1].kind != ')' || s->t[close + 2].kind != ';') return BC_UNSUPPORTED;
    uint32_t keys = 0; const token *callback = NULL;
    for (uint32_t i = at + 7; i < close;) {
        if (i + 2 >= close || s->t[i + 1].kind != ':') return BC_UNSUPPORTED;
        const token *key = s->t + i, *value = s->t + i + 2; unsigned bit = 0;
        if (equal(key, "url")) {
            bit = 1;
            if (value->kind != STRING || !equal(value, "/rpc/WEBSES/create.asp") || !copy(out->path, sizeof(out->path), value)) return BC_UNSUPPORTED;
        } else if (equal(key, "onrcv")) { bit = 2; if (value->kind != IDENT) return BC_UNSUPPORTED; callback = value; }
        else if (equal(key, "status")) { bit = 4; if (value->kind != STRING || value->length) return BC_UNSUPPORTED; }
        else if (equal(key, "timeout")) { bit = 8; if (value->kind != NUMBER) return BC_UNSUPPORTED; }
        else return BC_UNSUPPORTED;
        if (keys & bit) return BC_PROTOCOL_ERROR;
        keys |= bit; i += 3;
        if (i < close && s->t[i++].kind != ',') return BC_UNSUPPORTED;
    }
    if ((keys & 3) != 3 || !callback || !callback_declared(s, callback)) return BC_UNSUPPORTED;
    unsigned fields = 0, types = 0, sends = 0; const token *user = NULL, *password = NULL, *client = NULL;
    for (uint32_t i = begin; i < end; ++i) {
        if (!same(s->t + i, object)) continue;
        if (i == at) continue;
        if (i <= close + 2 || i + 4 >= end || s->t[i + 1].kind != '.' || s->t[i + 2].kind != IDENT || s->t[i + 3].kind != '(') return BC_UNSUPPORTED;
        if (equal(s->t + i + 2, "send")) {
            if (i + 5 >= end || s->t[i + 4].kind != ')' || s->t[i + 5].kind != ';' || ++sends != 1) return BC_UNSUPPORTED;
            /* No further field mutations after send. */
            for (uint32_t j = i + 6; j < end; ++j) if (same(s->t + j, object)) return BC_UNSUPPORTED;
            continue;
        }
        if (!equal(s->t + i + 2, "add") || i + 8 >= end || s->t[i + 4].kind != STRING ||
            s->t[i + 5].kind != ',' || s->t[i + 7].kind != ')' || s->t[i + 8].kind != ';' || sends) return BC_UNSUPPORTED;
        const token *key = s->t + i + 4, *value = s->t + i + 6; unsigned bit = 0;
        if (equal(key, "WEBVAR_USERNAME")) { bit = 1; user = value; }
        else if (equal(key, "WEBVAR_PASSWORD")) { bit = 2; password = value; }
        else if (equal(key, "WEBVAR_IPADDR")) { bit = 4; client = value; }
        else if (equal(key, "WEBVAR_TYPE")) {
            if (value->kind != STRING) return BC_UNSUPPORTED;
            if (equal(value, "Https")) bit = 8;
            else if (equal(value, "Http")) bit = 16;
            else return BC_UNSUPPORTED;
            ++types;
        } else return BC_UNSUPPORTED;
        if (fields & bit) return BC_UNSUPPORTED;
        fields |= bit;
    }
    if ((fields & 3) != 3 || !sends || !user || !password || user->kind != IDENT || password->kind != IDENT || same(user, password)) return BC_UNSUPPORTED;
    if (!selector(s, begin, at, user, out->username_input) || !selector(s, begin, at, password, out->password_input)) return BC_UNSUPPORTED;
    /* Reject assignment/update or aliases of the credential locals after their
     * getter. Passing them anywhere except the selected add is unknown. */
    for (uint32_t i = begin; i < end; ++i) {
        if (!same(s->t + i, user) && !same(s->t + i, password)) continue;
        if (i < at && i + 1 < end && s->t[i + 1].kind == '=') continue;
        if (i < 6 || !same(s->t + i - 6, object) || !equal(s->t + i - 4, "add") || s->t[i - 1].kind != ',') return BC_UNSUPPORTED;
    }
    if (client) {
        if (client->kind != IDENT || !(fields & 8) || !(fields & 16) || types != 2) return BC_UNSUPPORTED;
        out->flags = BC_WEB_LOGIN_CLIENT_ID | BC_WEB_LOGIN_TRANSPORT_TYPE;
    } else if (types) return BC_UNSUPPORTED;
    out->struct_size = sizeof(*out); out->kind = BC_WEB_LOGIN_LEGACY_RPC;
    return BC_OK;
}
bc_status bc_web_login_script_hint(const uint8_t *data, uint32_t length, bc_web_login_hint *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > SOURCE_LIMIT) return BC_LIMIT_EXCEEDED;
    script s = {calloc(TOKEN_LIMIT, sizeof(token)), 0};
    if (!s.t) return BC_NO_MEMORY;
    bc_status status = lex(data, length, &s); unsigned found = 0, candidates = 0;
    bc_web_login_hint selected = {0};
    if (status == BC_OK) for (uint32_t i = 0; i + 4 < s.count; ++i) {
        if (s.t[i].kind != IDENT || !equal(s.t + i, "function") || s.t[i + 1].kind != IDENT ||
            s.t[i + 2].kind != '(' || s.t[i + 3].kind != ')' || s.t[i + 4].kind != '{') continue;
        uint32_t end = s.t[i + 4].pair;
        for (uint32_t j = i + 5; j + 6 < end; ++j) {
            const char *const call[] = {"=", "xmit", ".", "getset", "(", "{"};
            if (!seq(&s, j + 1, call, 6)) continue;
            if (++candidates > 256) { status = BC_LIMIT_EXCEEDED; break; }
            bc_web_login_hint hint = {0};
            bc_status parsed = candidate(&s, i + 5, end, j, &hint);
            if (parsed != BC_OK) {
                uint32_t object_end = s.t[j + 6].pair;
                int login_url = 0;
                for (uint32_t k = j + 7; k + 2 < object_end; ++k)
                    if (equal(s.t + k, "url") && s.t[k + 1].kind == ':' &&
                        s.t[k + 2].kind == STRING && equal(s.t + k + 2, "/rpc/WEBSES/create.asp")) login_url = 1;
                if (login_url) { status = parsed; break; }
                continue;
            }
            if (++found != 1) { status = BC_UNSUPPORTED; break; }
            selected = hint;
        }
        if (status != BC_OK) break;
    }
    free(s.t);
    if (status == BC_OK && found == 1) *out = selected;
    else if (status == BC_OK) status = BC_UNSUPPORTED;
    return status;
}

static int browser_name(const token *t) {
    return equal(t, "window") || equal(t, "top") || equal(t, "location");
}
static int authority_redirect(const script *s, uint32_t sink, bc_string origin, char out[1025]) {
    if (!origin.data || origin.length <= 8 || memcmp(origin.data, "https://", 8)) return 0;
    if (sink < 39 || sink + 7 >= s->count) return 0;
    uint32_t f = sink - 39;
    do {
        if (sink != f + 39 || !equal(s->t + f,"function") || s->t[f + 1].kind != IDENT || browser_name(s->t + f + 1) ||
            s->t[f + 2].kind != '(' || s->t[f + 3].kind != ')' || s->t[f + 4].kind != '{' || s->t[f + 4].pair <= f + 46) continue;
        const char *const split[] = {"=","window",".","location",".","href",".","split","("};
        const char *const guard[] = {".","length",")","{","var"};
        const char *const target[] = {"window",".","location",".","href","="};
        const token *parts = s->t + f + 6, *destination = s->t + f + 27;
        if (!equal(s->t + f + 5,"var") || parts->kind != IDENT || browser_name(parts) ||
            !seq(s,f + 7,split,9) || s->t[f + 16].kind != STRING || !equal(s->t + f + 16,"/") ||
            s->t[f + 17].kind != ')' || s->t[f + 18].kind != ';' || !equal(s->t + f + 19,"if") ||
            s->t[f + 20].kind != '(' || !same(parts,s->t + f + 21) || !seq(s,f + 22,guard,5) ||
            destination->kind != IDENT || browser_name(destination) || same(parts,destination) || s->t[f + 28].kind != '=' ||
            s->t[f + 29].kind != STRING || s->t[f + 30].kind != '+' || s->t[f + 31].kind != STRING ||
            s->t[f + 32].kind != '+' || !same(parts,s->t + f + 33) || s->t[f + 34].kind != '[' ||
            s->t[f + 35].kind != NUMBER || !equal(s->t + f + 35,"2") || s->t[f + 36].kind != ']' ||
            s->t[f + 37].kind != ';' || s->t[f + 38].kind != '}' || !seq(s,f + 39,target,6) ||
            !same(destination,s->t + f + 45) || s->t[f + 46].kind != ';') continue;
        uint32_t end = s->t[f + 4].pair;
        const char *const close_later[] = {"setTimeout","(","function","(",")","{","window",".","close","(",")",";","}",","};
        if (end != f + 47 && (end != f + 64 || !seq(s,f + 47,close_later,14) ||
            s->t[f + 61].kind != NUMBER || s->t[f + 62].kind != ')' || s->t[f + 63].kind != ';')) continue;
        unsigned part_writes = 0, destination_writes = 0; int valid = 1;
        for (uint32_t j = f + 5; j < s->t[f + 4].pair; ++j) {
            if (equal(s->t + j,"var") && j + 1 < s->count && browser_name(s->t + j + 1)) valid = 0;
            if (j + 1 < s->count && s->t[j + 1].kind == '=') {
                if (same(parts,s->t + j)) ++part_writes;
                if (same(destination,s->t + j)) ++destination_writes;
            }
        }
        if (!valid || part_writes != 1 || destination_writes != 1) continue;
        const token *path = s->t + f + 29, *query = s->t + f + 31;
        if (path->length < 6 || memcmp(path->data + path->length - 5,".jnlp",5) || query->length < 3 ||
            query->data[0] != '?' || query->data[query->length - 1] != '=') continue;
        for (uint32_t j = 0; j < path->length; ++j)
            if (!alpha(path->data[j]) && !digit(path->data[j]) && path->data[j] != '/' && path->data[j] != '.' && path->data[j] != '-') valid = 0;
        for (uint32_t j = 1; j + 1 < query->length; ++j)
            if (!(j == 1 ? alpha(query->data[j]) : alpha(query->data[j]) || digit(query->data[j]))) valid = 0;
        if (!valid || path->length + query->length >= 1024) continue;
        size_t used = path->length + query->length;
        memcpy(out,path->data,path->length); memcpy(out + path->length,query->data,query->length);
        static const char hex[] = "0123456789ABCDEF";
        for (uint64_t j = 8; j < origin.length; ++j) {
            uint8_t c = (uint8_t)origin.data[j];
            if (c == '/' || c == '?' || c == '#' || c == '@' || c < 33 || c > 126) { valid = 0; break; }
            int plain = alpha(c) || digit(c) || c == '.' || c == '-' || c == '~';
            if (used + (plain ? 1u : 3u) >= 1025) { valid = 0; break; }
            if (plain) out[used++] = (char)c;
            else { out[used++] = '%'; out[used++] = hex[c >> 4]; out[used++] = hex[c & 15]; }
        }
        if (valid) { out[used] = 0; return 1; }
    } while (0);
    return 0;
}

static int appweb_seq(const script *s, uint32_t i, const char *const *words, uint32_t n) {
    if (i > s->count || n > s->count-i) return 0;
    for (uint32_t j=0;j<n;++j) {
        if (words[j][0]=='#') { if(s->t[i+j].kind!=STRING || !equal(s->t+i+j,words[j]+1)) return 0; }
        else if (!seq(s,i+j,words+j,1)) return 0;
    }
    return 1;
}
static int appweb_parameter(const script *s, bc_string origin, char out[320]) {
    const char *const prefix[] = {"function","getJavaPluginParameter","(",")","{","var","ipAddrAndFormat","=","getIPAddressAndFormat","("};
    const char *const suffix[] = {")",";","var","cache","=","new","Date","(",")",".","getTime","(",")",";","return","(","ipAddrAndFormat","+","#@","+","cache",")",";","}"};
    unsigned found = 0;
    if (!origin.data || origin.length < 9 || memcmp(origin.data, "https://", 8)) return 0;
    for (uint32_t i = 0; i + 34 < s->count; ++i) {
        if (!seq(s, i, prefix, 10) || s->t[i+10].kind != STRING || !appweb_seq(s, i+11, suffix, 24)) continue;
        const token *host = s->t+i+10;
        if (!host->length || host->length > 255) return 0;
        const char *start = origin.data+8; size_t length = origin.length-8;
        int ipv6 = start[0] == '[';
        if (ipv6) { ++start; --length; size_t n = 0; while (n < length && start[n] != ']') ++n; length = n; }
        else { size_t n = 0; while (n < length && start[n] != ':' && start[n] != '/') ++n; length = n; }
        if (length != host->length || memcmp(start, host->data, length) || ++found != 1) return 0;
        for (uint32_t j=0;j<host->length;++j) if (!alpha(host->data[j]) && !digit(host->data[j]) && !strchr(".:-",host->data[j])) return 0;
        time_t now = time(NULL); if (now < 0) return 0;
        snprintf(out,320,"%.*s@%d@%llu",(int)host->length,host->data,ipv6,(unsigned long long)now*1000);
    }
    return found == 1;
}
static bc_status appweb_links(const script *s, bc_string origin, bc_web_link_callback callback, void *user) {
    char parameters[320]; int have_parameters = appweb_parameter(s, origin, parameters);
    const char *const parameter_call[] = {"var","params","=","getJavaPluginParameter","(",")",";"};
    for (uint32_t i=0;i+4<s->count;++i) {
        if (s->t[i].kind != IDENT || !equal(s->t+i,"getACSRFProtectedUri") || s->t[i+1].kind != '(' || s->t[i+2].kind != STRING) continue;
        const token *target=s->t+i+2;
        if (s->t[i+3].kind == ')') {
            bc_status status=callback(user,BC_WEB_LINK_HTML,(bc_string){(const char *)target->data,target->length});
            if(status!=BC_OK)return status;
        } else if (have_parameters && i+7<s->count && s->t[i+3].kind=='+' && equal(s->t+i+4,"params") &&
            s->t[i+5].kind=='+' && s->t[i+6].kind==STRING && equal(s->t+i+6,")") && s->t[i+7].kind==')' &&
            (equal(target,"viewer.jnlp(") || equal(target,"/data?type=jnlp&get=vmStart("))) {
            int assigned=0;
            for(uint32_t j=0;j<i;++j) if(seq(s,j,parameter_call,7)) assigned=1;
            if(!assigned)continue;
            char path[1025]; snprintf(path,sizeof(path),"%.*s%s)",(int)target->length,target->data,parameters);
            bc_status status=callback(user,BC_WEB_LINK_STARTUP,(bc_string){path,strlen(path)});
            if(status!=BC_OK)return status;
        }
    }
    return BC_OK;
}
static bc_status dom_links(const script *, bc_web_link_callback, void *);
bc_status bc_web_login_script_origin_links(const uint8_t *data, uint32_t length, bc_string origin,
    bc_web_link_callback callback, void *user) {
    if (!data || !length || !callback) return BC_INVALID_ARGUMENT;
    if (length > SOURCE_LIMIT) return BC_LIMIT_EXCEEDED;
    script s = {calloc(TOKEN_LIMIT, sizeof(token)), 0};
    if (!s.t) return BC_NO_MEMORY;
    bc_status status = lex(data, length, &s); int unknown = 0;
    if (status == BC_OK && origin.length) status = appweb_links(&s, origin, callback, user);
    if (status == BC_OK) for (uint32_t i = 0; i < s.count; ++i) {
        if (s.t[i].kind != IDENT || (i && s.t[i - 1].kind == '.')) continue;
        uint32_t at = i;
        const char *const popup[] = {"window", ".", "open", "("};
        if (seq(&s, i, popup, 4)) {
            uint32_t close = s.t[i + 3].pair;
            if (close == UINT32_MAX || i + 5 >= close || s.t[i + 4].kind != STRING || s.t[i + 5].kind != ',') { unknown = 1; continue; }
            /* Static popup metadata only. The scheduler still limits this to
             * advertised HTML assets, never JNLP/ticket or arbitrary URLs. */
            uint32_t arg = i + 6; int valid = 1;
            while (arg < close) {
                if (s.t[arg].kind != STRING) { valid = 0; break; }
                ++arg;
                if (arg < close && s.t[arg++].kind != ',') { valid = 0; break; }
            }
            if (!valid) { unknown = 1; continue; }
            const token *target = s.t + i + 4;
            status = callback(user, BC_WEB_LINK_HTML, (bc_string){(const char *)target->data, target->length});
            if (status != BC_OK) break;
            i = close; continue;
        }
        /* A bare local named location is not evidence of browser navigation. */
        if (equal(s.t + at, "location")) { unknown = 1; continue; }
        if (equal(s.t + at, "window") || equal(s.t + at, "top") || equal(s.t + at, "self")) {
            if (++at >= s.count || s.t[at++].kind != '.' || at >= s.count) continue;
            unsigned members = 0;
            while (at < s.count && !equal(s.t + at, "location")) {
                if (++members > 8 || s.t[at].kind != IDENT) break;
                if (equal(s.t + at, "frames") && at + 3 < s.count && s.t[at + 1].kind == '[' &&
                    s.t[at + 2].kind == STRING && s.t[at + 3].kind == ']') at += 4;
                else ++at;
                if (at >= s.count || s.t[at].kind != '.') break;
                ++at;
            }
        }
        if (at >= s.count || s.t[at].kind != IDENT || !equal(s.t + at, "location")) continue;
        ++at;
        if (at + 1 < s.count && s.t[at].kind == '.' && equal(s.t + at + 1, "href")) at += 2;
        if (at >= s.count || s.t[at].kind != '=') continue;
        if (at + 2 >= s.count || s.t[at + 1].kind != STRING || s.t[at + 2].kind != ';') {
            char resolved[1025];
            if (!authority_redirect(&s,i,origin,resolved)) { unknown = 1; continue; }
            status = callback(user, BC_WEB_LINK_HTML, (bc_string){resolved,strlen(resolved)});
            if (status != BC_OK) break;
            i = at + 2; continue;
        }
        const token *target = s.t + at + 1;
        status = callback(user, BC_WEB_LINK_HTML, (bc_string){(const char *)target->data, target->length});
        if (status != BC_OK) break;
        i = at + 2;
    }
    if (status == BC_OK) status = dom_links(&s, callback, user);
    free(s.t);
    return status == BC_OK && unknown ? BC_UNSUPPORTED : status;
}

bc_status bc_web_login_script_links(const uint8_t *data, uint32_t length,
    bc_web_link_callback callback, void *user) {
    return bc_web_login_script_origin_links(data,length,(bc_string){0},callback,user);
}

/* Recognize the data relationships of the legacy xmit form transport. This is
 * independent from login fields, response handling, and any console protocol. */
typedef struct { uint32_t begin, end; const token *params[2]; } function;
static int session_guard_override(const script *s, uint32_t begin, uint32_t end, uint32_t assignment) {
    const char *const guard[] = {"if", "(", "parent", ".", "gSessionCheck", "=", "=", "true", ")", "{",
        "if", "(", "!", "parent", ".", "application_checkSessionValid", "(", ")", ")", "{",
        "parent", ".", "gSessionCheck", "=", "false", ";", "this", ".", "send", "=",
        "parent", ".", "application_sessionTimedOut", ";", "}", "}"};
    for (uint32_t i = begin; i < end; ++i)
        if (seq(s, i, guard, sizeof(guard) / sizeof(*guard)) && (assignment == UINT32_MAX || assignment == i + 26)) return 1;
    return 0;
}
static int function_at(const script *s, uint32_t at, uint32_t end, const char *owner,
    const char *method, unsigned parameters, function *out) {
    unsigned found = 0, depth = 0;
    for (uint32_t i = at; i + 6 < end; ++i) {
        const char *const prefix[] = {owner, ".", method, "="};
        if (!seq(s, i, prefix, 4) || s->t[i + 4].kind == '=') {
            if (s->t[i].kind == IDENT && equal(s->t + i, "function") && s->t[i + 1].kind == '(') {
                uint32_t close = s->t[i + 1].pair;
                if (close + 1 < end && s->t[close + 1].kind == '{') i = s->t[close + 1].pair;
            } else if (s->t[i].kind == '{') ++depth;
            else if (s->t[i].kind == '}' && depth) --depth;
            continue;
        }
        if (s->t[i + 4].kind != IDENT || !equal(s->t + i + 4, "function") || s->t[i + 5].kind != '(') {
            if (!strcmp(owner, "this") && !strcmp(method, "send") && session_guard_override(s, at, end, i)) continue;
            return 0;
        }
        if (depth) return 0;
        uint32_t close = s->t[i + 5].pair, first = i + 6;
        if (close + 1 >= end || s->t[close + 1].kind != '{' || ++found != 1) return 0;
        if (close - first != (parameters ? parameters * 2 - 1 : 0)) return 0;
        *out = (function){close + 2, s->t[close + 1].pair, {NULL, NULL}};
        for (unsigned j = 0; j < parameters; ++j) {
            if (s->t[first + j * 2].kind != IDENT || (j && s->t[first + j * 2 - 1].kind != ',')) return 0;
            out->params[j] = s->t + first + j * 2;
        }
        i = out->end;
    }
    return found == 1;
}
static int field(const script *s, uint32_t begin, uint32_t end, const char *name) {
    const char *const parts[] = {"this", ".", name};
    return end - begin == 3 && seq(s, begin, parts, 3);
}
static void ungroup(const script *s, uint32_t *begin, uint32_t *end) {
    while (*begin < *end && s->t[*begin].kind == '(' && s->t[*begin].pair == *end - 1) { ++*begin; --*end; }
}
static uint32_t operator_at(const script *s, uint32_t begin, uint32_t end, uint32_t kind) {
    for (uint32_t i = begin; i < end; ++i) {
        if (s->t[i].kind == kind) return i;
        if (s->t[i].kind == '(' || s->t[i].kind == '[' || s->t[i].kind == '{') i = s->t[i].pair;
    }
    return end;
}
static int assignment(const script *s, function f, const char *owner, const char *name,
    uint32_t positions[4], unsigned expected) {
    unsigned found = 0;
    for (uint32_t i = f.begin; i < f.end; ++i) {
        if (s->t[i].kind == IDENT && equal(s->t + i, "function") && i + 1 < f.end && s->t[i + 1].kind == '(') {
            uint32_t close = s->t[i + 1].pair;
            if (close + 1 < f.end && s->t[close + 1].kind == '{') i = s->t[close + 1].pair;
            continue;
        }
        const char *const parts[] = {owner, ".", name, "="};
        if (i + 4 >= f.end || !seq(s, i, parts, 4) || s->t[i + 4].kind == '=') continue;
        if (found == 4) return 0;
        positions[found++] = i + 4;
    }
    return found == expected;
}
static uint32_t expression_end(const script *s, uint32_t begin, uint32_t limit) { return operator_at(s, begin, limit, ';'); }
static int literal(const script *s, uint32_t begin, uint32_t end, const char *value) {
    ungroup(s, &begin, &end);
    return end - begin == 1 && s->t[begin].kind == STRING && equal(s->t + begin, value);
}
static int name_is(const script *s, uint32_t begin, uint32_t end, const token *name) {
    ungroup(s, &begin, &end); return end - begin == 1 && same(s->t + begin, name);
}
static int encode_call(const script *s, uint32_t begin, uint32_t end, const token *value) {
    ungroup(s, &begin, &end);
    const char *const call[] = {"xmit", ".", "encodespecial", "("};
    return end - begin == 6 && seq(s, begin, call, 4) && same(s->t + begin + 4, value) && s->t[begin + 5].kind == ')';
}
static int concat(const script *s, uint32_t begin, uint32_t end, const token *name, const token *value,
    const unsigned *terms, unsigned count) {
    ungroup(s, &begin, &end);
    if (!count || begin == end) return 0;
    uint32_t plus = operator_at(s, begin, end, '+');
    if (count == 1) {
        if (plus != end) return 0;
        if (*terms == 1) return name_is(s, begin, end, name);
        if (*terms == 2) return literal(s, begin, end, "=");
        if (*terms == 3) return encode_call(s, begin, end, value);
        if (*terms == 4) return field(s, begin, end, "data");
        if (*terms == 5) return literal(s, begin, end, "&");
        return 0;
    }
    return plus != end && concat(s, begin, plus, name, value, terms, 1) &&
        concat(s, plus + 1, end, name, value, terms + 1, count - 1);
}
static int append_form(const script *s, function f) {
    uint32_t at[4]; if (!assignment(s, f, "this", "data", at, 1)) return 0;
    uint32_t begin = at[0], end = expression_end(s, begin, f.end); ungroup(s, &begin, &end);
    uint32_t question = operator_at(s, begin, end, '?'), colon = operator_at(s, question + (question != end), end, ':');
    uint32_t condition_end = question; ungroup(s, &begin, &condition_end);
    if (condition_end - begin != 6 || !field(s, begin, begin + 3, "data") ||
        s->t[begin + 3].kind != '=' || s->t[begin + 4].kind != '=' || !literal(s, begin + 5, condition_end, "")) return 0;
    const unsigned first[] = {1, 2, 3}, later[] = {4, 5, 1, 2, 3};
    return question < colon && colon < end && concat(s, question + 1, colon, f.params[0], f.params[1], first, 3) &&
        concat(s, colon + 1, end, f.params[0], f.params[1], later, 5);
}
static int regex_character(const token *t, uint8_t *out) {
    if (t->kind != REGEX || t->length < 4 || t->data[0] != '/' || t->data[t->length - 1] != 'g') return 0;
    uint32_t i = 1;
    if (t->data[i] == '\\') ++i;
    if (i + 3 != t->length || t->data[i + 1] != '/') return 0;
    *out = t->data[i]; return 1;
}
static int replacements(const script *s, uint32_t begin, uint32_t end, const token *value, unsigned *mask) {
    ungroup(s, &begin, &end);
    if (name_is(s, begin, end, value)) return 1;
    if (end - begin < 8 || s->t[end - 1].kind != ')' || s->t[end - 7].kind != '.' ||
        s->t[end - 6].kind != IDENT || !equal(s->t + end - 6, "replace") || s->t[end - 5].kind != '(' ||
        s->t[end - 2].kind != STRING || s->t[end - 3].kind != ',') return 0;
    if (!replacements(s, begin, end - 7, value, mask)) return 0;
    uint8_t c; if (!regex_character(s->t + end - 4, &c)) return 0;
    unsigned bit = c == '%' ? 1 : c == '+' ? 2 : c == '&' ? 4 : c == '#' ? 8 : 0;
    const char *replacement = c == '%' ? "%25" : c == '+' ? "%2B" : c == '&' ? "%26" : "%23";
    if (!bit || (*mask & bit) || (bit != 1 && !(*mask & 1)) || !equal(s->t + end - 2, replacement)) return 0;
    *mask |= bit; return 1;
}
static int encode_form(const script *s, function f) {
    uint32_t i = f.begin;
    if (i + 2 >= f.end || !equal(s->t + i, "if") || s->t[i + 1].kind != '(') return 0;
    uint32_t cond_end = s->t[i + 1].pair, begin = i + 2;
    const char *const type[] = {"typeof", "("};
    if (cond_end - begin != 7 || !seq(s, begin, type, 2) || !same(s->t + begin + 2, f.params[0]) ||
        s->t[begin + 3].kind != ')' || s->t[begin + 4].kind != '=' || s->t[begin + 5].kind != '=' ||
        !literal(s, begin + 6, cond_end, "string") || s->t[cond_end + 1].kind != '{') return 0;
    uint32_t body_end = s->t[cond_end + 1].pair; i = cond_end + 2; unsigned mask = 0;
    for (unsigned statement = 0; statement < 2; ++statement) {
        if (i + 2 >= body_end || !same(s->t + i, f.params[0]) || s->t[i + 1].kind != '=') return 0;
        uint32_t end = expression_end(s, i + 2, body_end);
        if (end == body_end || !replacements(s, i + 2, end, f.params[0], &mask) || (statement == 0 && mask != 1)) return 0;
        i = end + 1;
    }
    return mask == 15 && i == body_end && f.end - body_end == 4 && equal(s->t + body_end + 1, "return") &&
        same(s->t + body_end + 2, f.params[0]) && s->t[body_end + 3].kind == ';';
}
static int dummy_path(const script *s, function f) {
    unsigned writes = 0;
    for (uint32_t i = 0; i + 2 < s->count; ++i) {
        if (s->t[i].kind != IDENT || !equal(s->t + i, "DUMMY_SERVER") || s->t[i + 1].kind != '=' || s->t[i + 2].kind == '=') continue;
        if (!i || !equal(s->t + i - 1, "var") || !equal(s->t + i + 2, "false") || ++writes != 1) return 0;
    }
    if (writes != 1) return 0;
    const char *const prefix[] = {"if", "(", "DUMMY_SERVER", "=", "=", "true", ")", "{"};
    uint32_t i = f.begin;
    if (!seq(s, i, prefix, 8)) return 0;
    i += 8;
    if (i + 9 >= f.end || !same(s->t + i, f.params[0]) || s->t[i + 1].kind != '=' || s->t[i + 2].kind != STRING ||
        s->t[i + 3].kind != '+' || !same(s->t + i + 4, f.params[0]) || s->t[i + 5].kind != ';' || s->t[i + 6].kind != '}' ||
        !equal(s->t + i + 7, "return") || !same(s->t + i + 8, f.params[0]) || s->t[i + 9].kind != ';') return 0;
    return i + 10 == f.end;
}
static int getset(const script *s, function f) {
    uint32_t i = f.begin;
    const char *const first[] = {"var", "", "=", "new", "xmit", ".", "goajax", "("};
    if (f.end - i != 14 || s->t[i + 1].kind != IDENT) return 0;
    for (unsigned j = 0; j < 8; ++j) if (j != 1 && !seq(s, i + j, first + j, 1)) return 0;
    return same(s->t + i + 8, f.params[0]) && s->t[i + 9].kind == ')' && s->t[i + 10].kind == ';' &&
        equal(s->t + i + 11, "return") && same(s->t + i + 12, s->t + i + 1) && s->t[i + 13].kind == ';';
}
static int constructor(const script *s, function f) {
    uint32_t i = f.begin, at[4];
    if (f.end - i < 24 || !equal(s->t + i, "var") || s->t[i + 1].kind != IDENT) return 0;
    const char *const call[] = {"=", "xmit", ".", "returnpath", "("};
    const char *const tail[] = {".", "url", ")", ";", "this", ".", "url", "="};
    if (!seq(s, i + 2, call, 5) || !same(s->t + i + 7, f.params[0]) || !seq(s, i + 8, tail, 8) ||
        !same(s->t + i + 16, s->t + i + 1) || s->t[i + 17].kind != ';' ||
        !field(s, i + 18, i + 21, "data") || s->t[i + 21].kind != '=' || !literal(s, i + 22, i + 23, "") || s->t[i + 23].kind != ';') return 0;
    if (!assignment(s, f, "this", "url", at, 1) || at[0] != i + 16 ||
        !assignment(s, f, "this", "data", at, 1) || at[0] != i + 22) return 0;
    for (uint32_t j = f.begin; j < f.end; ++j) {
        if (equal(s->t + j, "function") && j + 1 < f.end && s->t[j + 1].kind == '(') {
            uint32_t close = s->t[j + 1].pair;
            if (close + 1 < f.end && s->t[close + 1].kind == '{') j = s->t[close + 1].pair;
        } else if (s->t[j].kind == IDENT && equal(s->t + j, "return") &&
            (j + 3 != f.end || !equal(s->t + j + 1, "this") || s->t[j + 2].kind != ';')) return 0;
    }
    return 1;
}
static int matches_equals(const token *regex) {
    if (regex->kind != REGEX || regex->length < 6 || memcmp(regex->data, "/[^", 3)) return 0;
    uint32_t i = 3; int contains = 0;
    while (i < regex->length && regex->data[i] != ']') {
        uint8_t first = regex->data[i++], last = first;
        if (!(alpha(first) || digit(first))) return 0;
        if (i < regex->length && regex->data[i] == '-') {
            if (++i == regex->length) return 0;
            last = regex->data[i++]; if (last < first) return 0;
        }
        if (first <= '=' && last >= '=') contains = 1;
    }
    return !contains && i + 2 == regex->length && regex->data[i] == ']' && regex->data[i + 1] == '/';
}
static int post_condition(const script *s, uint32_t begin, uint32_t end) {
    ungroup(s, &begin, &end); uint32_t either = operator_at(s, begin, end, '|');
    if (either + 1 >= end || s->t[either + 1].kind != '|') return 0;
    uint32_t left_end = either; ungroup(s, &begin, &left_end);
    if (s->t[begin].kind != '(') return 0;
    uint32_t sum_end = s->t[begin].pair;
    const char *const length[] = {".", "length", ">"};
    if (sum_end + 5 != left_end || !seq(s, sum_end + 1, length, 3) ||
        s->t[sum_end + 4].kind != NUMBER || !equal(s->t + sum_end + 4, "512") ||
        !field(s, begin + 1, begin + 4, "url") || s->t[begin + 4].kind != '+' || !field(s, begin + 5, sum_end, "data")) return 0;
    begin = either + 2; ungroup(s, &begin, &end);
    const char *const execute[] = {".", "exec", "(", "this", ".", "data", ")", "!", "=", "null"};
    return end - begin == 11 && matches_equals(s->t + begin) && seq(s, begin + 1, execute, 10);
}
static int send_form(const script *s, function f) {
    uint32_t conditional = UINT32_MAX, post_begin = 0, post_end = 0, get_begin = 0, get_end = 0;
    for (uint32_t i = f.begin; i + 1 < f.end; ++i) {
        if (!equal(s->t + i, "if") || s->t[i + 1].kind != '(') continue;
        uint32_t end = s->t[i + 1].pair;
        if (!post_condition(s, i + 2, end)) continue;
        if (conditional != UINT32_MAX || end + 1 >= f.end || s->t[end + 1].kind != '{') return 0;
        conditional = i; post_begin = end + 2; post_end = s->t[end + 1].pair;
        if (post_end + 2 >= f.end || !equal(s->t + post_end + 1, "else") || s->t[post_end + 2].kind != '{') return 0;
        get_begin = post_end + 3; get_end = s->t[post_end + 2].pair;
    }
    if (conditional == UINT32_MAX) return 0;
    uint32_t method[4], data[4];
    if (!assignment(s, f, "this", "method", method, 2) || !assignment(s, f, "this", "postdata", data, 2)) return 0;
    if (method[0] < post_begin || method[0] >= post_end || data[0] < post_begin || data[0] >= post_end ||
        method[1] < get_begin || method[1] >= get_end || data[1] < get_begin || data[1] >= get_end ||
        !literal(s, method[0], expression_end(s, method[0], post_end), "POST") ||
        !literal(s, method[1], expression_end(s, method[1], get_end), "GET") ||
        !field(s, data[0], expression_end(s, data[0], post_end), "data") ||
        !equal(s->t + data[1], "null")) return 0;
    unsigned opens = 0, sends = 0, headers = 0;
    uint32_t opened = 0, sent = 0;
    const char *const open[] = {"this", ".", "xmldoc", ".", "open", "(", "this", ".", "method", ",", "this", ".", "url", ",", "this", ".", "async", ",", "this", ".", "username", ",", "this", ".", "password", ")", ";"};
    const char *const send[] = {"this", ".", "xmldoc", ".", "send", "(", "this", ".", "postdata", ")", ";"};
    const char *const header[] = {"this", ".", "xmldoc", ".", "setRequestHeader", "("};
    for (uint32_t i = get_end + 1; i < f.end; ++i) {
        if (seq(s, i, open, 27)) { ++opens; opened = i; }
        if (seq(s, i, send, 11)) { ++sends; sent = i; }
        if (seq(s, i, header, 6) && i + 10 < f.end && literal(s, i + 6, i + 7, "Content-type")) {
            if (s->t[i + 7].kind != ',' || !literal(s, i + 8, i + 9, "application/x-www-form-urlencoded") ||
                s->t[i + 9].kind != ')' || s->t[i + 10].kind != ';') return 0;
            ++headers;
        }
    }
    return opens == 1 && sends == 1 && headers == 1 && opened < sent;
}
bc_status bc_web_login_xmit_form_hint(const uint8_t *data, uint32_t length, uint32_t *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = 0;
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > SOURCE_LIMIT) return BC_LIMIT_EXCEEDED;
    script s = {calloc(TOKEN_LIMIT, sizeof(token)), 0}; if (!s.t) return BC_NO_MEMORY;
    bc_status status = lex(data, length, &s);
    function make = {0}, object = {0}, add = {0}, send = {0}, encode = {0}, path = {0};
    if (status == BC_OK && (!function_at(&s, 0, s.count, "xmit", "getset", 1, &make) || !getset(&s, make) ||
        !function_at(&s, 0, s.count, "xmit", "goajax", 1, &object) || !constructor(&s, object) ||
        !function_at(&s, object.begin, object.end, "this", "add", 2, &add) || !append_form(&s, add) ||
        !function_at(&s, object.begin, object.end, "this", "send", 0, &send) || !send_form(&s, send) ||
        !function_at(&s, 0, s.count, "xmit", "encodespecial", 1, &encode) || !encode_form(&s, encode) ||
        !function_at(&s, 0, s.count, "xmit", "returnpath", 1, &path) || !dummy_path(&s, path))) status = BC_UNSUPPORTED;
    if (status == BC_OK) *out = BC_WEB_LOGIN_XMIT_FORM_POST |
        (session_guard_override(&s, object.begin, object.end, UINT32_MAX) ? BC_WEB_LOGIN_XMIT_SESSION_GUARD : 0);
    free(s.t);
    return status;
}

static int named_function(const script *s, const token *name, function *out) {
    unsigned found = 0;
    for (uint32_t i = 0; i + 5 < s->count; ++i) {
        if (!equal(s->t + i, "function") || !same(s->t + i + 1, name)) continue;
        if (s->t[i + 2].kind != '(' || s->t[i + 3].kind != IDENT || s->t[i + 4].kind != ')' ||
            s->t[i + 5].kind != '{' || ++found != 1) return 0;
        *out = (function){i + 6, s->t[i + 5].pair, {s->t + i + 3, NULL}};
    }
    return found == 1;
}
static int success_block(const script *s, function f, function *out) {
    unsigned found = 0;
    for (uint32_t i = f.begin; i + 10 < f.end; ++i) {
        const char *const check[] = {".", "HAPI_STATUS", "=", "=", "=", "0", ")", "{"};
        if (!equal(s->t + i, "if") || s->t[i + 1].kind != '(' || !same(s->t + i + 2, f.params[0]) ||
            !seq(s, i + 3, check, 5) || s->t[i + 8].kind != NUMBER || !equal(s->t + i + 8, "0") || s->t[i + 9].kind != ')' || s->t[i + 10].kind != '{') continue;
        if (++found != 1) return 0;
        *out = (function){i + 11, s->t[i + 10].pair, {NULL, NULL}};
    }
    return found == 1;
}
static int response_value(const script *s, function f, const char *object, const char *array,
    const char *field_name, const char *target) {
    unsigned found = 0;
    for (uint32_t i = f.begin; i + 18 < f.end; ++i) {
        const char *const prefix[] = {"var", "", "=", object, ".", array, "[", "0", "]", ";",
            "top", ".", target, "="};
        int valid = 1;
        for (unsigned j = 0; j < 14; ++j) if (j != 1 && !equal(s->t + i + j, prefix[j])) valid = 0;
        if (!valid || s->t[i + 1].kind != IDENT || !same(s->t + i + 14, s->t + i + 1) ||
            s->t[i + 15].kind != '.' || !equal(s->t + i + 16, field_name) || s->t[i + 17].kind != ';') continue;
        if (++found != 1) return 0;
    }
    return found == 1;
}
/* HTTP response field relationships are independent of the browser's optional
 * inherited-session guard and of the eventual KVM transport/layout. */
bc_status bc_web_login_response_hint_get(const uint8_t *data, uint32_t length,
    bc_web_login_response_hint *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > SOURCE_LIMIT) return BC_LIMIT_EXCEEDED;
    bc_web_login_hint request = {0};
    bc_status status = bc_web_login_script_hint(data, length, &request);
    if (status != BC_OK) return status;
    script s = {calloc(TOKEN_LIMIT, sizeof(token)), 0};
    if (!s.t) return BC_NO_MEMORY;
    status = lex(data, length, &s);
    const token *login_callback = NULL;
    unsigned found = 0;
    if (status == BC_OK) for (uint32_t i = 0; i + 4 < s.count; ++i) {
        if (!equal(s.t + i, "url") || s.t[i + 1].kind != ':' || s.t[i + 2].kind != STRING ||
            !equal(s.t + i + 2, request.path)) continue;
        /* Search only this constructor's options object. */
        uint32_t begin = i;
        while (begin && s.t[begin].kind != '{') --begin;
        uint32_t end = s.t[begin].pair;
        if (s.t[begin].kind != '{' || end == UINT32_MAX || end >= s.count) continue;
        for (uint32_t j = begin + 1; j + 2 < end; ++j)
            if (equal(s.t + j, "onrcv") && s.t[j + 1].kind == ':' && s.t[j + 2].kind == IDENT) {
                login_callback = s.t + j + 2; ++found;
            }
    }
    function login = {0}, login_ok = {0}, csrf_fn = {0}, csrf_cb = {0}, csrf_ok = {0};
    if (status == BC_OK && (found != 1 || !named_function(&s, login_callback, &login) ||
        !success_block(&s, login, &login_ok) || !response_value(&s, login_ok,
        "WEBVAR_JSONVAR_WEB_SESSION", "WEBVAR_STRUCTNAME_WEB_SESSION", "SESSION_COOKIE", "gSessionCookie"))) status = BC_UNSUPPORTED;
    const token *csrf_name = NULL, *csrf_callback = NULL;
    unsigned calls = 0;
    if (status == BC_OK) for (uint32_t i = login_ok.begin; i + 15 < login_ok.end; ++i) {
        const char *const chain[] = {"writeCookie", "(", "top", ".", "keySessionCookie", ",", "top", ".",
            "gSessionCookie", ",", "false", ")", ";"};
        if (!seq(&s, i, chain, 13)) continue;
        uint32_t at = i + 13;
        const char *const argument[] = {"(", "top", ".", "gSessionCookie", ")", ";"};
        if (s.t[at].kind != IDENT || !seq(&s, at + 1, argument, 6) || ++calls != 1) { status = BC_UNSUPPORTED; break; }
        csrf_name = s.t + at;
    }
    if (status == BC_OK && (calls != 1 || !named_function(&s, csrf_name, &csrf_fn))) status = BC_UNSUPPORTED;
    if (status == BC_OK) {
        uint32_t i = csrf_fn.begin;
        const char *const prefix[] = {"var", "", "=", "xmit", ".", "getset", "(", "{"};
        int valid = csrf_fn.end > i + 8;
        for (unsigned j = 0; valid && j < 8; ++j) if (j != 1 && !equal(s.t + i + j, prefix[j])) valid = 0;
        if (!valid || s.t[i + 1].kind != IDENT) status = BC_UNSUPPORTED;
        else {
            uint32_t end = s.t[i + 7].pair, keys = 0;
            for (uint32_t j = i + 8; status == BC_OK && j < end;) {
                if (j + 2 >= end || s.t[j + 1].kind != ':') { status = BC_UNSUPPORTED; break; }
                uint32_t bit = 0;
                if (equal(s.t + j, "url")) {
                    bit = 1;
                    if (!copy(out->csrf_path, sizeof(out->csrf_path), s.t + j + 2) || out->csrf_path[0] != '/' ||
                        out->csrf_path[1] == '/' || strchr(out->csrf_path, '?') || strchr(out->csrf_path, '#')) status = BC_UNSUPPORTED;
                } else if (equal(s.t + j, "onrcv") && s.t[j + 2].kind == IDENT) { bit = 2; csrf_callback = s.t + j + 2; }
                else if (equal(s.t + j, "status") && s.t[j + 2].kind == STRING && !s.t[j + 2].length) bit = 4;
                else if (equal(s.t + j, "timeout") && s.t[j + 2].kind == NUMBER) bit = 8;
                else status = BC_UNSUPPORTED;
                if (keys & bit) status = BC_UNSUPPORTED;
                keys |= bit; j += 3;
                if (j < end && s.t[j++].kind != ',') status = BC_UNSUPPORTED;
            }
            const token *rpc = s.t + i + 1;
            uint32_t at = end + 3;
            const char *const add[] = {".", "add", "(", "SESSION_COOKIE", ","};
            const char *const send[] = {".", "send", "(", ")", ";"};
            if ((keys & 3) != 3 || end + 2 >= csrf_fn.end || s.t[end + 1].kind != ')' || s.t[end + 2].kind != ';' ||
                at + 15 != csrf_fn.end || !same(s.t + at, rpc) || !seq(&s, at + 1, add, 3) || !equal(s.t + at + 4, "SESSION_COOKIE") || s.t[at + 5].kind != ',' ||
                s.t[at + 4].kind != STRING || !same(s.t + at + 6, csrf_fn.params[0]) ||
                s.t[at + 7].kind != ')' || s.t[at + 8].kind != ';' || !same(s.t + at + 9, rpc) ||
                !seq(&s, at + 10, send, 5)) status = BC_UNSUPPORTED;
        }
    }
    if (status == BC_OK && (!named_function(&s, csrf_callback, &csrf_cb) || !success_block(&s, csrf_cb, &csrf_ok) ||
        !response_value(&s, csrf_ok, "WEBVAR_JSONVAR_GETCSRFTOKEN", "WEBVAR_STRUCTNAME_GETCSRFTOKEN", "CSRFTOKEN", "gCSRFToken"))) status = BC_UNSUPPORTED;
    unsigned lands = 0;
    if (status == BC_OK) for (uint32_t i = csrf_ok.begin; i + 8 < csrf_ok.end; ++i) {
        const char *const target[] = {"top", ".", "topFrame", ".", "location", "="};
        if (!seq(&s, i, target, 6)) continue;
        if (s.t[i + 7].kind != ';' || !copy(out->landing_relative, sizeof(out->landing_relative), s.t + i + 6) || ++lands != 1) status = BC_UNSUPPORTED;
    }
    free(s.t);
    if (status == BC_OK && lands == 1) { out->struct_size = sizeof(*out); out->flags = BC_WEB_LOGIN_RESPONSE_COOKIE | BC_WEB_LOGIN_RESPONSE_CSRF_RPC; }
    else { memset(out, 0, sizeof(*out)); if (status == BC_OK) status = BC_UNSUPPORTED; }
    return status;
}

bc_status bc_web_login_cookie_name_hint(const uint8_t *data, uint32_t length, char out[65]) {
    if (!out) return BC_INVALID_ARGUMENT;
    out[0] = 0;
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > SOURCE_LIMIT) return BC_LIMIT_EXCEEDED;
    script s = {calloc(TOKEN_LIMIT, sizeof(token)), 0};
    if (!s.t) return BC_NO_MEMORY;
    bc_status status = lex(data, length, &s); unsigned definitions = 0, writes = 0, depth = 0;
    if (status == BC_OK) for (uint32_t i = 0; i < s.count; ++i) {
        if (s.t[i].kind == '{') ++depth;
        else if (s.t[i].kind == '}' && depth) --depth;
        if (!equal(s.t + i, "keySessionCookie") || s.t[i].kind != IDENT) continue;
        if (i + 1 < s.count && s.t[i + 1].kind == '=' && (i + 2 == s.count || s.t[i + 2].kind != '=')) {
            ++writes;
            if (depth || !i || !equal(s.t + i - 1, "var") || i + 3 >= s.count ||
                s.t[i + 3].kind != ';' || !copy(out, 65, s.t + i + 2)) { status = BC_UNSUPPORTED; break; }
            for (uint32_t j = 0; out[j]; ++j)
                if (!alpha((uint8_t)out[j]) && !digit((uint8_t)out[j]) && out[j] != '-') status = BC_UNSUPPORTED;
            ++definitions;
        } else if ((i + 1 < s.count && (s.t[i + 1].kind == '+' || s.t[i + 1].kind == '-')) ||
            (i && (s.t[i - 1].kind == '+' || s.t[i - 1].kind == '-'))) { status = BC_UNSUPPORTED; break; }
    }
    free(s.t);
    if (status != BC_OK || definitions != 1 || writes != 1) {
        out[0] = 0; if (status == BC_OK) status = BC_UNSUPPORTED;
    }
    return status;
}

typedef struct { const token *name; uint64_t fragments; int known; } dom_binding;
typedef struct { uint32_t begin, end; } dom_fragment;
typedef struct { dom_binding vars[32]; dom_fragment fragments[64]; unsigned count, literals; } dom_state;
static bc_status count_anchor(void *user, uint32_t kind, bc_string value) {
    (void)value; if (kind == BC_WEB_LINK_NAVIGATION) ++*(unsigned *)user; return BC_OK;
}
static int dom_label_tail(const script *s, uint32_t at, uint32_t end) {
    while (at < end) {
        if (s->t[at++].kind != '+' || at == end) return 0;
        if (s->t[at].kind == STRING) {
            unsigned ignored = 0;
            if (s->t[at].length && bc_web_login_html_links(s->t[at].data, s->t[at].length, count_anchor, &ignored) != BC_OK) return 0;
            ++at; continue;
        }
        const char *const label[] = {"eLang", ".", "getString", "("};
        if (at + 7 >= end || !seq(s, at, label, 4) || s->t[at + 4].kind != STRING ||
            s->t[at + 5].kind != ',' || s->t[at + 6].kind != STRING || s->t[at + 7].kind != ')') return 0;
        at += 8;
    }
    return 1;
}
static int dom_expression(const script *s, uint32_t begin, uint32_t end, dom_state *state, uint64_t *bits) {
    *bits = 0; uint32_t at = begin;
    while (at < end) {
        if (s->t[at].kind == STRING) {
            uint32_t start = at; char prefix[4096]; size_t length = 0;
            do {
                if (s->t[at].length > sizeof(prefix) - length) return 0;
                memcpy(prefix + length, s->t[at].data, s->t[at].length); length += s->t[at].length; ++at;
                if (at + 1 >= end || s->t[at].kind != '+' || s->t[at + 1].kind != STRING) break;
                ++at;
            } while (at < end);
            unsigned anchors = 0;
            if (length && bc_web_login_html_links((const uint8_t *)prefix, (uint32_t)length, count_anchor, &anchors) != BC_OK) return 0;
            if (anchors) {
                if (state->literals == 64) return 0;
                state->fragments[state->literals] = (dom_fragment){start, at};
                *bits |= UINT64_C(1) << state->literals++;
                /* The complete static start tags already advertise these
                 * hrefs; dynamic label text after them is never traversed. */
                if (at < end && s->t[at].kind == '+') return dom_label_tail(s, at, end);
            }
        } else if (s->t[at].kind == IDENT) {
            unsigned found = 0;
            for (unsigned i = 0; i < state->count; ++i) if (same(state->vars[i].name, s->t + at)) {
                if (!state->vars[i].known) return 0;
                *bits |= state->vars[i].fragments; found = 1; break;
            }
            if (!found) return 0;
            ++at;
        } else return 0;
        if (at < end && s->t[at++].kind != '+') return 0;
    }
    return 1;
}
static bc_status dom_links(const script *s, bc_web_link_callback callback, void *user) {
    for (uint32_t f = 0; f + 4 < s->count; ++f) {
        if (!equal(s->t + f, "function") || s->t[f + 1].kind != IDENT || s->t[f + 2].kind != '(') continue;
        uint32_t close = s->t[f + 2].pair;
        if (close + 1 >= s->count || s->t[close + 1].kind != '{') continue;
        uint32_t end = s->t[close + 1].pair; unsigned sinks = 0;
        for (uint32_t i = close + 2; i + 1 < end; ++i)
            if (s->t[i].kind == '.' && equal(s->t + i + 1, "replaceWith")) ++sinks;
        if (!sinks) { f = end; continue; }
        dom_state *state = calloc(1, sizeof(*state)); if (!state) return BC_NO_MEMORY;
        uint64_t reachable = 0; bc_status status = BC_OK;
        for (uint32_t i = close + 2; i + 2 < end; ++i) {
            if (equal(s->t + i, "function")) { status = BC_UNSUPPORTED; break; }
            if (s->t[i].kind == IDENT && s->t[i + 1].kind == '=' && s->t[i + 2].kind != '=' &&
                (!i || s->t[i - 1].kind != '.')) {
                unsigned index = state->count;
                for (unsigned j = 0; j < state->count; ++j) if (same(state->vars[j].name, s->t + i)) { index = j; break; }
                if (index == state->count) {
                    if (!i || !equal(s->t + i - 1, "var")) continue;
                    if (state->count == 32) { status = BC_LIMIT_EXCEEDED; break; }
                    state->vars[state->count++] = (dom_binding){s->t + i, 0, 1};
                }
                uint32_t stop = expression_end(s, i + 2, end); uint64_t bits;
                int known = dom_expression(s, i + 2, stop, state, &bits);
                state->vars[index].known &= known; state->vars[index].fragments |= bits; i = stop;
            } else {
                const char *const sink[] = {"$", "(", "", ")", ".", "replaceWith", "("};
                if (!seq(s, i, sink, 2) || i + 6 >= end || s->t[i + 2].kind != STRING || !seq(s, i + 3, sink + 3, 4)) continue;
                uint32_t stop = s->t[i + 6].pair; uint64_t bits;
                if (stop >= end || !dom_expression(s, i + 7, stop, state, &bits)) { status = BC_UNSUPPORTED; break; }
                reachable |= bits; i = stop;
            }
        }
        if (status == BC_OK) for (unsigned j = 0; j < state->literals; ++j) if (reachable & (UINT64_C(1) << j)) {
            char prefix[4096]; size_t length = 0; dom_fragment fragment = state->fragments[j];
            for (uint32_t at = fragment.begin; at < fragment.end; at += 2) {
                memcpy(prefix + length, s->t[at].data, s->t[at].length); length += s->t[at].length;
            }
            status = bc_web_login_html_links((const uint8_t *)prefix, (uint32_t)length, callback, user);
            if (status != BC_OK) break;
        }
        free(state); if (status != BC_OK) return status;
        f = end;
    }
    return BC_OK;
}

bc_status bc_web_login_csrf_tokens(const uint8_t *data, uint32_t length, char st1[257], char st2[257]) {
    st1[0] = st2[0] = 0;
    if (!data || !length || length > SOURCE_LIMIT) return BC_INVALID_ARGUMENT;
    script s = {calloc(TOKEN_LIMIT, sizeof(token)), 0};
    if (!s.t) return BC_NO_MEMORY;
    bc_status status = lex(data, length, &s);
    unsigned found = 0;
    if (status == BC_OK) for (uint32_t i = 0; i + 12 < s.count; ++i) {
        if (!equal(s.t + i, "new") || s.t[i].kind != IDENT || !equal(s.t + i + 1, "CSRFHandler") ||
            s.t[i + 1].kind != IDENT || s.t[i + 2].kind != '(') continue;
        if (++found != 1 || s.t[i + 3].kind != STRING || !equal(s.t + i + 3, "ST1") ||
            s.t[i + 4].kind != ',' || s.t[i + 6].kind != ',' || s.t[i + 7].kind != STRING ||
            !equal(s.t + i + 7, "ST2") || s.t[i + 8].kind != ',' || s.t[i + 10].kind != ',' ||
            !equal(s.t + i + 11, "true") || s.t[i + 12].kind != ')' ||
            !copy(st1, 257, s.t + i + 5) || !copy(st2, 257, s.t + i + 9)) { status = BC_UNSUPPORTED; break; }
    }
    free(s.t);
    if (status == BC_OK && found != 1) status = BC_UNSUPPORTED;
    for (unsigned j = 0; status == BC_OK && j < 2; ++j) {
        const char *p = j ? st2 : st1;
        for (; *p; ++p) if (!alpha((uint8_t)*p) && !digit((uint8_t)*p) && *p != '-') { status = BC_PROTOCOL_ERROR; break; }
    }
    if (status != BC_OK) st1[0] = st2[0] = 0;
    return status;
}

bc_status bc_web_login_appweb_script(const uint8_t *data, uint32_t length) {
    if (!data || !length || length > SOURCE_LIMIT) return BC_INVALID_ARGUMENT;
    script s = {calloc(TOKEN_LIMIT, sizeof(token)), 0};
    if (!s.t) return BC_NO_MEMORY;
    bc_status status = lex(data, length, &s); unsigned found = 0;
    const char *const shape[] = {"function","sendLoginRequest","(",")","{",
        "var","form","=","document",".","auth",";",
        "var","url","=","#data/login",";",
        "var","postData","=","#user=","+","encodeURIComponent","(","fullUserName",
        ")","+","#&password=","+","encodeSetValue","(","fullPassword",
        ")",";","sendPost","(","url",",","postData",",","loginRequestChange",
        ")",";","return","(","false",")",";","}"};
    if (status == BC_OK) for (uint32_t i = 0; i < s.count; ++i) {
        if (appweb_seq(&s, i, shape, sizeof(shape)/sizeof(shape[0])) &&
            s.t[i+15].kind == STRING && s.t[i+20].kind == STRING && s.t[i+27].kind == STRING) ++found;
    }
    free(s.t); return status == BC_OK ? (found == 1 ? BC_OK : BC_UNSUPPORTED) : status;
}

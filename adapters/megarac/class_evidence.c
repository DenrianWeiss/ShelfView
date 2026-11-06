#include "megarac.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define UNKNOWN INT64_MIN
#define HEADER "com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr"
#define APP "com/ami/kvm/jviewer/gui/JViewerApp"
#define ENTRY "com/ami/kvm/jviewer/JViewer"
typedef struct { const uint8_t *p; uint32_t n, at; int bad; } reader;
typedef struct { uint8_t tag; uint16_t a, b, length; uint32_t integer; uint64_t wide; const uint8_t *text; } constant;
typedef struct { constant *cp; uint32_t count, packet_size, field_count, method_count, method_access, super_index, field_kind; const uint8_t *code; uint32_t code_length; const uint8_t *exceptions; uint32_t exception_count; } java_class;
static const uint8_t *take(reader *r, uint32_t n) {
    if (r->bad || n > r->n - r->at) { r->bad = 1; return NULL; }
    const uint8_t *p = r->p + r->at; r->at += n; return p;
}
static uint32_t number(reader *r, uint32_t n) {
    const uint8_t *p = take(r, n); uint32_t v = 0;
    if (p) for (uint32_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}
static int text(java_class *c, uint32_t i, const char *s) {
    return i && i < c->count && c->cp[i].tag == 1 && c->cp[i].length == strlen(s) &&
        !memcmp(c->cp[i].text, s, strlen(s));
}
static int class_name(java_class *c, uint32_t i, const char *s) {
    return i && i < c->count && c->cp[i].tag == 7 && text(c, c->cp[i].a, s);
}
static int method(java_class *c, uint32_t i, const char *owner, const char *name, const char *desc) {
    if (!i || i >= c->count || c->cp[i].tag != 10 || !class_name(c, c->cp[i].a, owner)) return 0;
    uint32_t n = c->cp[i].b;
    return n && n < c->count && c->cp[n].tag == 12 && text(c, c->cp[n].a, name) && text(c, c->cp[n].b, desc);
}
static int constructor(java_class *c, uint32_t i) { return method(c, i, HEADER, "<init>", "(SIS)V"); }
static bc_status parse_member(const uint8_t *data, uint32_t length, const char *owner,
    const char *field_name, const char *method_name, const char *method_desc, uint32_t field_access, java_class *c) {
    reader r = {data, length, 0, 0};
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > 1024 * 1024) return BC_LIMIT_EXCEEDED;
    if (number(&r, 4) != 0xcafebabeu) return BC_PROTOCOL_ERROR;
    (void)number(&r, 2); uint32_t major = number(&r, 2);
    if (major < 45 || major > 65) return BC_UNSUPPORTED;
    c->count = number(&r, 2);
    if (!c->count || c->count > 8192) return BC_LIMIT_EXCEEDED;
    c->cp = calloc(c->count, sizeof(*c->cp)); if (!c->cp) return BC_NO_MEMORY;
    for (uint32_t i = 1; i < c->count && !r.bad; ++i) {
        constant *v = &c->cp[i]; v->tag = (uint8_t)number(&r, 1);
        switch (v->tag) {
        case 1: v->length = (uint16_t)number(&r, 2); v->text = take(&r, v->length); break;
        case 3: case 4: v->integer = number(&r, 4); break;
        case 5: case 6: v->wide = (uint64_t)number(&r,4) << 32; v->wide |= number(&r,4);
            if (++i == c->count) r.bad = 1; break;
        case 7: case 8: case 16: case 19: case 20: v->a = (uint16_t)number(&r, 2); break;
        case 9: case 10: case 11: case 12: case 17: case 18:
            v->a = (uint16_t)number(&r, 2); v->b = (uint16_t)number(&r, 2); break;
        case 15: number(&r, 1); number(&r, 2); break;
        default: r.bad = 1; break;
        }
    }
    number(&r, 2); uint32_t self = number(&r, 2); c->super_index = number(&r, 2);
    if (r.bad) return BC_PROTOCOL_ERROR;
    if (!class_name(c, self, owner)) return BC_UNSUPPORTED;
    uint32_t interfaces = number(&r, 2); take(&r, interfaces * 2);
    unsigned packet_fields = 0, methods = 0;
    for (unsigned group = 0; group < 3 && !r.bad; ++group) {
        uint32_t count = group == 2 ? 1 : number(&r, 2);
        if (count > 4096) return BC_LIMIT_EXCEEDED;
        for (uint32_t i = 0; i < count && !r.bad; ++i) {
            uint32_t access = 0, name = 0, desc = 0;
            if (group != 2) { access = number(&r, 2); name = number(&r, 2); desc = number(&r, 2); }
            int packet = group == 0 && field_name && text(c, name, field_name);
            int method = group == 1 && text(c, name, method_name) && text(c, desc, method_desc);
            if (packet) {
                uint32_t kind = text(c,desc,"I") ? 1u : text(c,desc,"S") ? 2u : text(c,desc,"Z") ? 3u : 0u;
                if (++packet_fields != 1 || !kind || (kind == 3 && field_access != 8) ||
                    (access & field_access) != field_access || (field_access == 8 && ((access & 16) || kind == 2))) return BC_UNSUPPORTED;
                c->field_kind = kind;
            }
            if (method && ++methods != 1) return BC_PROTOCOL_ERROR;
            if (method) c->method_access = access;
            if (method && field_access == 8 && !(access & 8)) return BC_UNSUPPORTED;
            uint32_t attrs = number(&r, 2), constants = 0;
            if (attrs > 128) return BC_LIMIT_EXCEEDED;
            for (uint32_t j = 0; j < attrs && !r.bad; ++j) {
                uint32_t key = number(&r, 2), size = number(&r, 4); const uint8_t *value = take(&r, size);
                if (r.bad) break;
                if (packet && text(c, key, "ConstantValue")) {
                    if (++constants != 1 || size != 2) return BC_PROTOCOL_ERROR;
                    uint32_t index = ((uint32_t)value[0] << 8) | value[1];
                    if (!index || index >= c->count || c->cp[index].tag != 3) return BC_PROTOCOL_ERROR;
                    c->packet_size = c->cp[index].integer;
                }
                if (method && text(c, key, "Code")) {
                    if (c->code || size < 12) return BC_PROTOCOL_ERROR;
                    reader code = {value, size, 0, 0}; number(&code, 2); number(&code, 2);
                    c->code_length = number(&code, 4); c->code = take(&code, c->code_length);
                    if (code.bad || !c->code_length || c->code_length > 65535) return BC_PROTOCOL_ERROR;
                    c->exception_count = number(&code, 2);
                    if (c->exception_count && (strcmp(owner, APP) || strcmp(method_name, "OnsendWebsessionToken") ||
                        c->exception_count > 8)) return BC_UNSUPPORTED;
                    c->exceptions = take(&code, c->exception_count * 8);
                    uint32_t nested = number(&code, 2);
                    for (uint32_t k = 0; k < nested && !code.bad; ++k) {
                        number(&code, 2); uint32_t bytes = number(&code, 4); take(&code, bytes);
                    }
                    if (code.bad || code.at != code.n) return BC_PROTOCOL_ERROR;
                }
            }
        }
    }
    c->field_count = packet_fields; c->method_count = methods;
    return r.bad || r.at != r.n ? BC_PROTOCOL_ERROR : BC_OK;
}
static bc_status parse(const uint8_t *data, uint32_t length, const char *owner, java_class *c) {
    return parse_member(data, length, owner, "VIDEO_PACKET_SIZE", "OnsendWebsessionToken", "()I", 0x18, c);
}
static int64_t branch_offset(const uint8_t *code, uint32_t width) {
    int64_t offset = 0;
    for (uint32_t i = 1; i < width; ++i) offset = (offset << 8) | code[i];
    if (width == 3 && offset >= 32768) offset -= 65536;
    if (width == 5 && offset >= INT64_C(2147483648)) offset -= INT64_C(4294967296);
    return offset;
}
static bc_status sends_validation(java_class *c, const uint32_t *widths, const uint8_t *flags) {
    uint32_t n = c->code_length, head = 0, tail = 1;
    uint8_t *seen = calloc(n, 1); uint32_t *queue = malloc((size_t)n * 5 * sizeof(*queue));
    if (!seen || !queue) { free(seen); free(queue); return BC_NO_MEMORY; }
    seen[0] = 1; queue[0] = 0; bc_status status = BC_UNSUPPORTED;
    while (head < tail) {
        uint32_t entry = queue[head++], p = entry / 5, stage = entry % 5;
        uint8_t op = c->code[p]; uint32_t width = widths[p];
        if (flags[p] & 4) stage = 1;
        if (op == 182) {
            uint32_t index = ((uint32_t)c->code[p + 1] << 8) | c->code[p + 2];
            if (stage == 1 && method(c,index,HEADER,"array","()[B")) stage = 2;
            else if (stage == 2 && method(c,index,"java/nio/ByteBuffer","put","([B)Ljava/nio/ByteBuffer;")) stage = 3;
            else if (stage == 3 && method(c,index,"java/nio/ByteBuffer","get","([B)Ljava/nio/ByteBuffer;")) stage = 4;
            else if (stage == 4 && method(c,index,"com/ami/kvm/jviewer/kvmpkts/KVMClient","sendMessage","([BI)I")) {
                status = BC_OK; break;
            }
        }
        uint32_t next[2], count = 0;
        if ((op >= 153 && op <= 167) || op == 198 || op == 199 || op == 200)
            next[count++] = (uint32_t)((int64_t)p + branch_offset(c->code + p, width));
        if (op != 167 && op != 200 && !(op >= 172 && op <= 177) && op != 191 && p + width < n)
            next[count++] = p + width;
        for (uint32_t i = 0; i < count; ++i) if (!(seen[next[i]] & (1u << stage))) {
            seen[next[i]] |= (uint8_t)(1u << stage); queue[tail++] = next[i] * 5 + stage;
        }
    }
    free(queue); free(seen); return status;
}
static int failure_handler(java_class *c, uint32_t p) {
    const uint8_t *code = c->code; uint32_t n = c->code_length;
    if (p >= n) return 0;
    if (code[p] == 58) p += 2;
    else if (code[p] >= 75 && code[p] <= 78) ++p;
    else return 0;
    if (p < n && code[p] == 178) {
        if (n - p < 3) return 0;
        uint32_t field = ((uint32_t)code[p + 1] << 8) | code[p + 2]; p += 3;
        if (!field || field >= c->count || c->cp[field].tag != 9 ||
            !class_name(c, c->cp[field].a, "com/ami/kvm/jviewer/Debug")) return 0;
        uint32_t name = c->cp[field].b;
        if (!name || name >= c->count || c->cp[name].tag != 12 || !text(c, c->cp[name].a, "out") ||
            !text(c, c->cp[name].b, "Lcom/ami/kvm/jviewer/Debug;")) return 0;
        if (p >= n || (code[p] != 18 && code[p] != 19)) return 0;
        uint32_t width = code[p] == 18 ? 2 : 3;
        if (n - p < width) return 0;
        uint32_t literal = code[p + 1]; if (width == 3) literal = (literal << 8) | code[p + 2];
        if (!literal || literal >= c->count || c->cp[literal].tag != 8) return 0;
        p += width;
        if (n - p < 3 || code[p] != 182 || !method(c, ((uint32_t)code[p + 1] << 8) | code[p + 2],
            "com/ami/kvm/jviewer/Debug", "println", "(Ljava/lang/Object;)V")) return 0;
        p += 3;
    }
    return p < n && n - p >= 2 && code[p] == 2 && code[p + 1] == 172;
}

static bc_status graph(java_class *c, uint32_t **width_out, uint8_t **flag_out) {
    const uint8_t *code = c->code; uint32_t n = c->code_length;
    *width_out = NULL; *flag_out = NULL;
    if (!code) return BC_UNSUPPORTED;
    uint8_t *targets = calloc(n, 1); if (!targets) return BC_NO_MEMORY;
    uint32_t *widths = calloc(n, sizeof(*widths)); if (!widths) { free(targets); return BC_NO_MEMORY; }
    bc_status status = BC_UNSUPPORTED;
    for (uint32_t p = 0; p < n;) {
        uint8_t op = code[p]; uint32_t width = 1;
        if (op == 16 || op == 18 || (op >= 21 && op <= 25) || (op >= 54 && op <= 58) || op == 169 || op == 188) width = 2;
        if (op == 17 || op == 19 || op == 20 || op == 132 || (op >= 153 && op <= 168) ||
            (op >= 178 && op <= 184) || op == 187 || op == 189 || op == 192 || op == 193 || op == 198 || op == 199) width = 3;
        if (op == 185 || op == 186 || op == 200 || op == 201) width = 5;
        if (op == 197) width = 4;
        if (op == 170 || op == 171 || op == 196 || op > 201) goto done;
        if (width > n - p) { status = BC_PROTOCOL_ERROR; goto done; }
        widths[p] = width;
        if ((op >= 153 && op <= 168) || op == 198 || op == 199 || op == 200 || op == 201) {
            int64_t offset = 0;
            for (uint32_t i = 1; i < width; ++i) offset = (offset << 8) | code[p + i];
            if (width == 3 && offset >= 32768) offset -= 65536;
            if (width == 5 && offset >= INT64_C(2147483648)) offset -= INT64_C(4294967296);
            int64_t target = (int64_t)p + offset;
            if (target < 0 || target >= n) { status = BC_PROTOCOL_ERROR; goto done; }
            targets[target] = 1;
        }
        p += width;
    }
    for (uint32_t i = 0; i < c->exception_count; ++i) {
        reader e = {c->exceptions + i * 8, 8, 0, 0};
        uint32_t start = number(&e, 2), end = number(&e, 2), handler = number(&e, 2), type = number(&e, 2);
        if (start >= end || end > n || handler >= n || !widths[start] || (end < n && !widths[end]) ||
            !widths[handler] || !type || type >= c->count || c->cp[type].tag != 7) {
            status = BC_PROTOCOL_ERROR; goto done;
        }
        /* Only terminal failure handlers are excluded from the successful send path. */
        if (!failure_handler(c, handler)) goto done;
        targets[handler] |= 1;
    }
    for (uint32_t p = 0; p < n; ++p) if (targets[p] && !widths[p]) { status = BC_PROTOCOL_ERROR; goto done; }
    uint32_t *pending = malloc((size_t)n * sizeof(*pending));
    if (!pending) { status = BC_NO_MEMORY; goto done; }
    uint32_t head = 0, tail = 1; pending[0] = 0; targets[0] |= 2;
    while (head < tail) {
        uint32_t p = pending[head++], width = widths[p]; uint8_t op = code[p];
        if (op == 168 || op == 169 || op == 201) { free(pending); goto done; }
        if ((op >= 153 && op <= 167) || op == 198 || op == 199 || op == 200) {
            int64_t offset = 0;
            for (uint32_t i = 1; i < width; ++i) offset = (offset << 8) | code[p + i];
            if (width == 3 && offset >= 32768) offset -= 65536;
            if (width == 5 && offset >= INT64_C(2147483648)) offset -= INT64_C(4294967296);
            uint32_t target = (uint32_t)((int64_t)p + offset);
            if (!(targets[target] & 2)) { targets[target] |= 2; pending[tail++] = target; }
        }
        if (op != 167 && op != 200 && !(op >= 172 && op <= 177) && op != 191 && p + width < n && !(targets[p + width] & 2)) {
            targets[p + width] |= 2; pending[tail++] = p + width;
        }
    }
    free(pending);
    *width_out = widths; *flag_out = targets;
    return BC_OK;
done:
    free(widths); free(targets); return status;
}
/* Retain integer facts only within straight-line blocks; never execute code. */
static bc_status layout(java_class *c, uint32_t expected) {
    const uint8_t *code = c->code; uint32_t n = c->code_length;
    uint32_t *widths; uint8_t *targets;
    bc_status status = graph(c, &widths, &targets);
    if (status != BC_OK) return status;
    status = BC_UNSUPPORTED;
    int64_t locals[256], stack[64]; uint32_t used = 0, found = 0;
    for (unsigned i = 0; i < 256; ++i) locals[i] = UNKNOWN;
    for (uint32_t p = 0; p < n; p += widths[p]) {
        if (!(targets[p] & 2)) continue;
        uint8_t op = code[p];
        if (targets[p] & 1) { used = 0; for (unsigned i = 0; i < 256; ++i) locals[i] = UNKNOWN; }
        int64_t push = UNKNOWN; int pushing = 0;
        if (op >= 2 && op <= 8) { push = (int)op - 3; pushing = 1; }
        else if (op == 16 || op == 17) {
            push = code[p + 1]; if (op == 17) push = (push << 8) | code[p + 2];
            if (op == 16 && push >= 128) push -= 256;
            if (op == 17 && push >= 32768) push -= 65536;
            pushing = 1;
        } else if (op == 18 || op == 19) {
            uint32_t index = code[p + 1]; if (op == 19) index = (index << 8) | code[p + 2];
            if (index && index < c->count && c->cp[index].tag == 3) push = c->cp[index].integer;
            pushing = 1;
        } else if (op == 21 || (op >= 26 && op <= 29)) {
            push = locals[op == 21 ? code[p + 1] : op - 26]; pushing = 1;
        } else if (op == 54 || (op >= 59 && op <= 62)) {
            locals[op == 54 ? code[p + 1] : op - 59] = used ? stack[--used] : UNKNOWN;
        } else if ((op >= 55 && op <= 58) || (op >= 63 && op <= 78)) {
            uint32_t index = op <= 58 ? code[p + 1] : (op - 63) % 4;
            locals[index] = UNKNOWN;
            if ((op == 55 || op == 57 || (op >= 63 && op <= 66) || (op >= 71 && op <= 74)) && index < 255)
                locals[index + 1] = UNKNOWN;
            used = 0;
        } else if (op == 187 || op == 25 || (op >= 42 && op <= 45)) pushing = 1;
        else if (op == 190 && used) stack[used - 1] = UNKNOWN;
        else if (op == 89 && used) { push = stack[used - 1]; pushing = 1; }
        else if (op == 183 && constructor(c, ((uint32_t)code[p + 1] << 8) | code[p + 2])) {
            if (used < 4 || stack[used - 3] == UNKNOWN) goto done;
            if (stack[used - 3] == 18) {
                if (stack[used - 1] != 0 || (stack[used - 2] != expected && stack[used - 2] != expected + 8)) goto done;
                ++found; targets[p] |= 4;
            }
            used = 0;
        } else {
            used = 0;
            if ((op >= 153 && op <= 177) || op == 132)
                for (unsigned i = 0; i < 256; ++i) locals[i] = UNKNOWN;
        }
        if (pushing) { if (used == 64) goto done; stack[used++] = push; }
    }
    if (found) status = sends_validation(c, widths, targets);
done:
    free(widths); free(targets); return status;
}
bc_status bc_megarac_jviewer_class_evidence(const uint8_t *header, uint32_t header_length,
    const uint8_t *app, uint32_t app_length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); java_class h = {0}, a = {0};
    bc_status status = parse(header, header_length, HEADER, &h);
    if (status == BC_OK && h.packet_size != 195 && h.packet_size != 373) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = parse(app, app_length, APP, &a);
    if (status == BC_OK) status = layout(&a, h.packet_size);
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC,
        h.packet_size == 195 ? BC_SERVICE_MEGARAC_KVM_JVIEWER_195 : BC_SERVICE_MEGARAC_KVM_JVIEWER_373,
        BC_SERVICE_EVIDENCE_HINT};
    free(h.cp); free(a.cp); return status;
}

static int initializer_field(java_class *c, uint32_t index, const char *field_name, const char *field_desc) {
    if (!index || index >= c->count || c->cp[index].tag != 9 || !class_name(c, c->cp[index].a, ENTRY)) return 0;
    uint32_t name = c->cp[index].b;
    return name && name < c->count && c->cp[name].tag == 12 &&
        text(c, c->cp[name].a, field_name) && text(c, c->cp[name].b, field_desc);
}
static bc_status token_initializer(java_class *c, const char *field_name, const char *field_desc) {
    uint32_t *widths; uint8_t *flags;
    bc_status status = graph(c, &widths, &flags);
    if (status != BC_OK) return status;
    status = BC_UNSUPPORTED;
    uint32_t writer = UINT32_MAX, previous = UINT32_MAX, returns = 0;
    for (uint32_t p = 0; p < c->code_length; p += widths[p]) {
        if (flags[p] & 2) {
            if (c->code[p] == 179 && initializer_field(c, ((uint32_t)c->code[p+1] << 8) | c->code[p+2], field_name, field_desc)) {
                if (writer != UINT32_MAX || previous == UINT32_MAX || c->code[previous] != 3 ||
                    previous + 1 != p || (flags[p] & 1)) goto done;
                writer = p;
            }
            if (c->code[p] == 177) ++returns;
        }
        previous = p;
    }
    if (writer == UINT32_MAX || !returns) goto done;
    uint8_t *seen = calloc(c->code_length, 1);
    uint32_t *pending = malloc((size_t)c->code_length * sizeof(*pending));
    if (!seen || !pending) { free(seen); free(pending); status = BC_NO_MEMORY; goto done; }
    uint32_t head = 0, tail = 1; seen[0] = 1; pending[0] = 0;
    status = BC_OK;
    while (head < tail) {
        uint32_t p = pending[head++], width = widths[p]; uint8_t op = c->code[p];
        if (p == writer) continue;
        if (op >= 172 && op <= 177) { status = BC_UNSUPPORTED; break; }
        if ((op >= 153 && op <= 167) || op == 198 || op == 199 || op == 200) {
            uint32_t target = (uint32_t)((int64_t)p + branch_offset(c->code+p, width));
            if (!seen[target]) { seen[target] = 1; pending[tail++] = target; }
        }
        if (op != 167 && op != 200 && !(op >= 172 && op <= 177) && op != 191 &&
            p + width < c->code_length && !seen[p+width]) {
            seen[p+width] = 1; pending[tail++] = p+width;
        }
    }
    free(seen); free(pending);
done:
    free(widths); free(flags); return status;
}
bc_status bc_megarac_jviewer_class_token_default(const uint8_t *data, uint32_t length, uint32_t *value) {
    if (!value) return BC_INVALID_ARGUMENT;
    *value = UINT32_MAX;
    java_class c = {0};
    bc_status status = parse_member(data, length, ENTRY, "kvmTokenType", "<clinit>", "()V", 8, &c);
    if (status == BC_OK && (c.field_count != 1 || c.field_kind != 1 || c.method_count != 1)) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = token_initializer(&c,"kvmTokenType","I");
    if (status == BC_OK) *value = 0;
    free(c.cp); return status;
}

#define MEDIA_OBJECT INT64_MAX
#define MEDIA_PAYLOAD (INT64_MAX-1)
#define MEDIA_SIGNATURE (INT64_MAX-2)
#define IUSB_HEADER "com/ami/iusb/protocol/IUSBHeader"
static int field(java_class *c, uint32_t i, const char *name, const char *desc) {
    if (!i || i >= c->count || c->cp[i].tag != 9 || !class_name(c,c->cp[i].a,IUSB_HEADER)) return 0;
    uint32_t n = c->cp[i].b;
    return n && n < c->count && c->cp[n].tag == 12 && text(c,c->cp[n].a,name) && text(c,c->cp[n].b,desc);
}
static bc_status media_header(java_class *c) {
    static const char *const names[] = {"signature","packetHeaderLen","major","minor","sequenceNumber",
        "direction","dataPacketLen","deviceType","deviceNumber","interfaceNumber","protocol"};
    static const int64_t values[] = {MEDIA_SIGNATURE,32,1,0,0,128,MEDIA_PAYLOAD,5,0,0,1};
    int64_t stack[8], locals[8]; uint32_t top = 0, assigned = 0, allocated = 0, initialized = 0;
    for (unsigned i = 0; i < 8; ++i) locals[i] = UNKNOWN;
    locals[0] = MEDIA_PAYLOAD;
    for (uint32_t p = 0; p < c->code_length;) {
        uint8_t op = c->code[p]; uint32_t width = 1, index = 0; int64_t value = UNKNOWN;
        if (op == 16 || op == 18 || op == 21 || op == 25 || op == 58) width = 2;
        if (op == 17 || op == 19 || op == 181 || op == 183 || op == 187) width = 3;
        if (width > c->code_length-p) return BC_PROTOCOL_ERROR;
        if (width == 3) index = ((uint32_t)c->code[p+1] << 8) | c->code[p+2];
        if (op >= 2 && op <= 8) value = (int64_t)op-3;
        else if (op == 9) value = 0;
        else if (op == 16 || op == 17) {
            value = op == 16 ? c->code[p+1] : index;
            if (op == 16 && value >= 128) value -= 256;
            if (op == 17 && value >= 32768) value -= 65536;
        } else if (op == 18 || op == 19) {
            if (op == 18) index = c->code[p+1];
            if (!index || index >= c->count || c->cp[index].tag != 8 || !text(c,c->cp[index].a,"IUSB    ")) return BC_UNSUPPORTED;
            value = MEDIA_SIGNATURE;
        } else if (op == 187) {
            if (allocated++ || !class_name(c,index,IUSB_HEADER)) return BC_UNSUPPORTED;
            value = MEDIA_OBJECT;
        } else if (op == 89) {
            if (!top) return BC_UNSUPPORTED;
            value = stack[top-1];
        } else if (op == 183) {
            if (!top || initialized++ || stack[--top] != MEDIA_OBJECT || !method(c,index,IUSB_HEADER,"<init>","()V")) return BC_UNSUPPORTED;
        } else if (op == 21 || op == 25 || (op >= 26 && op <= 29) || (op >= 42 && op <= 45)) {
            uint32_t local = (op == 21 || op == 25) ? c->code[p+1] : op >= 42 ? op-42u : op-26u;
            if (local >= 8 || locals[local] == UNKNOWN) return BC_UNSUPPORTED;
            value = locals[local];
        } else if (op == 58 || (op >= 75 && op <= 78)) {
            uint32_t local = op == 58 ? c->code[p+1] : op-75u;
            if (local >= 8 || !top) return BC_UNSUPPORTED;
            locals[local] = stack[--top];
        } else if (op == 133) {
            if (!top || stack[top-1] == MEDIA_OBJECT || stack[top-1] == MEDIA_SIGNATURE) return BC_UNSUPPORTED;
        } else if (op == 181) {
            if (!initialized || top < 2 || stack[top-2] != MEDIA_OBJECT) return BC_UNSUPPORTED;
            int found = 0;
            for (unsigned i = 0; i < 11; ++i) {
                const char *desc = i == 0 ? "Ljava/lang/String;" : (i == 4 || i == 6) ? "J" : "I";
                if (!field(c,index,names[i],desc)) continue;
                if ((assigned & (1u << i)) || stack[top-1] != values[i]) return BC_UNSUPPORTED;
                assigned |= 1u << i; found = 1; break;
            }
            if (!found) return BC_UNSUPPORTED;
            top -= 2;
        } else if (op == 176) {
            return p+1 == c->code_length && top == 1 && initialized && stack[0] == MEDIA_OBJECT && assigned == 2047 ? BC_OK : BC_UNSUPPORTED;
        } else return BC_UNSUPPORTED;
        if (value != UNKNOWN) {
            if (top == 8) return BC_LIMIT_EXCEEDED;
            stack[top++] = value;
        }
        p += width;
    }
    return BC_UNSUPPORTED;
}
bc_status bc_megarac_jviewer_class_media_header_hint(const uint8_t *data, uint32_t length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out)); java_class c = {0};
    bc_status status = parse_member(data,length,IUSB_HEADER,"HEADER_LEN","createCDROMHeader",
        "(I)Lcom/ami/iusb/protocol/IUSBHeader;",0x18,&c);
    if (status == BC_OK && (c.field_count != 1 || c.method_count != 1 || !(c.method_access & 8) || c.packet_size != 32)) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_header(&c);
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out),BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_MEGARAC,BC_SERVICE_MEGARAC_MEDIA_IUSB_CD,BC_SERVICE_EVIDENCE_HINT};
    free(c.cp); return status;
}

static int opcode(reader *r, uint32_t op) { return number(r,1) == op && !r->bad; }
static int local_op(reader *r, uint32_t op, uint32_t compact, uint32_t *local) {
    uint32_t actual = number(r,1);
    if (actual == op) *local = number(r,1);
    else if (actual >= compact && actual < compact+4) *local = actual-compact;
    else return 0;
    return !r->bad;
}
static int load_local(reader *r, uint32_t op, uint32_t compact, uint32_t local) {
    uint32_t actual; return local_op(r,op,compact,&actual) && actual == local;
}
static int integer_op(reader *r, java_class *c, int32_t expected) {
    uint32_t op = number(r,1), index; int64_t value;
    if (op >= 2 && op <= 8) value = (int64_t)op-3;
    else if (op == 16) { value = number(r,1); if (value >= 128) value -= 256; }
    else if (op == 17) { value = number(r,2); if (value >= 32768) value -= 65536; }
    else if (op == 18 || op == 19) {
        index = number(r,op == 18 ? 1 : 2);
        if (!index || index >= c->count || c->cp[index].tag != 3) return 0;
        value = c->cp[index].integer;
        if (value >= INT64_C(2147483648)) value -= INT64_C(4294967296);
    } else return 0;
    return !r->bad && value == expected;
}
static int call_op(reader *r, java_class *c, uint32_t op, const char *owner, const char *name, const char *desc) {
    if (!opcode(r,op)) return 0;
    return method(c,number(r,2),owner,name,desc) && !r->bad;
}
static int byte_mask(reader *r, java_class *c) { return integer_op(r,c,255) && opcode(r,126); }
static int word_mask(reader *r, java_class *c) {
    if (!opcode(r,20)) return 0;
    uint32_t index = number(r,2);
    return !r->bad && index && index < c->count && c->cp[index].tag == 5 &&
        (c->cp[index].wide & UINT32_MAX) == UINT32_MAX && opcode(r,127) && opcode(r,136);
}
static int branch_op(reader *r, uint32_t op, uint32_t *target) {
    uint32_t at = r->at;
    if (!opcode(r,op)) return 0;
    int64_t offset = number(r,2); if (offset >= 32768) offset -= 65536;
    int64_t destination = (int64_t)at+offset;
    if (r->bad || destination < 0 || destination >= r->n) return 0;
    *target = (uint32_t)destination; return 1;
}
static bc_status media_serialization(java_class *c) {
    static const char *const names[] = {"signature","major","minor","packetHeaderLen","headerChecksum",
        "dataPacketLen","serverCaps","deviceType","protocol","direction","deviceNumber","interfaceNumber",
        "clientData","Instance","sequenceNumber","reserved"};
    const char *buffer = "java/nio/ByteBuffer";
    reader r = {c->code,c->code_length,0,0};
    if (!c->code) return BC_UNSUPPORTED;
    for (uint32_t i = 0; i < 16; ++i) {
        const char *desc = i == 0 ? "Ljava/lang/String;" : i == 15 ? "[B" : (i == 5 || i == 14) ? "J" : "I";
        if (!load_local(&r,25,42,1) || !load_local(&r,25,42,0) || !opcode(&r,180) ||
            !field(c,number(&r,2),names[i],desc)) return BC_UNSUPPORTED;
        const char *put_desc;
        if (i == 0 || i == 15) {
            if (i == 0 && !call_op(&r,c,182,"java/lang/String","getBytes","()[B")) return BC_UNSUPPORTED;
            put_desc = "([B)Ljava/nio/ByteBuffer;";
        } else if (i == 5 || i == 14) {
            if (!word_mask(&r,c)) return BC_UNSUPPORTED;
            put_desc = "(I)Ljava/nio/ByteBuffer;";
        } else {
            if (!byte_mask(&r,c) || !opcode(&r,145)) return BC_UNSUPPORTED;
            put_desc = "(B)Ljava/nio/ByteBuffer;";
        }
        if (!call_op(&r,c,182,buffer,(i == 5 || i == 14) ? "putInt" : "put",put_desc) || !opcode(&r,87)) return BC_UNSUPPORTED;
    }
    uint32_t sum, counter, exit, back;
    if (!integer_op(&r,c,0) || !local_op(&r,54,59,&sum) || !integer_op(&r,c,0) ||
        !local_op(&r,54,59,&counter) || sum == counter || sum < 2 || counter < 2) return BC_UNSUPPORTED;
    uint32_t condition = r.at;
    if (!load_local(&r,21,26,counter) || !load_local(&r,25,42,1) ||
        !call_op(&r,c,182,buffer,"limit","()I") || !branch_op(&r,162,&exit) ||
        !load_local(&r,21,26,sum) || !load_local(&r,25,42,1) || !load_local(&r,21,26,counter) ||
        !call_op(&r,c,182,buffer,"get","(I)B") || !byte_mask(&r,c) || !opcode(&r,96) ||
        !byte_mask(&r,c) || !load_local(&r,54,59,sum) || !opcode(&r,132) ||
        number(&r,1) != counter || number(&r,1) != 1 || !branch_op(&r,167,&back) ||
        back != condition || exit != r.at) return BC_UNSUPPORTED;
    if (!load_local(&r,25,42,1) || !integer_op(&r,c,11) || !load_local(&r,21,26,sum) ||
        !byte_mask(&r,c) || !opcode(&r,145) || !opcode(&r,116) || !opcode(&r,145) ||
        !call_op(&r,c,182,buffer,"put","(IB)Ljava/nio/ByteBuffer;") || !opcode(&r,87) ||
        !opcode(&r,177) || r.at != r.n || r.bad) return BC_UNSUPPORTED;
    return BC_OK;
}
bc_status bc_megarac_jviewer_class_media_serialization_hint(const uint8_t *data, uint32_t length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out)); java_class c = {0};
    bc_status status = parse_member(data,length,IUSB_HEADER,"HEADER_LEN","write","(Ljava/nio/ByteBuffer;)V",0x18,&c);
    if (status == BC_OK && (c.field_count != 1 || c.method_count != 1 || (c.method_access & 8) || c.packet_size != 32)) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_serialization(&c);
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out),BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_MEGARAC,BC_SERVICE_MEGARAC_MEDIA_IUSB_CD,BC_SERVICE_EVIDENCE_HINT};
    free(c.cp); return status;
}

bc_status bc_megarac_jviewer_class_media_hint(const uint8_t *data, uint32_t length,
    const uint8_t *parent, uint32_t parent_length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    java_class c = {0}, base = {0};
    const char *owner = "com/ami/iusb/protocol/RedirHeader";
    bc_status status = parse_member(data,length,IUSB_HEADER,"HEADER_LEN","<init>","()V",0x18,&c);
    if (status == BC_OK && (c.field_count != 1 || c.packet_size != 32 || c.method_count != 1 ||
        (c.method_access & 8) || !class_name(&c,c.super_index,owner))) status = BC_UNSUPPORTED;
    if (status == BC_OK) {
        reader r = {c.code,c.code_length,0,0};
        if (!c.code || !load_local(&r,25,42,0) || !call_op(&r,&c,183,owner,"<init>","()V") ||
            !load_local(&r,25,42,0) || !integer_op(&r,&c,4) || !opcode(&r,188) || !opcode(&r,8) ||
            !opcode(&r,181) || !field(&c,number(&r,2),"reserved","[B") ||
            !load_local(&r,25,42,0) || !integer_op(&r,&c,32) || !opcode(&r,181) ||
            !field(&c,number(&r,2),"headerLen","I") || !opcode(&r,177) || r.bad || r.at != r.n)
            status = BC_UNSUPPORTED;
    }
    if (status == BC_OK) status = parse_member(parent,parent_length,owner,"headerLen","<init>","()V",0,&base);
    if (status == BC_OK) {
        reader r = {base.code,base.code_length,0,0};
        if (!base.code || base.method_count != 1 || (base.method_access & 8) ||
            !class_name(&base,base.super_index,"java/lang/Object") ||
            !load_local(&r,25,42,0) || !call_op(&r,&base,183,"java/lang/Object","<init>","()V") ||
            !opcode(&r,177) || r.bad || r.at != r.n) status = BC_UNSUPPORTED;
    }
    free(c.cp); free(base.cp);
    if (status == BC_OK) status = bc_megarac_jviewer_class_media_header_hint(data,length,out);
    if (status == BC_OK) status = bc_megarac_jviewer_class_media_serialization_hint(data,length,out);
    if (status != BC_OK) memset(out,0,sizeof(*out));
    return status;
}

#define PACKET_MASTER "com/ami/iusb/protocol/PacketMaster"
#define CDROM_REDIR "com/ami/iusb/CDROMRedir"
static int field_op(reader *r, java_class *c, uint32_t op, const char *owner, const char *name, const char *desc) {
    if (!opcode(r,op)) return 0;
    uint32_t i = number(r,2);
    if (r->bad || !i || i >= c->count || c->cp[i].tag != 9 || !class_name(c,c->cp[i].a,owner)) return 0;
    uint32_t n = c->cp[i].b;
    return n && n < c->count && c->cp[n].tag == 12 && text(c,c->cp[n].a,name) && text(c,c->cp[n].b,desc);
}
static int this_field(reader *r, java_class *c, const char *owner, const char *name, const char *desc) {
    return load_local(r,25,42,0) && field_op(r,c,180,owner,name,desc);
}
static int diagnostic_tail(reader *r, java_class *c) {
    for (unsigned count = 0; count < 8 && r->at < r->n && r->p[r->at] == 178; ++count) {
        if (!field_op(r,c,178,"com/ami/kvm/jviewer/Debug","out","Lcom/ami/kvm/jviewer/Debug;")) return 0;
        uint32_t op = number(r,1);
        if (op != 18 && op != 19) return 0;
        uint32_t index = number(r,op == 18 ? 1 : 2);
        if (r->bad || !index || index >= c->count || c->cp[index].tag != 8) return 0;
        uint32_t literal = c->cp[index].a;
        if (!literal || literal >= c->count || c->cp[literal].tag != 1 ||
            !call_op(r,c,182,"com/ami/kvm/jviewer/Debug","println","(Ljava/lang/Object;)V")) return 0;
    }
    return opcode(r,177) && !r->bad && r->at == r->n;
}
static bc_status media_buffer_setup(java_class *c) {
    reader r = {c->code,c->code_length,0,0};
    if (!c->code) return BC_UNSUPPORTED;
    const char *desc = "Ljava/nio/ByteBuffer;";
    for (uint32_t i = 0; i < 4; ++i) {
        static const char *const names[] = {"netIn","netOut","appIn","appOut"};
        if (!load_local(&r,25,42,0)) return BC_UNSUPPORTED;
        if (i < 2) { if (!load_local(&r,25,42,i+1)) return BC_UNSUPPORTED; }
        else if (!this_field(&r,c,PACKET_MASTER,names[i-2],desc)) return BC_UNSUPPORTED;
        if (!field_op(&r,c,181,PACKET_MASTER,names[i],desc)) return BC_UNSUPPORTED;
    }
    for (unsigned i = 0; i < 2; ++i)
        if (!this_field(&r,c,PACKET_MASTER,i ? "netOut" : "netIn",desc) ||
            !call_op(&r,c,182,"java/nio/ByteBuffer","clear","()Ljava/nio/Buffer;") || !opcode(&r,87)) return BC_UNSUPPORTED;
    return diagnostic_tail(&r,c) ? BC_OK : BC_UNSUPPORTED;
}
static bc_status media_buffer_order(java_class *c) {
    reader r = {c->code,c->code_length,0,0};
    if (!c->code) return BC_UNSUPPORTED;
    for (unsigned i = 0; i < 2; ++i)
        if (!this_field(&r,c,PACKET_MASTER,i ? "appOut" : "appIn","Ljava/nio/ByteBuffer;") ||
            !load_local(&r,25,42,i+1) ||
            !call_op(&r,c,182,"java/nio/ByteBuffer","order","(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;") ||
            !opcode(&r,87)) return BC_UNSUPPORTED;
    return opcode(&r,177) && !r.bad && r.at == r.n ? BC_OK : BC_UNSUPPORTED;
}
static bc_status media_connect_order(java_class *c) {
    reader r = {c->code,c->code_length,0,0};
    if (!c->code || !load_local(&r,25,42,0) || !opcode(&r,187) ||
        !class_name(c,number(&r,2),PACKET_MASTER) || !opcode(&r,89) ||
        !load_local(&r,25,42,1) || !load_local(&r,21,26,2) || !integer_op(&r,c,0) ||
        !this_field(&r,c,CDROM_REDIR,"protocol","Lcom/ami/iusb/protocol/CDROMProtocol;") ||
        !load_local(&r,21,26,3) || !call_op(&r,c,183,PACKET_MASTER,"<init>","(Ljava/lang/String;IZLcom/ami/iusb/protocol/RedirProtocol;Z)V") ||
        !field_op(&r,c,181,CDROM_REDIR,"packetMaster","Lcom/ami/iusb/protocol/PacketMaster;") ||
        !this_field(&r,c,CDROM_REDIR,"packetMaster","Lcom/ami/iusb/protocol/PacketMaster;") ||
        !this_field(&r,c,CDROM_REDIR,"packetReadBuffer","Ljava/nio/ByteBuffer;") ||
        !this_field(&r,c,CDROM_REDIR,"packetWriteBuffer","Ljava/nio/ByteBuffer;") ||
        !call_op(&r,c,182,PACKET_MASTER,"setupBuffers","(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)V") ||
        !this_field(&r,c,CDROM_REDIR,"packetMaster","Lcom/ami/iusb/protocol/PacketMaster;")) return BC_UNSUPPORTED;
    for (unsigned i = 0; i < 2; ++i)
        if (!field_op(&r,c,178,"java/nio/ByteOrder","LITTLE_ENDIAN","Ljava/nio/ByteOrder;")) return BC_UNSUPPORTED;
    if (!call_op(&r,c,182,PACKET_MASTER,"setBufferEndianness","(Ljava/nio/ByteOrder;Ljava/nio/ByteOrder;)V")) return BC_UNSUPPORTED;
    uint32_t *widths; uint8_t *flags;
    bc_status status = graph(c,&widths,&flags);
    free(widths); free(flags); return status;
}
bc_status bc_megarac_jviewer_class_media_order_hint(const uint8_t *cdrom, uint32_t cdrom_length,
    const uint8_t *packet, uint32_t packet_length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out)); java_class c = {0};
    bc_status status = parse_member(packet,packet_length,PACKET_MASTER,NULL,"setupBuffers",
        "(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)V",0,&c);
    if (status == BC_OK && (c.method_count != 1 || (c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_buffer_setup(&c);
    free(c.cp); memset(&c,0,sizeof(c));
    if (status == BC_OK) status = parse_member(packet,packet_length,PACKET_MASTER,NULL,"setBufferEndianness",
        "(Ljava/nio/ByteOrder;Ljava/nio/ByteOrder;)V",0,&c);
    if (status == BC_OK && (c.method_count != 1 || (c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_buffer_order(&c);
    free(c.cp); memset(&c,0,sizeof(c));
    if (status == BC_OK) status = parse_member(cdrom,cdrom_length,CDROM_REDIR,NULL,"cdromConnect","(Ljava/lang/String;IZ)I",0,&c);
    if (status == BC_OK && (c.method_count != 1 || (c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_connect_order(&c);
    free(c.cp);
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out),BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_MEGARAC,BC_SERVICE_MEGARAC_MEDIA_IUSB_CD,BC_SERVICE_EVIDENCE_HINT};
    return status;
}

static int auth_buffer(reader *r, java_class *c) {
    return this_field(r,c,CDROM_REDIR,"packetWriteBuffer","Ljava/nio/ByteBuffer;");
}
static int auth_position(reader *r, java_class *c, int32_t position) {
    return auth_buffer(r,c) && integer_op(r,c,position) &&
        call_op(r,c,182,"java/nio/ByteBuffer","position","(I)Ljava/nio/Buffer;") && opcode(r,87);
}
static int auth_limit(reader *r, java_class *c, int32_t limit) {
    return auth_buffer(r,c) && call_op(r,c,182,"java/nio/ByteBuffer","clear","()Ljava/nio/Buffer;") && opcode(r,87) &&
        auth_buffer(r,c) && integer_op(r,c,limit) && call_op(r,c,182,"java/nio/ByteBuffer","limit","(I)Ljava/nio/Buffer;") && opcode(r,87);
}
static bc_status media_auth_construction(java_class *c) {
    reader r = {c->code,c->code_length,0,0};
    uint32_t payload, type, other, join, second_join, header, packet;
    if (!c->code || !integer_op(&r,c,0) || !local_op(&r,54,59,&payload) || payload < 2 ||
        !call_op(&r,c,184,APP,"getInstance","()Lcom/ami/kvm/jviewer/gui/JViewerApp;") ||
        !call_op(&r,c,182,APP,"getSessionTokenType","()I") || !local_op(&r,54,59,&type) ||
        type < 2 || payload == type || !load_local(&r,21,26,type) || !branch_op(&r,154,&other) ||
        !integer_op(&r,c,128) || !load_local(&r,54,59,payload) || !auth_limit(&r,c,160) ||
        !branch_op(&r,167,&join) || other != r.at || !load_local(&r,21,26,type) || !integer_op(&r,c,1) ||
        !branch_op(&r,160,&second_join) || second_join != join || !integer_op(&r,c,240) ||
        !load_local(&r,54,59,payload) || !auth_limit(&r,c,272) || join != r.at ||
        !load_local(&r,21,26,payload) || !call_op(&r,c,184,IUSB_HEADER,"createCDROMHeader","(I)Lcom/ami/iusb/protocol/IUSBHeader;") ||
        !local_op(&r,58,75,&header) || header < 2 || !load_local(&r,25,42,header) || !auth_buffer(&r,c) ||
        !call_op(&r,c,182,IUSB_HEADER,"write","(Ljava/nio/ByteBuffer;)V") || !auth_position(&r,c,41) ||
        !auth_buffer(&r,c) || !integer_op(&r,c,-14) ||
        !call_op(&r,c,182,"java/nio/ByteBuffer","put","(B)Ljava/nio/ByteBuffer;") || !opcode(&r,87) ||
        !auth_position(&r,c,62) || !auth_buffer(&r,c) || !integer_op(&r,c,0) ||
        !call_op(&r,c,182,"java/nio/ByteBuffer","put","(B)Ljava/nio/ByteBuffer;") || !opcode(&r,87) ||
        !auth_buffer(&r,c) || !load_local(&r,25,42,1) || !call_op(&r,c,182,"java/lang/String","getBytes","()[B") ||
        !call_op(&r,c,182,"java/nio/ByteBuffer","put","([B)Ljava/nio/ByteBuffer;") || !opcode(&r,87) ||
        !auth_position(&r,c,23) || !auth_buffer(&r,c) || !this_field(&r,c,CDROM_REDIR,"CDDevice_no","I") ||
        !opcode(&r,145) || !call_op(&r,c,182,"java/nio/ByteBuffer","put","(B)Ljava/nio/ByteBuffer;") ||
        !opcode(&r,87) || !auth_position(&r,c,0) || !opcode(&r,187) ||
        !class_name(c,number(&r,2),"com/ami/iusb/protocol/IUSBSCSI") || !opcode(&r,89) ||
        !auth_buffer(&r,c) || !integer_op(&r,c,1) ||
        !call_op(&r,c,183,"com/ami/iusb/protocol/IUSBSCSI","<init>","(Ljava/nio/ByteBuffer;Z)V") ||
        !local_op(&r,58,75,&packet) || packet < 2 ||
        !this_field(&r,c,CDROM_REDIR,"packetMaster","Lcom/ami/iusb/protocol/PacketMaster;") ||
        !load_local(&r,25,42,packet) || !call_op(&r,c,182,PACKET_MASTER,"sendPacket","(Lcom/ami/iusb/protocol/RedirPacket;)V") ||
        !opcode(&r,177) || r.bad || r.at != r.n) return BC_UNSUPPORTED;
    return BC_OK;
}
bc_status bc_megarac_jviewer_class_media_auth_hint(const uint8_t *data, uint32_t length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out)); java_class c = {0};
    bc_status status = parse_member(data,length,CDROM_REDIR,NULL,"SendAuth_SessionToken","(Ljava/lang/String;)V",0,&c);
    if (status == BC_OK && (c.method_count != 1 || (c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_auth_construction(&c);
    free(c.cp);
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out),BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_MEGARAC,BC_SERVICE_MEGARAC_MEDIA_IUSB_CD,BC_SERVICE_EVIDENCE_HINT};
    return status;
}

#define CONNECT_DESC "(Ljava/lang/String;ILjava/lang/String;IZZIIIBBBIIILjava/lang/String;I)V"
#define CONNECT_PRIV_DESC "(Ljava/lang/String;ILjava/lang/String;IZZIIIBBBIIIILjava/lang/String;I)V"
static bc_status media_app_token(java_class *c) {
    reader r = {c->code,c->code_length,0,0};
    if (!c->code || !load_local(&r,25,42,0) || !load_local(&r,25,42,1) ||
        !call_op(&r,c,184,ENTRY,"getServerIP","(Ljava/lang/String;)[B") ||
        !field_op(&r,c,181,APP,"m_serverIP","[B") ||
        !load_local(&r,25,42,0) || !load_local(&r,21,26,2) || !field_op(&r,c,181,APP,"m_serverPort","I") ||
        !load_local(&r,25,42,0) || !load_local(&r,25,42,3) || !field_op(&r,c,181,APP,"m_encToken","Ljava/lang/String;") ||
        !load_local(&r,25,42,0) || !load_local(&r,25,42,3) || !field_op(&r,c,181,APP,"m_session_token","Ljava/lang/String;") ||
        !load_local(&r,25,42,0) || !load_local(&r,21,26,4)) return BC_UNSUPPORTED;
    uint32_t writer = r.at;
    if (!field_op(&r,c,181,APP,"m_session_token_type","I")) return BC_UNSUPPORTED;
    uint32_t prefix_end = r.at, *widths; uint8_t *flags;
    bc_status status = graph(c,&widths,&flags);
    if (status == BC_OK) for (uint32_t p = 0; p < c->code_length; p += widths[p]) {
        if (p < prefix_end && (flags[p] & 1)) { status = BC_UNSUPPORTED; break; }
        if (p != writer && c->code[p] == 181) {
            reader member = {c->code,c->code_length,p,0};
            if (field_op(&member,c,181,APP,"m_session_token_type","I")) { status = BC_UNSUPPORTED; break; }
        }
    }
    free(widths); free(flags); return status;
}
static bc_status media_entry_token(java_class *c, int privileges) {
    static const char *const names[] = {"ip","kvmPort","kvmToken","kvmTokenType","UseSSL","VMUseSSL",
        "cdserver_port","fdserver_port","hdserver_port","Num_CD","Num_FD","Num_HD","CD_State","FD_State",
        "HD_State","webSessionToken","webSecPort"};
    static const char *const types[] = {"Ljava/lang/String;","I","Ljava/lang/String;","I","Z","Z","I","I","I",
        "B","B","B","I","I","I","Ljava/lang/String;","I"};
    reader r = {c->code,c->code_length,0,0}; uint32_t disabled, end;
    if (!c->code || (!privileges && (!call_op(&r,c,184,ENTRY,"isKVMEnabled","()Z") ||
        !branch_op(&r,153,&disabled))) ||
        !call_op(&r,c,184,APP,"getInstance","()Lcom/ami/kvm/jviewer/gui/JViewerApp;")) return BC_UNSUPPORTED;
    for (unsigned i = 0; i < 17; ++i) {
        if (privileges && i == 15 && !field_op(&r,c,178,ENTRY,"UserPrivileges","I")) return BC_UNSUPPORTED;
        if (!field_op(&r,c,178,ENTRY,names[i],types[i])) return BC_UNSUPPORTED;
    }
    if (!call_op(&r,c,182,APP,"OnConnectToServer",privileges ? CONNECT_PRIV_DESC : CONNECT_DESC) ||
        !call_op(&r,c,184,APP,"getInstance","()Lcom/ami/kvm/jviewer/gui/JViewerApp;") ||
        !call_op(&r,c,182,APP,"create_IUSBSession","()V")) return BC_UNSUPPORTED;
    if (privileges) return opcode(&r,177) && !r.bad && r.at == r.n ? BC_OK : BC_UNSUPPORTED;
    if (!branch_op(&r,167,&end) || disabled != r.at || end < disabled) return BC_UNSUPPORTED;
    uint32_t *widths; uint8_t *flags; bc_status status = graph(c,&widths,&flags);
    free(widths); free(flags); return status;
}
bc_status bc_megarac_jviewer_class_media_runtime_hint(const uint8_t *entry, uint32_t entry_length,
    const uint8_t *app, uint32_t app_length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out)); java_class c = {0};
    bc_status status = parse_member(app,app_length,APP,NULL,"getSessionTokenType","()I",0,&c);
    if (status == BC_OK) {
        reader r = {c.code,c.code_length,0,0};
        if (!c.code || c.method_count != 1 || (c.method_access & 8) ||
            !this_field(&r,&c,APP,"m_session_token_type","I") || !opcode(&r,172) || r.bad || r.at != r.n) status = BC_UNSUPPORTED;
    }
    free(c.cp); memset(&c,0,sizeof(c));
    int privileges = 0;
    if (status == BC_OK) {
        status = parse_member(app,app_length,APP,NULL,"OnConnectToServer",CONNECT_DESC,0,&c);
        if (status == BC_OK && !c.method_count) {
            free(c.cp); memset(&c,0,sizeof(c)); privileges = 1;
            status = parse_member(app,app_length,APP,NULL,"OnConnectToServer",CONNECT_PRIV_DESC,0,&c);
        }
    }
    if (status == BC_OK && (c.method_count != 1 || (c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_app_token(&c);
    free(c.cp); memset(&c,0,sizeof(c));
    if (status == BC_OK) status = parse_member(entry,entry_length,ENTRY,NULL,"redirect","()V",0,&c);
    if (status == BC_OK && (c.method_count != 1 || !(c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_entry_token(&c, privileges);
    free(c.cp);
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out),BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_MEGARAC,BC_SERVICE_MEGARAC_MEDIA_IUSB_CD,BC_SERVICE_EVIDENCE_HINT};
    return status;
}

#define IUSB_SCSI "com/ami/iusb/protocol/IUSBSCSI"
#define REDIR_HEADER "com/ami/iusb/protocol/RedirHeader"
static int class_op(reader *r, java_class *c, uint32_t op, const char *name) {
    return opcode(r,op) && class_name(c,number(r,2),name) && !r->bad;
}
static bc_status media_scsi_write(java_class *c) {
    reader r = {c->code,c->code_length,0,0}; uint32_t copy, end;
    const char *header = "Lcom/ami/iusb/protocol/RedirHeader;", *buffer = "java/nio/ByteBuffer";
    if (!c->code || !this_field(&r,c,IUSB_SCSI,"header",header) || !class_op(&r,c,192,IUSB_HEADER) ||
        !integer_op(&r,c,128) || !field_op(&r,c,181,IUSB_HEADER,"direction","I") ||
        !this_field(&r,c,IUSB_SCSI,"header",header) || !load_local(&r,25,42,1) ||
        !call_op(&r,c,182,REDIR_HEADER,"write","(Ljava/nio/ByteBuffer;)V") ||
        !this_field(&r,c,IUSB_SCSI,"preBuffered","Z") || !branch_op(&r,153,&copy) ||
        !load_local(&r,25,42,1) || !this_field(&r,c,IUSB_SCSI,"dataLen","I") || !integer_op(&r,c,32) ||
        !opcode(&r,96) || !call_op(&r,c,182,buffer,"limit","(I)Ljava/nio/Buffer;") || !opcode(&r,87) ||
        !load_local(&r,25,42,1) || !load_local(&r,25,42,1) || !call_op(&r,c,182,buffer,"limit","()I") ||
        !call_op(&r,c,182,buffer,"position","(I)Ljava/nio/Buffer;") || !opcode(&r,87) ||
        !branch_op(&r,167,&end) || copy != r.at || !load_local(&r,25,42,1) ||
        !this_field(&r,c,IUSB_SCSI,"data","Ljava/nio/ByteBuffer;") ||
        !call_op(&r,c,182,buffer,"put","(Ljava/nio/ByteBuffer;)Ljava/nio/ByteBuffer;") || !opcode(&r,87) ||
        end != r.at || !opcode(&r,177) || r.bad || r.at != r.n) return BC_UNSUPPORTED;
    return BC_OK;
}
static bc_status media_packet_send(java_class *c) {
    reader r = {c->code,c->code_length,0,0}; uint32_t array;
    const char *buffer = "java/nio/ByteBuffer", *desc = "Ljava/nio/ByteBuffer;";
    if (!c->code) return BC_UNSUPPORTED;
    for (unsigned i = 0; i < 2; ++i)
        if (!this_field(&r,c,PACKET_MASTER,i ? "netOut" : "appOut",desc) ||
            !call_op(&r,c,182,buffer,"clear","()Ljava/nio/Buffer;") || !opcode(&r,87)) return BC_UNSUPPORTED;
    if (!load_local(&r,25,42,1) || !this_field(&r,c,PACKET_MASTER,"appOut",desc) ||
        !call_op(&r,c,182,"com/ami/iusb/protocol/RedirPacket","writePacket","(Ljava/nio/ByteBuffer;)V") ||
        !this_field(&r,c,PACKET_MASTER,"appOut",desc) || !call_op(&r,c,182,buffer,"flip","()Ljava/nio/Buffer;") ||
        !opcode(&r,87) || !this_field(&r,c,PACKET_MASTER,"netOut",desc) || !call_op(&r,c,182,buffer,"remaining","()I") ||
        !opcode(&r,188) || !opcode(&r,8) || !local_op(&r,58,75,&array) || array < 2 ||
        !this_field(&r,c,PACKET_MASTER,"netOut",desc) || !load_local(&r,25,42,array) ||
        !call_op(&r,c,182,buffer,"get","([B)Ljava/nio/ByteBuffer;") || !opcode(&r,87) ||
        !load_local(&r,25,42,0) || !call_op(&r,c,182,PACKET_MASTER,"getSock","()Ljava/net/Socket;") ||
        !call_op(&r,c,182,"java/net/Socket","getOutputStream","()Ljava/io/OutputStream;") ||
        !load_local(&r,25,42,array) || !call_op(&r,c,182,"java/io/OutputStream","write","([B)V") ||
        !opcode(&r,177) || r.bad || r.at != r.n) return BC_UNSUPPORTED;
    return BC_OK;
}
bc_status bc_megarac_jviewer_class_media_send_hint(const uint8_t *scsi, uint32_t scsi_length,
    const uint8_t *master, uint32_t master_length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out)); java_class c = {0};
    bc_status status = parse_member(scsi,scsi_length,IUSB_SCSI,NULL,"writePacket","(Ljava/nio/ByteBuffer;)V",0,&c);
    if (status == BC_OK && (c.method_count != 1 || (c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_scsi_write(&c);
    free(c.cp); memset(&c,0,sizeof(c));
    if (status == BC_OK) status = parse_member(master,master_length,PACKET_MASTER,NULL,"sendPacket","(Lcom/ami/iusb/protocol/RedirPacket;)V",0,&c);
    if (status == BC_OK && (c.method_count != 1 || (c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = media_packet_send(&c);
    free(c.cp);
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out),BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_MEGARAC,BC_SERVICE_MEGARAC_MEDIA_IUSB_CD,BC_SERVICE_EVIDENCE_HINT};
    return status;
}

static int string_op(reader *r, java_class *c, const char *expected) {
    uint32_t op = number(r,1);
    if (op != 18 && op != 19) return 0;
    uint32_t index = number(r,op == 18 ? 1 : 2);
    return !r->bad && index && index < c->count && c->cp[index].tag == 8 && text(c,c->cp[index].a,expected);
}
static bc_status media_header_read(java_class *c) {
    static const char *const names[] = {"major","minor","packetHeaderLen","headerChecksum","dataPacketLen",
        "serverCaps","deviceType","protocol","direction","deviceNumber","interfaceNumber","clientData","Instance","sequenceNumber"};
    reader r = {c->code,c->code_length,0,0}; uint32_t array, valid;
    const char *buffer = "java/nio/ByteBuffer";
    if (!c->code || !integer_op(&r,c,8) || !opcode(&r,188) || !opcode(&r,8) ||
        !local_op(&r,58,75,&array) || array < 2 || !load_local(&r,25,42,1) || !load_local(&r,25,42,array) ||
        !call_op(&r,c,182,buffer,"get","([B)Ljava/nio/ByteBuffer;") || !opcode(&r,87) ||
        !load_local(&r,25,42,0) || !class_op(&r,c,187,"java/lang/String") || !opcode(&r,89) ||
        !load_local(&r,25,42,array) || !call_op(&r,c,183,"java/lang/String","<init>","([B)V") ||
        !field_op(&r,c,181,IUSB_HEADER,"signature","Ljava/lang/String;") ||
        !this_field(&r,c,IUSB_HEADER,"signature","Ljava/lang/String;") || !string_op(&r,c,"IUSB    ") ||
        !call_op(&r,c,182,"java/lang/String","equals","(Ljava/lang/Object;)Z") || !branch_op(&r,154,&valid) || valid <= r.at)
        return BC_UNSUPPORTED;
    uint32_t *widths; uint8_t *flags; bc_status status = graph(c,&widths,&flags);
    if (status == BC_OK && (!widths[valid] || !widths[valid-1] || c->code[valid-1] != 191)) status = BC_UNSUPPORTED;
    free(widths); free(flags); if (status != BC_OK) return status;
    r.at = valid;
    for (unsigned i = 0; i < 14; ++i) {
        int wide = i == 4 || i == 13;
        if (!load_local(&r,25,42,0) || !load_local(&r,25,42,1) ||
            !call_op(&r,c,182,buffer,wide ? "getInt" : "get",wide ? "()I" : "()B")) return BC_UNSUPPORTED;
        if (wide) {
            if (!opcode(&r,133) || !opcode(&r,20)) return BC_UNSUPPORTED;
            uint32_t index = number(&r,2);
            if (r.bad || !index || index >= c->count || c->cp[index].tag != 5 ||
                (c->cp[index].wide & UINT32_MAX) != UINT32_MAX || !opcode(&r,127)) return BC_UNSUPPORTED;
        } else if (!byte_mask(&r,c)) return BC_UNSUPPORTED;
        if (!field_op(&r,c,181,IUSB_HEADER,names[i],wide ? "J" : "I")) return BC_UNSUPPORTED;
    }
    if (!load_local(&r,25,42,1) || !this_field(&r,c,IUSB_HEADER,"reserved","[B") ||
        !call_op(&r,c,182,buffer,"get","([B)Ljava/nio/ByteBuffer;") || !opcode(&r,87) ||
        !opcode(&r,177) || r.bad || r.at != r.n) return BC_UNSUPPORTED;
    return BC_OK;
}
static bc_status media_scsi_construct(java_class *c) {
    reader r = {c->code,c->code_length,0,0};
    const char *parent = "com/ami/iusb/protocol/RedirPacket", *header = "Lcom/ami/iusb/protocol/RedirHeader;";
    if (!c->code || !class_name(c,c->super_index,parent) || !load_local(&r,25,42,0) ||
        !call_op(&r,c,183,parent,"<init>","()V") || !load_local(&r,25,42,0) || !integer_op(&r,c,-1) ||
        !field_op(&r,c,181,IUSB_SCSI,"connectionStatus","I") || !load_local(&r,25,42,0) ||
        !load_local(&r,21,26,2) || !field_op(&r,c,181,IUSB_SCSI,"preBuffered","Z") ||
        !load_local(&r,25,42,0) || !class_op(&r,c,187,IUSB_HEADER) || !opcode(&r,89) ||
        !call_op(&r,c,183,IUSB_HEADER,"<init>","()V") || !field_op(&r,c,181,IUSB_SCSI,"header",header) ||
        !this_field(&r,c,IUSB_SCSI,"header",header) || !load_local(&r,25,42,1) ||
        !call_op(&r,c,182,REDIR_HEADER,"read","(Ljava/nio/ByteBuffer;)V") ||
        !this_field(&r,c,IUSB_SCSI,"header",header) || !class_op(&r,c,192,IUSB_HEADER) ||
        !load_local(&r,25,42,1) || !call_op(&r,c,182,"java/nio/ByteBuffer","limit","()I") ||
        !this_field(&r,c,IUSB_SCSI,"header",header) || !field_op(&r,c,180,REDIR_HEADER,"headerLen","I") ||
        !opcode(&r,100) || !opcode(&r,133) || !field_op(&r,c,181,IUSB_HEADER,"dataPacketLen","J") ||
        !load_local(&r,25,42,0) || !this_field(&r,c,IUSB_SCSI,"header",header) || !class_op(&r,c,192,IUSB_HEADER) ||
        !field_op(&r,c,180,IUSB_HEADER,"dataPacketLen","J") || !opcode(&r,136) ||
        !field_op(&r,c,181,IUSB_SCSI,"dataLen","I") || !load_local(&r,25,42,0) || !load_local(&r,25,42,1) ||
        !call_op(&r,c,182,"java/nio/ByteBuffer","slice","()Ljava/nio/ByteBuffer;") ||
        !field_op(&r,c,181,IUSB_SCSI,"data","Ljava/nio/ByteBuffer;") || !opcode(&r,177) || r.bad || r.at != r.n)
        return BC_UNSUPPORTED;
    return BC_OK;
}
static bc_status media_packet_construct(java_class *c) {
    reader r = {c->code,c->code_length,0,0};
    return c->code && class_name(c,c->super_index,"java/lang/Object") && load_local(&r,25,42,0) &&
        call_op(&r,c,183,"java/lang/Object","<init>","()V") && load_local(&r,25,42,0) && integer_op(&r,c,0) &&
        field_op(&r,c,181,"com/ami/iusb/protocol/RedirPacket","encrypted","Z") && opcode(&r,177) && !r.bad && r.at == r.n ? BC_OK : BC_UNSUPPORTED;
}
static bc_status media_instance_method(const uint8_t *data, uint32_t length, const char *owner, const char *name,
    const char *desc, bc_status (*inspect)(java_class *)) {
    java_class c = {0}; bc_status status = parse_member(data,length,owner,NULL,name,desc,0,&c);
    if (status == BC_OK && (c.method_count != 1 || (c.method_access & 8))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = inspect(&c);
    free(c.cp); return status;
}
bc_status bc_megarac_jviewer_class_media_state_hint(const uint8_t *header, uint32_t header_length,
    const uint8_t *scsi, uint32_t scsi_length, const uint8_t *parent, uint32_t parent_length, bc_service_profile *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    bc_status status = media_instance_method(header,header_length,IUSB_HEADER,"read","(Ljava/nio/ByteBuffer;)V",media_header_read);
    if (status == BC_OK) status = media_instance_method(scsi,scsi_length,IUSB_SCSI,"<init>","(Ljava/nio/ByteBuffer;Z)V",media_scsi_construct);
    if (status == BC_OK) status = media_instance_method(parent,parent_length,"com/ami/iusb/protocol/RedirPacket","<init>","()V",media_packet_construct);
    if (status == BC_OK) *out = (bc_service_profile){sizeof(*out),BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_MEGARAC,BC_SERVICE_MEGARAC_MEDIA_IUSB_CD,BC_SERVICE_EVIDENCE_HINT};
    return status;
}

bc_status bc_megarac_jviewer_class_single_port_default(const uint8_t *data, uint32_t length, uint32_t *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = UINT32_MAX; java_class c = {0};
    bc_status status = parse_member(data,length,ENTRY,"isSinglePortEnabled","<clinit>","()V",8,&c);
    if (status == BC_OK && (c.field_count != 1 || c.field_kind != 3 || c.method_count != 1)) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = token_initializer(&c,"isSinglePortEnabled","Z");
    free(c.cp); memset(&c,0,sizeof(c));
    if (status == BC_OK) status = parse_member(data,length,ENTRY,NULL,"isSinglePortEnabled","()Z",0,&c);
    if (status == BC_OK) {
        reader r = {c.code,c.code_length,0,0};
        if (!c.code || c.method_count != 1 || !(c.method_access & 8) ||
            !field_op(&r,&c,178,ENTRY,"isSinglePortEnabled","Z") || !opcode(&r,172) || r.bad || r.at != r.n) status = BC_UNSUPPORTED;
    }
    free(c.cp); if (status == BC_OK) *out = 0;
    return status;
}

#include "web_internal.h"
#include "../launch_xml.h"
#include <stdlib.h>
#include <string.h>
typedef struct {
    bc_avocent_web_reply reply;
    uint32_t field, used, depth;
    char value[1025];
} document;
static bc_status event(void *user, enum bc_launch_xml_event kind, uint32_t depth,
    const char *name, const char *data) {
    document *d = user;
    if (kind == BC_XML_START) {
        if (depth == 1 && strcmp(name, "root")) return BC_PROTOCOL_ERROR;
        if (d->field) return BC_PROTOCOL_ERROR;
        uint32_t field = !strcmp(name, "status") ? 1u : !strcmp(name, "authResult") ? 2u : !strcmp(name, "forwardUrl") ? 4u : 0;
        if (field) {
            if (depth != 2 || (d->reply.fields & field)) return BC_PROTOCOL_ERROR;
            d->reply.fields |= field; d->field = field; d->depth = depth;
            d->used = 0; d->value[0] = 0;
        }
    } else if (kind == BC_XML_CONTENT && d->field) {
        return bc_launch_append(d->value, &d->used, sizeof(d->value), data);
    } else if (kind == BC_XML_END && d->field && depth == d->depth) {
        bc_status status = BC_OK;
        if (d->field == 4) strcpy(d->reply.forward, d->value);
        else status = bc_launch_number(d->value, 65535, d->field == 1 ? &d->reply.status : &d->reply.auth_result);
        d->field = 0; return status;
    }
    return BC_OK;
}
bc_status bc_avocent_web_parse(bc_bytes body, int login, bc_avocent_web_reply *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (body.length > 65536) return BC_LIMIT_EXCEEDED;
    document d = {0};
    bc_status status = bc_launch_xml_parse(body.data, (uint32_t)body.length, event, &d);
    if (status == BC_OK && ((d.reply.fields & 1u) == 0 || (login && !(d.reply.fields & 2u)))) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) *out = d.reply;
    volatile unsigned char *p = (volatile unsigned char *)&d;
    for (size_t i = 0; i < sizeof(d); ++i) p[i] = 0;
    return status;
}
char *bc_avocent_web_password(bc_string value) {
    if (!value.data || !value.length || value.length > 1024) return NULL;
    char *out = malloc((size_t)value.length * 2 + 1);
    if (!out) return NULL;
    size_t used = 0;
    for (uint64_t i = 0; i < value.length; ++i) {
        char c = value.data[i];
        if (strchr("\\:,()=&?", c) != NULL) out[used++] = '\\';
        out[used++] = c;
    }
    out[used] = 0; return out;
}

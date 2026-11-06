#include "bcontrol/avocent.h"
#include "launch_xml.h"
#include <string.h>
typedef struct {
    bc_avocent_launch launch;
    char main_class[96], argument[1024];
    uint32_t class_length, argument_length, app_depth, arg_depth, apps, seen;
    int capture_class;
} document;
static bc_status argument(document *d) {
    char *value = strchr(d->argument, '=');
    if (!value) return BC_PROTOCOL_ERROR;
    *value++ = 0;
    const char *names[] = {"ip", "user", "passwd", "password", "kmport", "vport", "port", "apcp"};
    for (uint32_t i = 0; i < 8; ++i) {
        if (strcmp(d->argument, names[i])) continue;
        if (d->seen & (1u << i)) return BC_PROTOCOL_ERROR;
        d->seen |= 1u << i;
        if (i >= 4) {
            uint32_t n;
            if (bc_launch_number(value, i == 7 ? 1 : 65535, &n) != BC_OK || (i != 7 && !n))
                return BC_PROTOCOL_ERROR;
            if (i == 5) d->launch.video_port = n;
            else if (i == 7) d->launch.apcp = n;
            else d->launch.port = n;
        } else {
            size_t n = strlen(value), cap = i == 0 ? sizeof(d->launch.host) : sizeof(d->launch.username);
            if (!n || n >= cap) return BC_PROTOCOL_ERROR;
            for (size_t j = 0; j < n; ++j) {
                unsigned char c = (unsigned char)value[j];
                if (c < 32 || c == 127 || (i == 0 && (c <= 32 || strchr("/@?#\\", c)))) return BC_PROTOCOL_ERROR;
            }
            memcpy(i == 0 ? d->launch.host : i == 1 ? d->launch.username : d->launch.password, value, n + 1);
        }
        break;
    }
    return BC_OK;
}
static bc_status event(void *user, enum bc_launch_xml_event kind, uint32_t depth,
    const char *name, const char *data) {
    document *d = user;
    switch (kind) {
    case BC_XML_START:
        if (d->arg_depth || (depth == 1 && strcmp(name, "jnlp"))) return BC_PROTOCOL_ERROR;
        if (!strcmp(name, "application-desc")) {
            if (depth != 2 || ++d->apps != 1) return BC_PROTOCOL_ERROR;
            d->app_depth = depth;
        } else if (!strcmp(name, "argument")) {
            if (!d->app_depth || depth != d->app_depth + 1) return BC_PROTOCOL_ERROR;
            d->arg_depth = depth; d->argument_length = 0; d->argument[0] = 0;
        }
        break;
    case BC_XML_ATTRIBUTE:
        d->capture_class = d->app_depth && depth == d->app_depth && !strcmp(name, "main-class");
        break;
    case BC_XML_ATTRIBUTE_VALUE:
        if (d->capture_class) return bc_launch_append(d->main_class, &d->class_length, sizeof(d->main_class), data);
        break;
    case BC_XML_ATTRIBUTE_END: d->capture_class = 0; break;
    case BC_XML_CONTENT:
        if (d->arg_depth) return bc_launch_append(d->argument, &d->argument_length, sizeof(d->argument), data);
        break;
    case BC_XML_END:
        if (d->arg_depth == depth) {
            d->arg_depth = 0; bc_status status = argument(d); if (status != BC_OK) return status;
        }
        if (d->app_depth == depth) d->app_depth = 0;
        break;
    }
    return BC_OK;
}
bc_status bc_avocent_launch_parse(const uint8_t *data, uint32_t length, bc_avocent_launch *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    document d = {0};
    bc_status status = bc_launch_xml_parse(data, length, event, &d);
    uint32_t required = 0, forbidden = 0;
    if (status == BC_OK) {
        if (!strcmp(d.main_class, "com.avocent.kvm.client.Main")) {
            d.launch.service = BC_AVOCENT_CONTROL;
            required = 1u | 2u | 4u | 16u | 32u | 128u; forbidden = 8u | 64u;
        } else if (!strcmp(d.main_class, "com.avocent.vm.VirtualMedia")) {
            d.launch.service = BC_AVOCENT_MEDIA;
            required = 1u | 2u | 8u | 64u; forbidden = 4u | 16u | 32u | 128u;
        } else status = BC_UNSUPPORTED;
    }
    if (status == BC_OK && (d.apps != 1 || (d.seen & required) != required || (d.seen & forbidden)))
        status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) { d.launch.struct_size = sizeof(d.launch); *out = d.launch; }
    volatile uint8_t *p = (volatile uint8_t *)&d;
    for (size_t i = 0; i < sizeof(d); ++i) p[i] = 0;
    return status;
}

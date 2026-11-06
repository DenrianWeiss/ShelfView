#include "megarac.h"
#include "launch_xml.h"
#include "jar.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    bc_megarac_kvm_info info;
    bc_megarac_media_parameters media;
    bc_status media_status, token_status;
    char name[BC_MEGARAC_MAX_TOKEN], value[BC_MEGARAC_MAX_TOKEN];
    uint32_t seen, length, count, cd_state;
    int awaiting_value;
} launch_args;

static bc_status argument(launch_args *args) {
    if (++args->count > 128) return BC_LIMIT_EXCEEDED;
    if (!args->awaiting_value) {
        if (args->value[0] != '-') return BC_PROTOCOL_ERROR;
        strcpy(args->name, args->value); args->awaiting_value = 1;
        return BC_OK;
    }
    args->awaiting_value = 0;
    if (!strcmp(args->name, "-cdstate")) {
        if ((args->seen & (1u << 6)) || bc_launch_number(args->value, 255, &args->cd_state) != BC_OK)
            args->media_status = BC_PROTOCOL_ERROR;
        args->seen |= 1u << 6;
    }
    static const char *const media_names[] = {"-kvmtokentype", "-vmsecure", "-cdport", "-cdnum"};
    uint32_t *media_values[] = {&args->media.token_type, &args->media.secure, &args->media.port, &args->media.devices};
    for (uint32_t i = 0; i < 4; ++i) {
        if (strcmp(args->name, media_names[i])) continue;
        bc_status status = args->media.flags & (1u << i) ? BC_PROTOCOL_ERROR :
            bc_launch_number(args->value, i == 1 ? 1 : i == 2 ? 65535 : 255, media_values[i]);
        args->media.flags |= 1u << i;
        if (status != BC_OK || (i == 2 && !args->media.port)) args->media_status = BC_PROTOCOL_ERROR;
        if (i == 0 && status != BC_OK) args->token_status = BC_PROTOCOL_ERROR;
        break;
    }
    static const char *const names[] = {"-hostname", "-kvmtoken", "-webcookie", "-kvmport",
        "-kvmsecure", "-singleportenabled"};
    for (uint32_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (strcmp(args->name, names[i])) continue;
        if (args->seen & (1u << i)) return BC_PROTOCOL_ERROR;
        args->seen |= 1u << i;
        if (i >= 3) {
            uint32_t *out = i == 3 ? &args->info.port : i == 4 ? &args->info.secure : &args->info.single_port;
            bc_status status = bc_launch_number(args->value, i == 3 ? 65535 : 1, out);
            if (status != BC_OK || (i == 3 && !*out)) return BC_PROTOCOL_ERROR;
        } else {
            char *out = i == 0 ? args->info.host : i == 1 ? args->info.token : args->info.cookie;
            size_t capacity = i == 0 ? sizeof(args->info.host) : i == 1 ? 129 : sizeof(args->info.cookie);
            if (!args->length || args->length >= capacity) return BC_PROTOCOL_ERROR;
            for (uint32_t j = 0; j < args->length; ++j)
                if ((unsigned char)args->value[j] < 33 || (unsigned char)args->value[j] > 126) return BC_PROTOCOL_ERROR;
            memcpy(out, args->value, args->length + 1);
        }
        break;
    }
    return BC_OK;
}
typedef struct {
    launch_args args;
    uint32_t app_depth, arg_depth, apps, class_length;
    char main_class[128];
    int capture_class;
} launch_document;

static bc_status launch_event(void *user, enum bc_launch_xml_event event,
    uint32_t depth, const char *name, const char *data) {
    launch_document *doc = user;
    switch (event) {
    case BC_XML_START:
        if (doc->arg_depth || (depth == 1 && strcmp(name, "jnlp"))) return BC_PROTOCOL_ERROR;
        if (!strcmp(name, "application-desc")) {
            if (depth != 2 || ++doc->apps != 1) return BC_PROTOCOL_ERROR;
            doc->app_depth = depth;
        } else if (!strcmp(name, "argument")) {
            if (!doc->app_depth || depth != doc->app_depth + 1) return BC_PROTOCOL_ERROR;
            doc->arg_depth = depth; doc->args.length = 0; doc->args.value[0] = 0;
        }
        break;
    case BC_XML_ATTRIBUTE:
        doc->capture_class = depth == doc->app_depth && doc->app_depth && !strcmp(name, "main-class");
        break;
    case BC_XML_ATTRIBUTE_VALUE:
        if (doc->capture_class)
            return bc_launch_append(doc->main_class, &doc->class_length, sizeof(doc->main_class), data);
        break;
    case BC_XML_ATTRIBUTE_END: doc->capture_class = 0; break;
    case BC_XML_CONTENT:
        if (doc->arg_depth)
            return bc_launch_append(doc->args.value, &doc->args.length, sizeof(doc->args.value), data);
        break;
    case BC_XML_END:
        if (doc->arg_depth == depth) {
            bc_status status = argument(&doc->args); doc->arg_depth = 0;
            if (status != BC_OK) return status;
        }
        if (doc->app_depth == depth) doc->app_depth = 0;
        break;
    }
    return BC_OK;
}

bc_status bc_megarac_discover_jnlp(const uint8_t *data, uint32_t length,
    bc_megarac_kvm_info *out, bc_service_profile *profile) {
    if (!out || !profile) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    *profile = (bc_service_profile){sizeof(*profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC, 0, 0};
    launch_document doc = {0};
    bc_status status = bc_launch_xml_parse(data, length, launch_event, &doc);
    const uint32_t required = (1u << 0) | (1u << 1) | (1u << 3) | (1u << 4);
    if (status == BC_OK && (doc.apps != 1 || doc.args.awaiting_value ||
        (doc.args.seen & required) != required)) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK && doc.main_class[0] && strcmp(doc.main_class, "com.ami.kvm.jviewer.JViewer"))
        status = BC_UNSUPPORTED;
    if (status == BC_OK && doc.args.token_status != BC_OK) status = doc.args.token_status;
    if (status == BC_OK && (doc.args.media.flags & BC_MEGARAC_MEDIA_TOKEN_TYPE_PRESENT) && doc.args.media.token_type != 0)
        status = BC_UNSUPPORTED;
    if (status == BC_OK) {
        doc.args.info.struct_size = sizeof(doc.args.info); *out = doc.args.info;
        profile->evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR;
    }
    volatile uint8_t *secret = (volatile uint8_t *)&doc;
    for (size_t i = 0; i < sizeof(doc); ++i) secret[i] = 0;
    return status;
}

static int manifest_main_class(bc_bytes jar) {
#ifdef BC_MEGARAC_ZLIB
    if (jar.length > 16u * 1024u * 1024u) return 0;
    const char *const paths[] = {"META-INF/MANIFEST.MF"};
    bc_jar_entry entry = {0}; int match = 0;
    if (bc_jar_extract(jar.data, (uint32_t)jar.length, paths, 1, &entry) == BC_OK) {
        const char *p = (const char *)entry.data, *end = p + entry.length;
        static const char main_class[] = "Main-Class: com.ami.kvm.jviewer.JViewer";
        while (p < end) {
            const char *next = memchr(p, '\n', (size_t)(end - p));
            if (!next) break;
            size_t n = (size_t)(next - p);
            if (n && p[n - 1] == '\r') --n;
            if (!n) break;
            if (n >= 11 && !memcmp(p, "Main-Class:", 11)) {
                if (match || n != sizeof(main_class) - 1 || memcmp(p, main_class, n) ||
                    (next + 1 < end && next[1] == ' ')) { match = 0; break; }
                match = 1;
            }
            p = next + 1;
        }
    }
    free(entry.data); return match;
#else
    (void)jar; return 0;
#endif
}
bc_status bc_megarac_jviewer_media_parameters_with_jar(const uint8_t *data, uint32_t length, bc_bytes jar, bc_megarac_media_parameters *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    launch_document doc = {0};
    bc_status status = bc_launch_xml_parse(data, length, launch_event, &doc);
    if (status == BC_OK && (doc.apps != 1 || doc.args.awaiting_value)) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK && (doc.main_class[0] ? strcmp(doc.main_class, "com.ami.kvm.jviewer.JViewer") != 0 :
        !jar.data || !manifest_main_class(jar))) status = BC_UNSUPPORTED;
    if (status == BC_OK) status = doc.args.media_status;
    if (status == BC_OK) {
        doc.args.media.struct_size = sizeof(doc.args.media);
        doc.args.media.single_port = doc.args.info.single_port;
        if ((doc.args.seen & (1u << 6)) && !doc.args.cd_state) doc.args.media.devices = 0;
        if (doc.args.seen & (1u << 5)) doc.args.media.flags |= BC_MEGARAC_MEDIA_SINGLE_PORT_PRESENT;
        *out = doc.args.media;
    }
    volatile uint8_t *secret = (volatile uint8_t *)&doc;
    for (size_t i = 0; i < sizeof(doc); ++i) secret[i] = 0;
    return status;
}
bc_status bc_megarac_jviewer_media_parameters(const uint8_t *data, uint32_t length, bc_megarac_media_parameters *out) {
    return bc_megarac_jviewer_media_parameters_with_jar(data, length, (bc_bytes){0}, out);
}

int bc_megarac_media_parameters_transport_usable(const bc_megarac_media_parameters *p) {
    if (p && p->struct_size == sizeof(*p) && p->flags == (BC_MEGARAC_MEDIA_WEBSOCKET | BC_MEGARAC_MEDIA_DEVICES_PRESENT))
        return p->devices > 0 && p->devices <= 255 && p->single_port == 1 && !p->token_type && !p->port;
    uint32_t required = BC_MEGARAC_MEDIA_SECURE_PRESENT | BC_MEGARAC_MEDIA_PORT_PRESENT | BC_MEGARAC_MEDIA_DEVICES_PRESENT;
    return p && p->struct_size == sizeof(*p) && !(p->flags & ~127u) && (p->flags & required) == required &&
        (p->flags & (BC_MEGARAC_MEDIA_TOKEN_TYPE_PRESENT | BC_MEGARAC_MEDIA_TOKEN_TYPE_RESOURCE_DEFAULT)) && !p->token_type && (p->flags & (BC_MEGARAC_MEDIA_SINGLE_PORT_PRESENT | BC_MEGARAC_MEDIA_SINGLE_PORT_RESOURCE_DEFAULT)) && p->secure <= 1 && p->port && p->port <= 65535 && p->devices && p->devices <= 255 && !p->single_port;
}

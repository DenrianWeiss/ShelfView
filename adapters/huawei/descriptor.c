#include "bcontrol/huawei_kvm.h"
#include "launch_xml.h"
#include <string.h>

typedef struct {
    bc_huawei_kvm_params params;
    uint32_t app_depth, param_depth, apps, count, seen;
    uint32_t name_length, value_length, attributes, capture;
    char name[64], value[256];
} huawei_launch;

static bc_status parameter(huawei_launch *doc) {
    static const char *const names[] = {"IPA", "port", "verifyValue", "decrykey",
        "verifyValueExt", "vmmPort", "privilege", "compress", "title"};
    if (++doc->count > 128) return BC_LIMIT_EXCEEDED;
    if (doc->attributes != 3 || !doc->name[0]) return BC_PROTOCOL_ERROR;
    for (uint32_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (strcmp(doc->name, names[i])) continue;
        if (doc->seen & (1u << i)) return BC_PROTOCOL_ERROR;
        doc->seen |= 1u << i;
        if (i == 1 || (i >= 5 && i <= 7)) {
            uint32_t value = 0;
            bc_status status = bc_launch_number(doc->value, i == 1 || i == 5 ? 65535 : UINT32_MAX, &value);
            if (status != BC_OK || ((i == 1 || i == 5) && !value)) return BC_PROTOCOL_ERROR;
            if (i == 1) doc->params.port = (uint16_t)value;
            else if (i == 5) doc->params.vmm_port = (uint16_t)value;
            else if (i == 6) doc->params.privilege = value;
            else doc->params.compress = value;
        } else {
            char *out; size_t capacity;
            switch (i) {
            case 0: out = doc->params.host; capacity = sizeof(doc->params.host); break;
            case 2: out = doc->params.verify_value; capacity = sizeof(doc->params.verify_value); break;
            case 3: out = doc->params.decrykey; capacity = sizeof(doc->params.decrykey); break;
            case 4: out = doc->params.verify_value_ext; capacity = sizeof(doc->params.verify_value_ext); break;
            default: out = doc->params.title; capacity = sizeof(doc->params.title); break;
            }
            if (doc->value_length >= capacity || (!doc->value_length && i != 4 && i != 8))
                return BC_PROTOCOL_ERROR;
            for (uint32_t j = 0; j < doc->value_length; ++j) {
                unsigned char c = (unsigned char)doc->value[j];
                if (c < 32 || (i != 8 && (c == 32 || c > 126))) return BC_PROTOCOL_ERROR;
                if ((i == 3 || i == 4) && !((c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return BC_PROTOCOL_ERROR;
            }
            if ((i == 3 && doc->value_length != 64) ||
                (i == 4 && doc->value_length && doc->value_length != 32)) return BC_PROTOCOL_ERROR;
            memcpy(out, doc->value, doc->value_length + 1);
        }
        break;
    }
    return BC_OK;
}

static bc_status launch_event(void *user, enum bc_launch_xml_event event,
    uint32_t depth, const char *name, const char *data) {
    huawei_launch *doc = user;
    switch (event) {
    case BC_XML_START:
        if (doc->param_depth || (depth == 1 && strcmp(name, "jnlp"))) return BC_PROTOCOL_ERROR;
        if (!strcmp(name, "applet-desc")) {
            if (depth != 2 || ++doc->apps != 1) return BC_PROTOCOL_ERROR;
            doc->app_depth = depth;
        } else if (!strcmp(name, "param")) {
            if (!doc->app_depth || depth != doc->app_depth + 1) return BC_PROTOCOL_ERROR;
            doc->param_depth = depth; doc->attributes = 0;
            doc->name_length = doc->value_length = 0;
            doc->name[0] = doc->value[0] = 0;
        }
        break;
    case BC_XML_ATTRIBUTE:
        doc->capture = doc->param_depth == depth ?
            (!strcmp(name, "name") ? 1u : !strcmp(name, "value") ? 2u : 0u) : 0u;
        doc->attributes |= doc->capture;
        break;
    case BC_XML_ATTRIBUTE_VALUE:
        if (doc->capture == 1)
            return bc_launch_append(doc->name, &doc->name_length, sizeof(doc->name), data);
        if (doc->capture == 2)
            return bc_launch_append(doc->value, &doc->value_length, sizeof(doc->value), data);
        break;
    case BC_XML_ATTRIBUTE_END: doc->capture = 0; break;
    case BC_XML_CONTENT:
        if (doc->param_depth)
            for (; *data; ++data)
                if (*data != ' ' && *data != '\t' && *data != '\r' && *data != '\n') return BC_PROTOCOL_ERROR;
        break;
    case BC_XML_END:
        if (doc->param_depth == depth) {
            bc_status status = parameter(doc); doc->param_depth = 0;
            if (status != BC_OK) return status;
        }
        if (doc->app_depth == depth) doc->app_depth = 0;
        break;
    }
    return BC_OK;
}

bc_status bc_huawei_kvm_discover_jnlp(const uint8_t *data, uint32_t length,
    bc_huawei_kvm_params *params, bc_service_profile *profile) {
    if (!params || !profile) return BC_INVALID_ARGUMENT;
    memset(params, 0, sizeof(*params));
    *profile = (bc_service_profile){sizeof(*profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_HUAWEI, 0, 0};
    huawei_launch doc = {0};
    bc_status status = bc_launch_xml_parse(data, length, launch_event, &doc);
    if (status == BC_OK && (doc.apps != 1 || (doc.seen & 15u) != 15u)) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) {
        doc.params.struct_size = sizeof(doc.params); doc.params.abi_version = BC_ABI_VERSION;
        *params = doc.params;
        profile->variant = BC_SERVICE_HUAWEI_KVM_NEGOTIATED;
        profile->evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR;
    }
    volatile uint8_t *secret = (volatile uint8_t *)&doc;
    for (size_t i = 0; i < sizeof(doc); ++i) secret[i] = 0;
    return status;
}

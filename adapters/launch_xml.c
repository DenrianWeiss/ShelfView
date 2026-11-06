#include "launch_xml.h"
#include "yxml.h"
#include <string.h>

bc_status bc_launch_append(char *out, uint32_t *used, size_t capacity, const char *data) {
    size_t length = strlen(data);
    if (*used >= capacity || length >= capacity - *used) return BC_LIMIT_EXCEEDED;
    memcpy(out + *used, data, length + 1); *used += (uint32_t)length;
    return BC_OK;
}

bc_status bc_launch_number(const char *text, uint32_t maximum, uint32_t *out) {
    if (!*text) return BC_PROTOCOL_ERROR;
    uint32_t value = 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') return BC_PROTOCOL_ERROR;
        uint32_t digit = (uint32_t)(*text - '0');
        if (digit > maximum || value > (maximum - digit) / 10) return BC_PROTOCOL_ERROR;
        value = value * 10 + digit;
    }
    *out = value; return BC_OK;
}

bc_status bc_launch_xml_parse(const uint8_t *data, uint32_t length,
    bc_launch_xml_callback callback, void *user) {
    if (!data || !length || !callback) return BC_INVALID_ARGUMENT;
    if (length > 65536) return BC_LIMIT_EXCEEDED;
    yxml_t xml; char stack[4096], attributes[32][64];
    yxml_init(&xml, stack, sizeof(stack));
    uint32_t depth = 0, attribute_count = 0;
    for (uint32_t i = 0; i < length; ++i) {
        yxml_ret_t event = yxml_parse(&xml, data[i]);
        if (event < 0) return event == YXML_ESTACK ? BC_LIMIT_EXCEEDED : BC_PROTOCOL_ERROR;
        enum bc_launch_xml_event mapped;
        const char *name = xml.elem;
        switch (event) {
        case YXML_ELEMSTART:
            if (++depth > 32) return BC_LIMIT_EXCEEDED;
            attribute_count = 0; mapped = BC_XML_START; break;
        case YXML_ATTRSTART:
            if (attribute_count == 32 || strlen(xml.attr) >= sizeof(attributes[0]))
                return BC_LIMIT_EXCEEDED;
            for (uint32_t j = 0; j < attribute_count; ++j)
                if (!strcmp(attributes[j], xml.attr)) return BC_PROTOCOL_ERROR;
            strcpy(attributes[attribute_count++], xml.attr);
            name = xml.attr; mapped = BC_XML_ATTRIBUTE; break;
        case YXML_ATTRVAL: mapped = BC_XML_ATTRIBUTE_VALUE; break;
        case YXML_ATTREND: mapped = BC_XML_ATTRIBUTE_END; break;
        case YXML_CONTENT: mapped = BC_XML_CONTENT; break;
        case YXML_ELEMEND: mapped = BC_XML_END; break;
        default: continue;
        }
        bc_status status = callback(user, mapped, depth, name, xml.data);
        if (status != BC_OK) return status;
        if (event == YXML_ELEMEND) --depth;
    }
    return yxml_eof(&xml) == YXML_OK && !depth ? BC_OK : BC_PROTOCOL_ERROR;
}

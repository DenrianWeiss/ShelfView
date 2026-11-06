#ifndef BCONTROL_LAUNCH_XML_H
#define BCONTROL_LAUNCH_XML_H
#include "bcontrol/bcontrol.h"
#include <stddef.h>

enum bc_launch_xml_event { BC_XML_START, BC_XML_END, BC_XML_ATTRIBUTE,
    BC_XML_ATTRIBUTE_VALUE, BC_XML_ATTRIBUTE_END, BC_XML_CONTENT };
typedef bc_status (*bc_launch_xml_callback)(void *user, enum bc_launch_xml_event event,
    uint32_t depth, const char *name, const char *data);
/* Bounded XML syntax only; vendor callbacks validate document and field semantics. */
bc_status bc_launch_xml_parse(const uint8_t *data, uint32_t length,
    bc_launch_xml_callback callback, void *user);
bc_status bc_launch_append(char *out, uint32_t *used, size_t capacity, const char *data);
bc_status bc_launch_number(const char *text, uint32_t maximum, uint32_t *out);
#endif

#ifndef BCONTROL_DISCOVERY_INTERNAL_H
#define BCONTROL_DISCOVERY_INTERNAL_H
#include "bcontrol/bcontrol.h"
#include "bcontrol/redfish.h"
#include <string.h>
static inline bc_string bc_discovery_resource_path(bc_string uri) {
    if (uri.data && uri.length > 12 && uri.data[uri.length - 1] == '/') --uri.length;
    return uri;
}
static inline int bc_discovery_uri_matches(bc_string a, bc_string b, const char *pattern) {
    return bc_redfish_resource_uri_match(a, b, (bc_string){pattern, strlen(pattern)}) != BC_REDFISH_URI_NO_MATCH;
}
int bc_console_endpoint_is_https(const bc_endpoint *);
#endif

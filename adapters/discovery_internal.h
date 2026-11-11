#ifndef BCONTROL_DISCOVERY_INTERNAL_H
#define BCONTROL_DISCOVERY_INTERNAL_H
#include "bcontrol/bcontrol.h"
#include "bcontrol/redfish.h"
#include "bcontrol/jviewer_discovery.h"
#include "bcontrol/web_login.h"
#include <string.h>
static inline bc_string bc_discovery_resource_path(bc_string uri) {
    if (uri.data && uri.length > 12 && uri.data[uri.length - 1] == '/') --uri.length;
    return uri;
}
static inline int bc_discovery_uri_matches(bc_string a, bc_string b, const char *pattern) {
    return bc_redfish_resource_uri_match(a, b, (bc_string){pattern, strlen(pattern)}) != BC_REDFISH_URI_NO_MATCH;
}
int bc_console_endpoint_is_https(const bc_endpoint *);
BC_DISCOVERY_API int bc_web_session_jviewer_alias(const bc_web_session *, const bc_endpoint *, const bc_megarac_kvm_info *);
BC_DISCOVERY_API bc_status bc_jviewer_artifact_start_for_web(bc_endpoint *, bc_request *, const bc_web_session *,
    const bc_jviewer_artifact_options *, bc_jviewer_artifact_completion, void *, bc_jviewer_artifact **);
#endif

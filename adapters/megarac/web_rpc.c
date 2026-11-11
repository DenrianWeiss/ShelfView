#include "web_rpc.h"
#include <string.h>

int bc_megarac_inline_rpc_asset_matches(const char *path, bc_bytes body) {
    static const char *const index[] = {
        "src=\"index_imp.js\"", "src=\"lib/xmit.js\"", "gPageDir", "\"login.html\"", "mainFrame", NULL
    };
    static const char *const page[] = {
        "src=\"../lib/ns_inc.js\"", "id=\"login_username\"", "id=\"login_password\"", "onclick=\"validate(document.forms[", NULL
    };
    static const char *const script[] = {
        BC_MEGARAC_INLINE_RPC_LOGIN_RPC, "\"WEBVAR_USERNAME\",$(\"login_username\").value",
        "\"WEBVAR_PASSWORD\",$(\"login_password\").value",
        "WEBVAR_JSONVAR_WEB_SESSION.WEBVAR_STRUCTNAME_WEB_SESSION[0]",
        "\"SessionCookie=\" + LOGIN_DATA.SESSION_COOKIE", "LOGIN_DATA.CSRFTOKEN", NULL
    };
    static const char *const xmit[] = {
        "xmit.encodespecial(val)", "this.method=\"POST\"", "application/x-www-form-urlencoded",
        "setRequestHeader(\"CSRFTOKEN\", top.user.CSRFtoken)", NULL
    };
    const char *const *markers;
    if (!strcmp(path, "/") || !strcmp(path, "/index.html")) markers = index;
    else if (!strcmp(path, BC_MEGARAC_INLINE_RPC_LOGIN_PAGE)) markers = page;
    else if (!strcmp(path, BC_MEGARAC_INLINE_RPC_LOGIN_SCRIPT)) markers = script;
    else if (!strcmp(path, BC_MEGARAC_INLINE_RPC_XMIT_SCRIPT)) markers = xmit;
    else return 0;

    if (!body.data || body.length > 262144) return 0;
    for (; *markers; ++markers) {
        size_t n = strlen(*markers), at = 0;
        while (at + n <= body.length && memcmp(body.data + at, *markers, n)) ++at;
        if (at + n > body.length) return 0;
    }
    return 1;
}

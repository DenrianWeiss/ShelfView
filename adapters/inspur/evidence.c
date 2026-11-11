#include "bcontrol/inspur.h"
#include <string.h>
#include "../megarac/h5_internal.h"
#include "../megarac/rpc.h"

static int contains(const uint8_t *data, uint32_t length, const char *text) {
    size_t n = strlen(text);
    if (!data || n > length) return 0;
    for (size_t i = 0; i <= length - n; ++i) if (!memcmp(data + i, text, n)) return 1;
    return 0;
}
int bc_inspur_login_page_matches(const uint8_t *data, uint32_t length) {
    return length <= 262144 && contains(data, length, "src=\"js/signin.js\"") &&
        contains(data, length, "src=\"js/Blowfish.js\"") && contains(data, length, "ng-click=\"doValidate()\"");
}
int bc_inspur_login_script_matches(const uint8_t *data, uint32_t length) {
    static const char *const fields[] = {"url: \"/api/randomtag\"", "url: \"/api/session\"",
        "new Blowfish(\"secret\")", "bf.encrypt($scope.username)", "bf.encrypt($scope.password)",
        "login_tag: localStorage.getItem(\"login_tag\")"};
    if (length > 262144) return 0;
    for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); ++i)
        if (!contains(data, length, fields[i])) return 0;
    return (contains(data, length, "username: bf.base64Encode(encrypt_username)") &&
        contains(data, length, "password: bf.base64Encode(encrypt_password)") &&
        contains(data, length, "encrypt_flag: \"2\"")) ||
        (contains(data, length, "$scope.encrypt_ctrl = data.encrypt_ctrl") &&
        contains(data, length, "encrypt_flag: $scope.encrypt_ctrl") &&
        contains(data, length, "encrypt_username = encryStr($scope.username)") &&
        contains(data, length, "encrypt_password = encryStr($scope.password)") &&
        contains(data, length, "charCode=charCode^127") &&
        contains(data, length, "parseInt(charCode).toString(16)"));
}
int bc_inspur_viewer_script_matches(const uint8_t *data, uint32_t length) {
    return bc_megarac_split_h5_viewer_matches(data, length);
}

int bc_inspur_rpc_page_matches(const uint8_t *data, uint32_t length) {
    return length <= 262144 && contains(data, length, "src=\"img/inspur_logo.png\"") &&
        contains(data, length, "src=\"js/signin.js\"") && contains(data, length, "ng-click=\"doValidate()\"");
}
int bc_inspur_rpc_script_matches(const uint8_t *data, uint32_t length) {
    static const char *const fields[] = {
        "url: '/rpc/WEBSES/create.asp'", "data: \"WEBVAR_USERNAME=\" + UserName + \"&\" + \"WEBVAR_PASSWORD=\" + Password",
        "WEBVAR_JSONVAR_WEB_SESSION.WEBVAR_STRUCTNAME_WEB_SESSION[0].SESSION_COOKIE",
        "WEBVAR_JSONVAR_WEB_SESSION.WEBVAR_STRUCTNAME_WEB_SESSION[0].CSRFTOKEN",
        "\"SessionCookie=\" + login_cookie", "url: 'rpc/WEBSES/logout.asp'",
        "top.location.href = \"/main.html\""
    };
    if (length > 262144) return 0;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i)
        if (!contains(data, length, fields[i])) return 0;
    return 1;
}
bc_bytes bc_inspur_rpc_payload(bc_bytes body, const char *assignment) {
    return bc_megarac_rpc_payload(body, assignment);
}

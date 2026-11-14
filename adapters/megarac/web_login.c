#include "web_login.h"
#include "h5_internal.h"
#include <stdio.h>

int bc_megarac_web_login_page_matches(bc_bytes body) {
    return body.length <= 262144 &&
        bc_megarac_h5_contains(body.data, (uint32_t)body.length, "<main role=\"main\" id=\"main\"></main>");
}
static int identifier(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$';
}
int bc_megarac_web_login_script_matches(bc_bytes body) {
    if (!body.data || body.length > 8u * 1024u * 1024u) return 0;
    const uint8_t *data = body.data;
    uint32_t length = (uint32_t)body.length;
    const char *const markers[] = {
        "\"views/LoginView\",[\"jquery\",\"underscore\",\"backbone\",\"app\"",
        "\"text!templates/login.html\",[],function(){return",
        "id=\"userid\"", "id=\"password\"", "url:\"/api/session\",type:\"DELETE\""
    };
    for (size_t i = 0; i < sizeof(markers)/sizeof(markers[0]); ++i)
        if (!bc_megarac_h5_contains(data, length, markers[i])) return 0;
    const char start[] = ".ajax({type:\"POST\",url:\"/api/session\",dataType:\"json\",data:{username:";
    unsigned matches = 0;
    for (uint32_t i = 1; i + sizeof(start) < length; ++i) {
        if (memcmp(data + i, start, sizeof(start) - 1)) continue;
        uint32_t begin = i;
        while (begin && identifier(data[begin - 1])) --begin;
        uint32_t n = i - begin;
        if (!n || n > 32) return 0;
        char pattern[512];
        int size = snprintf(pattern, sizeof(pattern),
            "%s%.*s(\"#userid\").val(),password:%.*s(\"#password\").val()},success:function(",
            start, (int)n, data + begin, (int)n, data + begin);
        if (size < 0 || (size_t)size >= sizeof(pattern) || (uint32_t)size > length - i ||
            memcmp(data + i, pattern, (size_t)size)) return 0;
        uint32_t arg = i + (uint32_t)size, end = arg;
        while (end < length && identifier(data[end])) ++end;
        if (end == arg || end - arg > 32 || end + 1 >= length || data[end] != ')' || data[end + 1] != '{') return 0;
        snprintf(pattern, sizeof(pattern), "%.*s.ajaxSetup({headers:{\"X-CSRFTOKEN\":%.*s.CSRFToken}})",
            (int)n, data + begin, (int)(end - arg), data + arg);
        uint32_t response_length = length - end > 16384 ? 16384 : length - end;
        if (!bc_megarac_h5_contains(data + end, response_length, pattern)) return 0;
        snprintf(pattern, sizeof(pattern), "else if(0===%.*s.ok)", (int)(end - arg), data + arg);
        if (!bc_megarac_h5_contains(data + end, response_length, pattern)) return 0;
        ++matches;
    }
    return matches == 1;
}

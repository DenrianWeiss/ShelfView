#include "rpc.h"
#include <string.h>

static int space(uint8_t c) { return c == ' ' || c == '\r' || c == '\n' || c == '\t'; }
bc_bytes bc_megarac_rpc_payload(bc_bytes body, const char *assignment) {
    static const char begin[] = "//Dynamic Data Begin", end[] = "//Dynamic data end";
    if (!assignment || !body.data || !body.length || body.length > 65536) return (bc_bytes){0};
    const uint8_t *p = body.data, *last = p + body.length;
    while (p < last && space(*p)) ++p;
    while (last > p && space(last[-1])) --last;
    if ((size_t)(last - p) >= sizeof(end) - 1 && !memcmp(last - (sizeof(end) - 1), end, sizeof(end) - 1))
        last -= sizeof(end) - 1;
    while ((size_t)(last - p) >= 2 && p[0] == '/' && p[1] == '/') {
        if ((size_t)(last - p) > sizeof(begin) - 1 && !memcmp(p, begin, sizeof(begin) - 1) &&
            (p[sizeof(begin) - 1] == '\r' || p[sizeof(begin) - 1] == '\n')) break;
        p = memchr(p, '\n', (size_t)(last - p));
        if (!p) return (bc_bytes){0};
        ++p;
        while (p < last && space(*p)) ++p;
    }
    if ((size_t)(last - p) < sizeof(begin) - 1 || memcmp(p, begin, sizeof(begin) - 1)) return (bc_bytes){0};
    p += sizeof(begin) - 1;
    while (p < last && space(*p)) ++p;
    size_t n = strlen(assignment);
    if ((size_t)(last - p) <= n || memcmp(p, assignment, n)) return (bc_bytes){0};
    p += n;
    while (p < last && space(*p)) ++p;
    if (p == last || *p++ != '=') return (bc_bytes){0};
    while (last > p && space(last[-1])) --last;
    if (last == p || *--last != ';') return (bc_bytes){0};
    return (bc_bytes){p, (uint64_t)(last - p)};
}

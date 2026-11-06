#include "diagnostic_zip.h"
#include <string.h>
#ifdef BC_DIAGNOSTIC_ZLIB
#include <zlib.h>
#endif
static uint32_t le(const uint8_t *p, unsigned n) {
    uint32_t v = 0; for (unsigned i = 0; i < n; ++i) v |= (uint32_t)p[i] << (i * 8); return v;
}
static uint32_t checksum(const uint8_t *p, size_t n, uint32_t crc) {
    while (n--) { crc ^= *p++; for (unsigned i = 0; i < 8; ++i) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u))); }
    return crc;
}
static int payload(const uint8_t *p, uint32_t packed, uint32_t size, unsigned method, uint32_t expected) {
    uint32_t crc = ~0u;
    if (!method) { if (packed != size) return 0; crc = checksum(p, size, crc); }
    else {
#ifdef BC_DIAGNOSTIC_ZLIB
        z_stream stream; memset(&stream, 0, sizeof(stream));
        if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) return 0;
        stream.next_in = (Bytef *)p; stream.avail_in = packed;
        uint8_t buffer[16384]; int status; uint32_t total = 0;
        do {
            stream.next_out = buffer; stream.avail_out = sizeof(buffer);
            status = inflate(&stream, Z_NO_FLUSH);
            uint32_t got = sizeof(buffer) - stream.avail_out;
            if (got > size - total) { inflateEnd(&stream); return 0; }
            total += got; crc = checksum(buffer, got, crc);
            if (status == Z_OK && !got && !stream.avail_in) break;
        } while (status == Z_OK);
        int valid = status == Z_STREAM_END && total == size && !stream.avail_in;
        inflateEnd(&stream); if (!valid) return 0;
#else
        return 0;
#endif
    }
    return ~crc == expected;
}
int bc_diagnostic_zip_valid(const uint8_t *data, size_t length) {
    if (!data || length < 22 || length > 16u*1024u*1024u) return 0;
    size_t end = length - 22, floor = end > 65535 ? end - 65535 : 0;
    for (;;) {
        if (le(data + end, 4) == 0x06054b50u && le(data + end + 20, 2) == length - end - 22) break;
        if (end == floor) return 0; --end;
    }
    const uint8_t *e = data + end;
    uint32_t count = le(e + 10, 2), central = le(e + 16, 4), bytes = le(e + 12, 4);
    if (le(e + 4, 2) || le(e + 6, 2) || !count || count > 2048 || le(e + 8, 2) != count || central > end || bytes != end - central) return 0;
    size_t at = central; uint32_t total = 0; int java = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (at > end || end - at < 46 || le(data + at, 4) != 0x02014b50u) return 0;
        const uint8_t *c = data + at;
        uint32_t flags = le(c + 8, 2), method = le(c + 10, 2), packed = le(c + 20, 4), size = le(c + 24, 4);
        uint32_t name = le(c + 28, 2), extra = le(c + 30, 2), comment = le(c + 32, 2), local = le(c + 42, 4);
        size_t record = 46u + name + extra + comment;
        if (!name || record > end - at || (flags & ~0x080eu) || (method != 0 && method != 8) || le(c + 34, 2) ||
            size > 64u*1024u*1024u - total || packed > 16u*1024u*1024u || local > central || central - local < 30) return 0;
        total += size;
        const uint8_t *l = data + local;
        uint32_t ln = le(l + 26, 2), lx = le(l + 28, 2);
        size_t header = 30u + ln + lx;
        if (le(l, 4) != 0x04034b50u || le(l + 6, 2) != flags || le(l + 8, 2) != method || ln != name ||
            header > central - local || packed > central - local - header || memcmp(l + 30, c + 46, name)) return 0;
        uint32_t crc = le(c + 16, 4);
        if (!(flags & 8) && (le(l + 14, 4) != crc || le(l + 18, 4) != packed || le(l + 22, 4) != size)) return 0;
        if (flags & 8) {
            size_t descriptor = local + header + packed;
            if (central - descriptor < 12) return 0;
            if (le(data + descriptor, 4) == 0x08074b50u) { descriptor += 4; if (central - descriptor < 12) return 0; }
            if (le(data + descriptor, 4) != crc || le(data + descriptor + 4, 4) != packed || le(data + descriptor + 8, 4) != size) return 0;
        }
        if (!payload(l + header, packed, size, method, crc)) return 0;
        if ((name >= 6 && !memcmp(c + 46 + name - 6, ".class", 6)) ||
            (name == 20 && !memcmp(c + 46, "META-INF/MANIFEST.MF", 20))) java = 1;
        at += record;
    }
    return at == end && java;
}

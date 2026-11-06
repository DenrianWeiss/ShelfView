#include "bcontrol/bcontrol.h"
#include "bcontrol/wire.h"
#include "log_internal.h"
#include <inttypes.h>
#include <string.h>

static int valid(const bc_media_header *h) {
    return h && h->opcode >= BC_MEDIA_READ && h->opcode <= BC_MEDIA_CLOSE &&
        h->channel && h->request_id && !h->reserved && !h->flags;
}
bc_status bc_media_header_encode(const bc_media_header *h, uint8_t out[40]) {
    if (!out || !valid(h)) return BC_INVALID_ARGUMENT;
    memset(out, 0, 40); memcpy(out, "BCTL", 4);
    bc_wire_write_be(out + 4, 1, 2); bc_wire_write_be(out + 6, h->opcode, 2);
    bc_wire_write_be(out + 8, h->channel, 4); bc_wire_write_be(out + 12, h->flags, 4);
    bc_wire_write_be(out + 16, h->request_id, 8); bc_wire_write_be(out + 24, h->offset, 8);
    bc_wire_write_be(out + 32, h->payload_length, 4);
    return BC_OK;
}
bc_status bc_media_header_decode(const uint8_t *p, uint64_t size, uint32_t max_payload, bc_media_header *out) {
    if (!p || !out || size < 40 || memcmp(p, "BCTL", 4)) {
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "media.header", "status=invalid_argument bytes=%" PRIu64, size);
        return BC_INVALID_ARGUMENT;
    }
    if (bc_wire_read_be(p + 4, 2) != 1) {
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "media.header", "status=unsupported version=%u",
            (unsigned)bc_wire_read_be(p + 4, 2));
        return BC_UNSUPPORTED;
    }
    bc_media_header h = {0};
    h.opcode = (uint32_t)bc_wire_read_be(p + 6, 2); h.channel = (uint32_t)bc_wire_read_be(p + 8, 4);
    h.flags = (uint32_t)bc_wire_read_be(p + 12, 4); h.request_id = bc_wire_read_be(p + 16, 8);
    h.offset = bc_wire_read_be(p + 24, 8); h.payload_length = (uint32_t)bc_wire_read_be(p + 32, 4);
    h.reserved = (uint32_t)bc_wire_read_be(p + 36, 4);
    if (!valid(&h)) {
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "media.header", "status=invalid_argument opcode=%u channel=%u flags=%u",
            h.opcode, h.channel, h.flags);
        return BC_INVALID_ARGUMENT;
    }
    if (h.payload_length > max_payload) {
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "media.header", "status=limit_exceeded payload=%u max=%u",
            h.payload_length, max_payload);
        return BC_LIMIT_EXCEEDED;
    }
    if (size != 40u + (uint64_t)h.payload_length) {
        BC_LOG_DEBUG(BC_LOG_CATEGORY_MEDIA, "media.header", "status=invalid_argument bytes=%" PRIu64 " payload=%u",
            size, h.payload_length);
        return BC_INVALID_ARGUMENT;
    }
    *out = h; return BC_OK;
}
bc_status bc_media_range_check(uint64_t size, uint64_t offset, uint64_t length) {
    return offset <= size && length <= size - offset ? BC_OK : BC_INVALID_ARGUMENT;
}
bc_status bc_media_read_encode(const bc_media_header *h, uint32_t length, uint64_t source_size, uint32_t max_block, uint8_t out[44]) {
    if (!h || !out || h->opcode != BC_MEDIA_READ || h->payload_length != 4 || !length || !max_block)
        return BC_INVALID_ARGUMENT;
    if (length > max_block) return BC_LIMIT_EXCEEDED;
    if (bc_media_range_check(source_size, h->offset, length) != BC_OK) return BC_INVALID_ARGUMENT;
    bc_status status = bc_media_header_encode(h, out);
    if (status == BC_OK) bc_wire_write_be(out + 40, length, 4);
    return status;
}
bc_status bc_media_read_decode(const uint8_t *data, uint64_t size, uint64_t source_size, uint32_t max_block, bc_media_header *out, uint32_t *length) {
    if (!out || !length || !max_block) return BC_INVALID_ARGUMENT;
    bc_media_header h;
    bc_status status = bc_media_header_decode(data, size, 4, &h);
    if (status != BC_OK) return status;
    if (h.opcode != BC_MEDIA_READ || h.payload_length != 4) return BC_INVALID_ARGUMENT;
    uint32_t n = (uint32_t)bc_wire_read_be(data + 40, 4);
    if (!n || bc_media_range_check(source_size, h.offset, n) != BC_OK) return BC_INVALID_ARGUMENT;
    if (n > max_block) return BC_LIMIT_EXCEEDED;
    *out = h; *length = n; return BC_OK;
}

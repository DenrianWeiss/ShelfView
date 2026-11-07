#include "bcontrol/avocent.h"
#include "bcontrol/wire.h"
#include <stdlib.h>
#include <string.h>

struct bc_avocent_video {
    uint32_t max_width, max_height;
    uint32_t *reference;
    uint8_t *rgba;
    uint8_t *compressed;
    uint32_t compressed_length, compressed_capacity;
    uint8_t block_header[24];
    bc_kvm_frame frame;
};
bc_status bc_avocent_video_create(uint32_t width, uint32_t height, bc_avocent_video **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!width || !height || width > 8192 || height > 8192) return BC_INVALID_ARGUMENT;
    bc_avocent_video *v = calloc(1, sizeof(*v));
    if (!v) return BC_NO_MEMORY;
    v->max_width = width; v->max_height = height;
    v->frame.struct_size = sizeof(v->frame);
    *out = v;
    return BC_OK;
}
void bc_avocent_video_destroy(bc_avocent_video *v) {
    if (!v) return;
    free(v->reference); free(v->rgba); free(v->compressed); free(v);
}
const bc_kvm_frame *bc_avocent_video_frame(const bc_avocent_video *v) { return v ? &v->frame : NULL; }
void bc_avocent_video_ack(bc_avocent_video *v) {
    if (v) v->frame.flags &= ~(BC_KVM_FRAME_READY | BC_KVM_DESKTOP_RESIZED);
}
bc_status bc_avocent_video_feed(bc_avocent_video *v, const uint8_t *data, uint32_t length) {
    if (!v || !data) return BC_INVALID_ARGUMENT;
    if (length < 8 || memcmp(data, "\xde\xad\xbe\xef", 4) ||
        bc_wire_read_be(data + 4, 2) != 0x8b || bc_wire_read_be(data + 6, 2) != length)
        return BC_PROTOCOL_ERROR;
    if (length < 24 || data[8] != 10) return BC_UNSUPPORTED;
    uint32_t height = (uint32_t)bc_wire_read_be(data + 12, 2), width = (uint32_t)bc_wire_read_be(data + 14, 2);
    uint32_t y = (uint32_t)bc_wire_read_be(data + 16, 2), x = (uint32_t)bc_wire_read_be(data + 18, 2);
    uint32_t h = (uint32_t)bc_wire_read_be(data + 20, 2), w = (uint32_t)bc_wire_read_be(data + 22, 2);
    if (!width || !height || !w || !h || width > v->max_width || height > v->max_height ||
        x + w > width || y + h > height) return BC_PROTOCOL_ERROR;
    int resized = width != v->frame.width || height != v->frame.height;
    if (resized && !(data[9] & 4)) return BC_PROTOCOL_ERROR;
    if (v->compressed_length && memcmp(v->block_header + 12, data + 12, 12)) return BC_PROTOCOL_ERROR;
    uint32_t payload = length - 24, limit = w * h * 4;
    if (payload > limit - v->compressed_length) return BC_PROTOCOL_ERROR;
    uint32_t needed = v->compressed_length + payload;
    if (needed > v->compressed_capacity) {
        uint8_t *compressed = realloc(v->compressed, needed);
        if (!compressed) return BC_NO_MEMORY;
        v->compressed = compressed; v->compressed_capacity = needed;
    }
    if (!v->compressed_length) memcpy(v->block_header, data, 24);
    if (payload) memcpy(v->compressed + v->compressed_length, data + 24, payload);
    v->compressed_length = needed;
    if (!data[10]) return BC_OK;
    uint32_t *block = calloc((size_t)w * h, sizeof(*block));
    if (!block) return BC_NO_MEMORY;
    if (!resized && !(data[9] & 4))
        for (uint32_t row = 0; row < h; ++row)
            memcpy(block + row * w, v->reference + (y + row) * width + x, w * sizeof(*block));
    bc_status status = bc_avocent_dvc23_decode(v->compressed, v->compressed_length, w, h, block, w * h);
    v->compressed_length = 0;
    if (status != BC_OK) { free(block); return status; }
    if (resized) {
        uint32_t *reference = calloc((size_t)width * height, sizeof(*reference));
        uint8_t *rgba = calloc((size_t)width * height, 4);
        if (!reference || !rgba) { free(reference); free(rgba); free(block); return BC_NO_MEMORY; }
        free(v->reference); free(v->rgba); v->reference = reference; v->rgba = rgba;
        v->frame.width = width; v->frame.height = height; v->frame.stride = width * 4;
        v->frame.pixels = rgba;
        v->frame.flags |= BC_KVM_DESKTOP_RESIZED;
    }
    for (uint32_t row = 0; row < h; ++row) {
        for (uint32_t col = 0; col < w; ++col) {
            uint32_t pixel = block[row * w + col], index = (y + row) * width + x + col;
            v->reference[index] = pixel;
            uint8_t *rgba = v->rgba + index * 4;
            rgba[0] = (uint8_t)(pixel >> 15); rgba[1] = (uint8_t)(pixel >> 7);
            rgba[2] = (uint8_t)((pixel & 127) << 1); rgba[3] = 255;
        }
    }
    free(block);
    v->frame.flags |= BC_KVM_READY;
    if (data[9] & 2) v->frame.flags |= BC_KVM_FRAME_READY;
    return BC_OK;
}

bc_status bc_avocent_dvc23_decode(const uint8_t *data, uint32_t length,
    uint32_t width, uint32_t height, uint32_t *pixels, uint32_t capacity) {
    if (!data || !length || !pixels || !width || !height ||
        (uint64_t)width * height > capacity) return BC_INVALID_ARGUMENT;
    uint32_t total = width * height, position = 0, offset = 0;
    while (offset < length) {
        uint8_t command = data[offset++], kind = command & 0xe0;
        if (position >= total) return BC_PROTOCOL_ERROR;
        if (kind <= 0x40) {
            uint64_t count = command & 31u;
            uint32_t shift = 5;
            while (offset < length && (data[offset] & 0xe0) == kind) {
                if (shift >= 35) return BC_PROTOCOL_ERROR;
                count |= (uint64_t)(data[offset++] & 31u) << shift;
                shift += 5;
            }
            if (count > total - position || (kind == 0x40 && position < width))
                return BC_PROTOCOL_ERROR;
            uint32_t previous = position ? pixels[position - 1] : 0;
            for (uint32_t i = 0; i < count; ++i, ++position) {
                if (kind == 0x20) pixels[position] = previous;
                else if (kind == 0x40) pixels[position] = pixels[position - width];
            }
        } else if (kind == 0x60) {
            if (!position || total - position < 4) return BC_PROTOCOL_ERROR;
            uint32_t last = pixels[position - 1], other = last;
            for (uint32_t i = position - 1; i > 0; --i) {
                if (pixels[i - 1] != last) { other = pixels[i - 1]; break; }
            }
            for (uint32_t bit = 0; bit < 4; ++bit)
                pixels[position++] = command & (8u >> bit) ? other : last;
            int more = command & 0x10;
            while (more) {
                if (offset == length || total - position < 7) return BC_PROTOCOL_ERROR;
                command = data[offset++]; more = command & 0x80;
                for (uint32_t bit = 0; bit < 7; ++bit)
                    pixels[position++] = command & (64u >> bit) ? other : last;
            }
        } else {
            if (length - offset < 2) return BC_PROTOCOL_ERROR;
            pixels[position++] = (uint32_t)(command & 0x7f) << 16 |
                (uint32_t)data[offset] << 8 | data[offset + 1];
            offset += 2;
        }
    }
    return position == total ? BC_OK : BC_PROTOCOL_ERROR;
}

#include "video_internal.h"
#include <string.h>

bc_status bc_ilo_bits_append(bc_ilo_bits *bits, uint8_t byte) {
    if (!bits) return BC_INVALID_ARGUMENT;
    if (bits->count > 24) return BC_LIMIT_EXCEEDED;
    bits->pending |= (uint32_t)byte << bits->count;
    bits->count += 8;
    return BC_OK;
}
int bc_ilo_bits_take(bc_ilo_bits *bits, uint8_t count, uint16_t *out) {
    if (!bits || !out || count > 16 || count > bits->count) return 0;
    uint16_t value = 0;
    for (unsigned i = 0; i < count; ++i) {
        value = (uint16_t)((value << 1) | (bits->pending & 1));
        bits->pending >>= 1;
    }
    bits->count -= count; *out = value;
    return 1;
}
void bc_ilo_palette_insert(bc_ilo_palette *palette, uint16_t color) {
    color |= 1;
    unsigned index = palette->count;
    for (unsigned i = 0; i < palette->count; ++i)
        if (palette->colors[i] == color) { index = i; break; }
    if (palette->count && index == 0) return;
    if (index == palette->count) {
        if (palette->count < 17) ++palette->count;
        /* Literals shift the entire active palette, including an existing color. */
    }
    memmove(palette->colors + 1, palette->colors, (palette->count - 1u) * sizeof(uint16_t));
    palette->colors[0] = color;
}
bc_status bc_ilo_palette_get(bc_ilo_palette *palette, uint8_t index, uint16_t *color) {
    if (!palette || !color) return BC_INVALID_ARGUMENT;
    if (index >= palette->count) return BC_PROTOCOL_ERROR;
    uint16_t value = palette->colors[index] | 1;
    memmove(palette->colors + 1, palette->colors, index * sizeof(uint16_t));
    palette->colors[0] = value; *color = value;
    return BC_OK;
}
void bc_ilo_palette_prune(bc_ilo_palette *palette) {
    unsigned used = 0;
    for (unsigned i = 0; i < palette->count; ++i)
        if (palette->colors[i] & 1) palette->colors[used++] = palette->colors[i] & (uint16_t)~1u;
    memset(palette->colors + used, 0, (17 - used) * sizeof(uint16_t));
    palette->count = (uint8_t)used;
}
uint8_t bc_ilo_palette_bits(const bc_ilo_palette *palette) {
    if (palette->count < 2) return 0;
    if (palette->count < 4) return 1;
    if (palette->count < 6) return 2;
    if (palette->count < 10) return 3;
    return 4;
}
bc_status bc_ilo_blit(bc_kvm_frame *frame, const uint16_t *tile, uint32_t x, uint32_t y,
    uint32_t height, uint8_t bpc) {
    if (!frame || !tile || !frame->pixels || bpc < 2 || bpc > 5 || (height != 8 && height != 16))
        return BC_INVALID_ARGUMENT;
    if (frame->width > UINT32_MAX / 4 || frame->stride < frame->width * 4 ||
        x >= frame->width || y >= frame->height || frame->width - x < 16) return BC_PROTOCOL_ERROR;
    uint32_t rows = frame->height - y < height ? frame->height - y : height;
    uint16_t mask = (uint16_t)((1u << bpc) - 1);
    for (uint32_t row = 0; row < rows; ++row) {
        uint8_t *pixel = (uint8_t *)frame->pixels + (size_t)(y + row) * frame->stride + x * 4;
        for (unsigned col = 0; col < 16; ++col) {
            uint16_t color = tile[row * 16 + col] >> 1;
            pixel[0] = (uint8_t)(((color >> (2 * bpc)) & mask) << (8 - bpc));
            pixel[1] = (uint8_t)(((color >> bpc) & mask) << (8 - bpc));
            pixel[2] = (uint8_t)((color & mask) << (8 - bpc)); pixel[3] = 255;
            pixel += 4;
        }
    }
    frame->flags |= BC_KVM_FRAME_READY;
    return BC_OK;
}

#include "megarac.h"
#include "bcontrol/wire.h"
#include <stdlib.h>
#include <string.h>

struct bc_megarac_soc_video {
    uint8_t font[65536];
    uint8_t font_valid;
};

bc_status bc_megarac_soc_video_create(bc_megarac_soc_video **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = calloc(1, sizeof(**out));
    return *out ? BC_OK : BC_NO_MEMORY;
}
void bc_megarac_soc_video_destroy(bc_megarac_soc_video *video) { free(video); }

bc_status bc_megarac_soc_frame_size(const uint8_t *data, uint32_t length, uint32_t *width, uint32_t *height) {
    if (!data || !width || !height || length < 34) return BC_INVALID_ARGUMENT;
    if (bc_wire_read_le(data + 5, 4) != length - 34) return BC_PROTOCOL_ERROR;
    uint32_t w = (uint32_t)bc_wire_read_le(data + 9, 2), h = (uint32_t)bc_wire_read_le(data + 11, 2);
    if (!w || !h || w > 4096 || h > 4096) return BC_LIMIT_EXCEEDED;
    if ((data[23] & 3) == 2) {
        if (data[4] || data[22] != 1 || (data[23] & 0x29) || (data[29] & 12) != 12 ||
            !data[24] || data[24] > 32 || h % data[24]) return BC_UNSUPPORTED;
        w *= 8;
        if (w > 4096) return BC_LIMIT_EXCEEDED;
    }
    *width = w; *height = h;
    return BC_OK;
}

bc_status bc_megarac_soc_video_decode(bc_megarac_soc_video *video, const uint8_t *data, uint32_t length,
    uint8_t *rgba, uint32_t capacity, uint32_t *width, uint32_t *height) {
    if (!video || !rgba) return BC_INVALID_ARGUMENT;
    uint32_t w = 0, h = 0;
    bc_status status = bc_megarac_soc_frame_size(data, length, &w, &h);
    if (status != BC_OK) return status;
    if (!width || !height) return BC_INVALID_ARGUMENT;
    if ((uint64_t)w * h * 4 > capacity) return BC_LIMIT_EXCEEDED;
    if ((data[23] & 3) != 2) return bc_megarac_soc_decode(data, length, rgba, capacity, width, height);
    uint32_t columns = w / 8, char_height = data[24], cells = columns * (h / char_height);
    uint32_t text_size = cells * 2;
    if (length - 34 < text_size || data[21] > 8) return BC_PROTOCOL_ERROR;
    if (data[29] & 16) {
        if (length - 34 - text_size != sizeof(video->font)) return BC_PROTOCOL_ERROR;
        memcpy(video->font, data + 34 + text_size, sizeof(video->font)); video->font_valid = 1;
    } else if (length - 34 != text_size) return BC_PROTOCOL_ERROR;
    if (!video->font_valid) return BC_BUSY;
    static const uint8_t colors[16][3] = {
        {0,0,0},{0,0,170},{0,170,0},{0,170,170},{170,0,0},{170,0,170},{170,85,0},{170,170,170},
        {85,85,85},{85,85,255},{85,255,85},{85,255,255},{255,85,85},{255,85,255},{255,255,85},{255,255,255}
    };
    for (uint32_t cell = 0; cell < cells; ++cell) {
        uint8_t attr = data[35 + cell * 2];
        uint32_t glyph = data[34 + cell * 2];
        if ((attr & 8) && data[21]) glyph += (uint32_t)(data[21] - 1) * 256;
        const uint8_t *font = video->font + glyph * 32;
        uint32_t x0 = cell % columns * 8, y0 = cell / columns * char_height;
        for (uint32_t y = 0; y < char_height; ++y)
            for (uint32_t x = 0; x < 8; ++x) {
                const uint8_t *color = colors[font[y] & (0x80u >> x) ? attr & 15 : (attr >> 4) & 7];
                uint8_t *pixel = rgba + ((y0 + y) * w + x0 + x) * 4;
                memcpy(pixel, color, 3); pixel[3] = 255;
            }
    }
    *width = w; *height = h;
    return BC_OK;
}

bc_status bc_megarac_soc_decode(const uint8_t *data, uint32_t length, uint8_t *rgba,
    uint32_t capacity, uint32_t *width, uint32_t *height) {
    if (!data || !rgba || !width || !height || length < 36) return BC_INVALID_ARGUMENT;
    uint32_t w = (uint32_t)bc_wire_read_le(data + 9, 2), h = (uint32_t)bc_wire_read_le(data + 11, 2);
    uint32_t size = (uint32_t)bc_wire_read_le(data + 5, 4);
    if (!w || !h || w > 4096 || h > 4096 || (uint64_t)w * h * 4 > capacity) return BC_LIMIT_EXCEEDED;
    if (size != length - 34) return BC_PROTOCOL_ERROR;
    if (data[4] != 8 || data[22] != 4 || (data[23] & 0x29u) != 1) return BC_UNSUPPORTED;
    uint32_t count = (uint32_t)bc_wire_read_le(data + 34, 2);
    if (!count || count > ((w + 31) / 32) * ((h + 31) / 32)) return BC_PROTOCOL_ERROR;
    uint32_t table = 2 + count * 2;
    uint32_t start = 34 + ((table + 3) & ~3u);
    if (start > length) return BC_PROTOCOL_ERROR;
    for (uint32_t i = 0; i < count; ++i)
        if ((uint32_t)data[36 + i * 2] * 32 >= h || (uint32_t)data[37 + i * 2] * 32 >= w) return BC_PROTOCOL_ERROR;
    uint32_t decoded_size = count * 4096;
    uint8_t *pixels = malloc(decoded_size);
    if (!pixels) return BC_NO_MEMORY;
    uint32_t used = 0;
    bc_status status = BC_OK;
    for (uint32_t i = start; i < length;) {
        uint8_t value = data[i++];
        uint32_t repeat = 1;
        if (value == 0x55) {
            if (i == length) { status = BC_PROTOCOL_ERROR; break; }
            uint8_t code = data[i++];
            if (code < 2) value = code ? 0xaa : 0x55;
            else {
                if (i == length) { status = BC_PROTOCOL_ERROR; break; }
                repeat = (uint32_t)code + 1; value = data[i++];
            }
        } else if (value == 0xaa) {
            if (i == length) { status = BC_PROTOCOL_ERROR; break; }
            repeat = 3; value = data[i++];
        }
        if (repeat > decoded_size - used) { status = BC_PROTOCOL_ERROR; break; }
        memset(pixels + used, value, repeat); used += repeat;
    }
    if (used != decoded_size) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) {
        uint32_t plane = count * 1024;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t y0 = (uint32_t)data[36 + i * 2] * 32, x0 = (uint32_t)data[37 + i * 2] * 32;
            for (uint32_t y = 0; y < 32 && y0 + y < h; ++y)
                for (uint32_t x = 0; x < 32 && x0 + x < w; ++x) {
                    uint32_t source = i * 1024 + y * 32 + x, target = ((y0 + y) * w + x0 + x) * 4;
                    rgba[target] = pixels[source + plane * 2]; rgba[target + 1] = pixels[source + plane];
                    rgba[target + 2] = pixels[source]; rgba[target + 3] = 255;
                }
        }
        *width = w; *height = h;
    }
    free(pixels);
    return status;
}

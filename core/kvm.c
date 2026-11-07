#include "bcontrol/kvm.h"
#include "bcontrol/wire.h"
#include "log_internal.h"
#include "jpeg.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define KVM_INPUT_CAPACITY 4096u
#define KVM_OUTPUT_CAPACITY 8192u
#define KVM_BYTES_PER_PIXEL 4u
#define KVM_MAX_DIMENSION 4096u
#define KVM_MAX_FRAME_BYTES (36u * 1024u * 1024u)
#define KVM_ENCODING_RAW 0
#define KVM_ENCODING_COPY_RECT 1
#define KVM_ENCODING_HEXTILE 5
#define KVM_ENCODING_DESKTOP_SIZE (-223)

enum { KVM_VERSION, KVM_SECURITY_TYPES, KVM_SECURITY_RESULT, KVM_SERVER_INIT, KVM_READY, KVM_FAILED };
enum { KVM_MSG_NONE, KVM_MSG_UPDATE_HEADER, KVM_MSG_COLOUR_MAP, KVM_MSG_CUT_TEXT, KVM_MSG_RECT_HEADER, KVM_MSG_RECT_DATA,
    KVM_MSG_COPY_RECT, KVM_MSG_HEXTILE_FLAGS, KVM_MSG_HEXTILE_BG, KVM_MSG_HEXTILE_FG, KVM_MSG_HEXTILE_COUNT,
    KVM_MSG_HEXTILE_SUBRECT_COLOR, KVM_MSG_HEXTILE_SUBRECT, KVM_MSG_HEXTILE_RAW,
    KVM_MSG_TIGHT_CONTROL, KVM_MSG_TIGHT_LENGTH, KVM_MSG_TIGHT_JPEG, KVM_MSG_TIGHT_FILL };

struct bc_kvm {
    bc_kvm_extension_handler extension;
    void *extension_userdata;
    uint8_t extension_type;
    uint32_t max_width, max_height;
    uint8_t *framebuffer;
    uint64_t framebuffer_capacity, framebuffer_limit;
    uint32_t width, height, stride;
    uint32_t flags;
    uint8_t state, version;
    uint8_t owns_framebuffer, full_update;

    uint8_t inbuf[KVM_INPUT_CAPACITY];
    uint32_t inlen;
    uint8_t outbuf[KVM_OUTPUT_CAPACITY];
    uint32_t outlen;
    uint32_t skip;

    uint8_t bits_per_pixel, big_endian, true_color;
    uint16_t red_max, green_max, blue_max;
    uint8_t red_shift, green_shift, blue_shift;
    uint8_t name[BC_KVM_MAX_NAME];
    uint32_t name_length;

    uint8_t phase;
    uint8_t message;
    uint16_t rect_count;
    uint16_t rect_x, rect_y, rect_w, rect_h;
    uint32_t rect_pixel;
    uint16_t copy_src_x, copy_src_y;
    uint16_t tile_x, tile_y;
    uint8_t tile_w, tile_h, hextile_flags;
    uint8_t bg[4], fg[4], color[4];
    uint8_t subrect_count, subrect_index, sub_x, sub_y, sub_w, sub_h;
    uint8_t *jpeg;
    uint32_t jpeg_size, jpeg_used, jpeg_shift;
    bc_kvm_frame frame;
};

static uint8_t *need(bc_kvm *kvm, uint32_t length) { return kvm->inlen >= length ? kvm->inbuf : NULL; }
static void drop(bc_kvm *kvm, uint32_t length) {
    memmove(kvm->inbuf, kvm->inbuf + length, kvm->inlen - length);
    kvm->inlen -= length;
}
static bc_status queue(bc_kvm *kvm, const uint8_t *data, uint32_t length) {
    if (kvm->outlen + length > sizeof(kvm->outbuf)) return BC_LIMIT_EXCEEDED;
    memcpy(kvm->outbuf + kvm->outlen, data, length);
    kvm->outlen += length;
    return BC_OK;
}
static bc_status parse_extension(bc_kvm *kvm) {
    uint32_t consumed = 0, written = 0;
    uint32_t capacity = (uint32_t)sizeof(kvm->outbuf) - kvm->outlen;
    bc_status status = kvm->extension(kvm->extension_userdata, kvm->inbuf, kvm->inlen,
        &consumed, kvm->outbuf + kvm->outlen, capacity, &written);
    if (status != BC_OK) return status;
    if (consumed > kvm->inlen || written > capacity || (!consumed && written)) return BC_PROTOCOL_ERROR;
    drop(kvm, consumed);
    kvm->outlen += written;
    return BC_OK;
}

static bc_status queue_request(bc_kvm *kvm, int incremental) {
    uint8_t message[10] = {3, (uint8_t)(incremental ? 1 : 0)};
    bc_wire_write_be(message + 2, 0, 2);
    bc_wire_write_be(message + 4, 0, 2);
    bc_wire_write_be(message + 6, kvm->width, 2);
    bc_wire_write_be(message + 8, kvm->height, 2);
    return queue(kvm, message, sizeof(message));
}
static bc_status queue_encodings(bc_kvm *kvm) {
    uint8_t message[20] = {2, 0, 0, 4};
    bc_wire_write_be(message + 4, KVM_ENCODING_RAW, 4);
    bc_wire_write_be(message + 8, KVM_ENCODING_COPY_RECT, 4);
    bc_wire_write_be(message + 12, KVM_ENCODING_HEXTILE, 4);
    bc_wire_write_be(message + 16, (uint32_t)(int32_t)KVM_ENCODING_DESKTOP_SIZE, 4);
    return queue(kvm, message, sizeof(message));
}

static bc_status set_geometry(bc_kvm *kvm, uint32_t width, uint32_t height) {
    uint32_t stride = width * KVM_BYTES_PER_PIXEL;
    uint64_t bytes = (uint64_t)stride * height;
    if (!width || !height || width > kvm->max_width || height > kvm->max_height || bytes > kvm->framebuffer_limit)
        return BC_LIMIT_EXCEEDED;
    if (width == kvm->width && height == kvm->height) return BC_OK;
    if (bytes > kvm->framebuffer_capacity) {
        uint8_t *pixels = realloc(kvm->framebuffer, (size_t)bytes);
        if (!pixels) return BC_NO_MEMORY;
        kvm->framebuffer = pixels;
        kvm->framebuffer_capacity = bytes;
    }
    if (kvm->height || kvm->owns_framebuffer) {
        uint32_t rows = height < kvm->height ? height : kvm->height;
        uint32_t copy = stride < kvm->stride ? stride : kvm->stride;
        /* Preserve the top-left area without overwriting rows that still need moving. */
        for (uint32_t i = 0; i < rows; ++i) {
            uint32_t row = stride > kvm->stride ? rows - 1 - i : i;
            uint8_t *target = kvm->framebuffer + (size_t)row * stride;
            memmove(target, kvm->framebuffer + (size_t)row * kvm->stride, copy);
            memset(target + copy, 0, stride - copy);
        }
        memset(kvm->framebuffer + (size_t)rows * stride, 0, (size_t)(height - rows) * stride);
    }
    if (kvm->height) kvm->full_update = 1;
    kvm->width = width; kvm->height = height; kvm->stride = stride;
    return BC_OK;
}

static bc_status parse_server_init(bc_kvm *kvm) {
    uint8_t *data = need(kvm, 24);
    if (!data) return BC_OK;
    uint32_t width = (uint32_t)bc_wire_read_be(data, 2), height = (uint32_t)bc_wire_read_be(data + 2, 2);
    if (!width || !height) return BC_PROTOCOL_ERROR;
    kvm->bits_per_pixel = data[4];
    kvm->big_endian = data[6];
    kvm->true_color = data[7] != 0;
    kvm->red_max = (uint16_t)bc_wire_read_be(data + 8, 2);
    kvm->green_max = (uint16_t)bc_wire_read_be(data + 10, 2);
    kvm->blue_max = (uint16_t)bc_wire_read_be(data + 12, 2);
    kvm->red_shift = data[14];
    kvm->green_shift = data[15];
    kvm->blue_shift = data[16];
    uint32_t name_length = (uint32_t)bc_wire_read_be(data + 20, 4);
    if (kvm->bits_per_pixel != 8 && kvm->bits_per_pixel != 16 && kvm->bits_per_pixel != 32) return BC_UNSUPPORTED;
    int negotiate_pixels = kvm->bits_per_pixel != 32 || !kvm->true_color;
    if (!negotiate_pixels && (!kvm->red_max || !kvm->green_max || !kvm->blue_max)) return BC_PROTOCOL_ERROR;
    if (name_length > BC_KVM_MAX_NAME) return BC_LIMIT_EXCEEDED;
    if (kvm->inlen < 24 + name_length) return BC_OK;
    bc_status status = set_geometry(kvm, width, height);
    if (status != BC_OK) return status;
    memcpy(kvm->name, data + 24, name_length);
    kvm->name_length = name_length;
    drop(kvm, 24 + name_length);
    if (negotiate_pixels) {
        const uint8_t format[20] = {0,0,0,0,32,24,0,1,0,255,0,255,0,255,16,8,0,0,0,0};
        status = queue(kvm, format, sizeof(format));
        if (status != BC_OK) return status;
        kvm->bits_per_pixel = 32; kvm->big_endian = 0; kvm->true_color = 1;
        kvm->red_max = kvm->green_max = kvm->blue_max = 255;
        kvm->red_shift = 16; kvm->green_shift = 8; kvm->blue_shift = 0;
    }
    status = queue_encodings(kvm);
    if (status != BC_OK) return status;
    status = queue_request(kvm, 0);
    if (status != BC_OK) return status;
    kvm->flags |= BC_KVM_READY | BC_KVM_DESKTOP_RESIZED;
    kvm->state = KVM_READY;
    BC_LOG_INFO(BC_LOG_CATEGORY_KVM, "kvm.server_init",
        "width=%u height=%u bpp=%u depth_endian=%u true_color=%u name_len=%u",
        width, height, kvm->bits_per_pixel, kvm->big_endian, kvm->true_color, name_length);
    return BC_OK;
}

static bc_status finish_update(bc_kvm *kvm) {
    kvm->flags |= BC_KVM_FRAME_READY;
    kvm->phase = KVM_MSG_NONE;
    BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "kvm.frame", "width=%u height=%u", kvm->width, kvm->height);
    bc_status status = queue_request(kvm, !kvm->full_update);
    kvm->full_update = 0;
    return status;
}

static void store_pixel(const bc_kvm *kvm, const uint8_t *source, uint8_t *target) {
    uint32_t pixel = kvm->big_endian ? (uint32_t)bc_wire_read_be(source, 4) : (uint32_t)bc_wire_read_le(source, 4);
    uint32_t red = (pixel >> kvm->red_shift) & kvm->red_max;
    uint32_t green = (pixel >> kvm->green_shift) & kvm->green_max;
    uint32_t blue = (pixel >> kvm->blue_shift) & kvm->blue_max;
    target[0] = (uint8_t)((red * 255u + kvm->red_max / 2) / kvm->red_max);
    target[1] = (uint8_t)((green * 255u + kvm->green_max / 2) / kvm->green_max);
    target[2] = (uint8_t)((blue * 255u + kvm->blue_max / 2) / kvm->blue_max);
    target[3] = 255;
}

static bc_status parse_rect_data(bc_kvm *kvm) {
    uint64_t total = (uint64_t)kvm->rect_w * kvm->rect_h;
    uint32_t available = kvm->inlen / KVM_BYTES_PER_PIXEL;
    uint64_t remaining = total - kvm->rect_pixel;
    uint32_t count = available < remaining ? available : (uint32_t)remaining;
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t index = kvm->rect_pixel + i;
        uint32_t row = (uint32_t)(index / kvm->rect_w), column = (uint32_t)(index % kvm->rect_w);
        uint8_t *target = kvm->framebuffer + (uint64_t)(kvm->rect_y + row) * kvm->stride + (kvm->rect_x + column) * KVM_BYTES_PER_PIXEL;
        store_pixel(kvm, kvm->inbuf + (uint64_t)i * KVM_BYTES_PER_PIXEL, target);
    }
    if (count) drop(kvm, count * KVM_BYTES_PER_PIXEL);
    kvm->rect_pixel += count;
    if (kvm->rect_pixel < total) return BC_OK;
    if (--kvm->rect_count == 0) return finish_update(kvm);
    kvm->phase = KVM_MSG_RECT_HEADER;
    return BC_OK;
}

static void fill_rect(bc_kvm *kvm, uint32_t x, uint32_t y, uint32_t width, uint32_t height, const uint8_t rgba[4]) {
    for (uint32_t row = 0; row < height; ++row) {
        uint8_t *target = kvm->framebuffer + (uint64_t)(y + row) * kvm->stride + x * KVM_BYTES_PER_PIXEL;
        for (uint32_t column = 0; column < width; ++column) {
            memcpy(target + column * KVM_BYTES_PER_PIXEL, rgba, 4);
        }
    }
}
static bc_status finish_rect(bc_kvm *kvm) {
    if (--kvm->rect_count == 0) return finish_update(kvm);
    kvm->phase = KVM_MSG_RECT_HEADER;
    return BC_OK;
}
static void hextile_advance(bc_kvm *kvm) {
    kvm->tile_x = (uint16_t)(kvm->tile_x + 16);
    if (kvm->tile_x >= kvm->rect_w) {
        kvm->tile_x = 0; kvm->tile_y = (uint16_t)(kvm->tile_y + 16);
    }
    kvm->phase = kvm->tile_y >= kvm->rect_h ? KVM_MSG_RECT_HEADER : KVM_MSG_HEXTILE_FLAGS;
}
static void hextile_fill_background(bc_kvm *kvm) {
    fill_rect(kvm, kvm->rect_x + kvm->tile_x, kvm->rect_y + kvm->tile_y, kvm->tile_w, kvm->tile_h, kvm->bg);
}
static bc_status hextile_step(bc_kvm *kvm) {
    uint8_t *data;
    switch (kvm->phase) {
    case KVM_MSG_HEXTILE_FLAGS:
        data = need(kvm, 1);
        if (!data) return BC_OK;
        kvm->hextile_flags = data[0]; drop(kvm, 1);
        kvm->tile_w = (uint8_t)(kvm->rect_w - kvm->tile_x < 16 ? kvm->rect_w - kvm->tile_x : 16);
        kvm->tile_h = (uint8_t)(kvm->rect_h - kvm->tile_y < 16 ? kvm->rect_h - kvm->tile_y : 16);
        if (kvm->hextile_flags & 1) { kvm->phase = KVM_MSG_HEXTILE_RAW; return BC_OK; }
        /* A tile always starts from its background: the explicitly supplied one
         * or the most recent tile background when this tile omits it. */
        if (kvm->hextile_flags & 2) { kvm->phase = KVM_MSG_HEXTILE_BG; return BC_OK; }
        hextile_fill_background(kvm);
        if (kvm->hextile_flags & 4) { kvm->phase = KVM_MSG_HEXTILE_FG; return BC_OK; }
        if (kvm->hextile_flags & 8) { kvm->phase = KVM_MSG_HEXTILE_COUNT; return BC_OK; }
        hextile_advance(kvm);
        return BC_OK;
    case KVM_MSG_HEXTILE_BG:
        data = need(kvm, 4);
        if (!data) return BC_OK;
        store_pixel(kvm, data, kvm->bg); drop(kvm, 4);
        hextile_fill_background(kvm);
        if (kvm->hextile_flags & 4) { kvm->phase = KVM_MSG_HEXTILE_FG; return BC_OK; }
        if (kvm->hextile_flags & 8) { kvm->phase = KVM_MSG_HEXTILE_COUNT; return BC_OK; }
        hextile_advance(kvm);
        return BC_OK;
    case KVM_MSG_HEXTILE_FG:
        data = need(kvm, 4);
        if (!data) return BC_OK;
        store_pixel(kvm, data, kvm->fg); drop(kvm, 4);
        if (kvm->hextile_flags & 8) kvm->phase = KVM_MSG_HEXTILE_COUNT;
        else hextile_advance(kvm);
        return BC_OK;
    case KVM_MSG_HEXTILE_COUNT:
        data = need(kvm, 1);
        if (!data) return BC_OK;
        kvm->subrect_count = data[0]; drop(kvm, 1);
        if (!kvm->subrect_count) { hextile_advance(kvm); return BC_OK; }
        /* Subrects may follow a tile that specified no background/foreground,
         * so the index must reset when the list starts, not when filling bg. */
        kvm->subrect_index = 0;
        kvm->phase = (kvm->hextile_flags & 16) ? KVM_MSG_HEXTILE_SUBRECT_COLOR : KVM_MSG_HEXTILE_SUBRECT;
        return BC_OK;
    case KVM_MSG_HEXTILE_SUBRECT_COLOR:
        data = need(kvm, 4);
        if (!data) return BC_OK;
        store_pixel(kvm, data, kvm->color); drop(kvm, 4);
        kvm->phase = KVM_MSG_HEXTILE_SUBRECT;
        return BC_OK;
    case KVM_MSG_HEXTILE_SUBRECT:
        data = need(kvm, 2);
        if (!data) return BC_OK;
        kvm->sub_x = (uint8_t)(data[0] >> 4);
        kvm->sub_y = (uint8_t)(data[0] & 15);
        kvm->sub_w = (uint8_t)((data[1] >> 4) + 1);
        kvm->sub_h = (uint8_t)((data[1] & 15) + 1);
        drop(kvm, 2);
        if ((uint32_t)kvm->sub_x + kvm->sub_w > kvm->tile_w || (uint32_t)kvm->sub_y + kvm->sub_h > kvm->tile_h)
            return BC_PROTOCOL_ERROR;
        fill_rect(kvm, kvm->rect_x + kvm->tile_x + kvm->sub_x, kvm->rect_y + kvm->tile_y + kvm->sub_y,
            kvm->sub_w, kvm->sub_h, (kvm->hextile_flags & 16) ? kvm->color : kvm->fg);
        if (++kvm->subrect_index >= kvm->subrect_count) { hextile_advance(kvm); }
        else kvm->phase = (kvm->hextile_flags & 16) ? KVM_MSG_HEXTILE_SUBRECT_COLOR : KVM_MSG_HEXTILE_SUBRECT;
        return BC_OK;
    case KVM_MSG_HEXTILE_RAW: {
        uint32_t count = (uint32_t)kvm->tile_w * kvm->tile_h;
        data = need(kvm, count * KVM_BYTES_PER_PIXEL);
        if (!data) return BC_OK;
        for (uint32_t row = 0; row < kvm->tile_h; ++row) {
            uint8_t *target = kvm->framebuffer + (uint64_t)(kvm->rect_y + kvm->tile_y + row) * kvm->stride +
                (kvm->rect_x + kvm->tile_x) * KVM_BYTES_PER_PIXEL;
            for (uint32_t column = 0; column < kvm->tile_w; ++column)
                store_pixel(kvm, data + (row * kvm->tile_w + column) * KVM_BYTES_PER_PIXEL,
                    target + column * KVM_BYTES_PER_PIXEL);
        }
        drop(kvm, count * KVM_BYTES_PER_PIXEL);
        hextile_advance(kvm);
        return BC_OK;
    }
    default: return BC_PROTOCOL_ERROR;
    }
}
static bc_status parse_ready(bc_kvm *kvm) {
    for (;;) {
        if (kvm->skip) {
            uint32_t count = kvm->inlen < kvm->skip ? kvm->inlen : kvm->skip;
            if (!count) return BC_OK;
            drop(kvm, count);
            kvm->skip -= count;
            if (kvm->skip) return BC_OK;
            continue;
        }
        if (kvm->phase == KVM_MSG_NONE) {
            if (kvm->extension && kvm->inlen && kvm->inbuf[0] == kvm->extension_type) return parse_extension(kvm);
            uint8_t *data = need(kvm, 1);
            if (!data) return BC_OK;
            kvm->message = data[0];
            drop(kvm, 1);
            switch (kvm->message) {
            case 0: kvm->phase = KVM_MSG_UPDATE_HEADER; break;
            case 1: kvm->phase = KVM_MSG_COLOUR_MAP; break;
            case 2: break;
            case 3: kvm->phase = KVM_MSG_CUT_TEXT; break;
            default:
                BC_LOG_WARN(BC_LOG_CATEGORY_KVM, "kvm.message_unsupported", "message=%u", kvm->message);
                return BC_UNSUPPORTED;
            }
            continue;
        }
        if (kvm->phase == KVM_MSG_UPDATE_HEADER) {
            uint8_t *data = need(kvm, 3);
            if (!data) return BC_OK;
            kvm->rect_count = (uint16_t)bc_wire_read_be(data + 1, 2);
            drop(kvm, 3);
            BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "kvm.update", "rects=%u", kvm->rect_count);
            if (!kvm->rect_count) return finish_update(kvm);
            kvm->phase = KVM_MSG_RECT_HEADER;
            continue;
        }
        if (kvm->phase == KVM_MSG_COLOUR_MAP) {
            uint8_t *data = need(kvm, 5);
            if (!data) return BC_OK;
            kvm->skip = (uint32_t)6 * (uint16_t)bc_wire_read_be(data + 3, 2);
            drop(kvm, 5);
            kvm->phase = KVM_MSG_NONE;
            continue;
        }
        if (kvm->phase == KVM_MSG_CUT_TEXT) {
            uint8_t *data = need(kvm, 7);
            if (!data) return BC_OK;
            uint32_t length = (uint32_t)bc_wire_read_be(data + 3, 4);
            if (length > 1024u * 1024u) return BC_LIMIT_EXCEEDED;
            kvm->skip = length;
            drop(kvm, 7);
            kvm->phase = KVM_MSG_NONE;
            continue;
        }
        if (kvm->phase == KVM_MSG_RECT_HEADER) {
            uint8_t *data = need(kvm, 12);
            if (!data) return BC_OK;
            kvm->rect_x = (uint16_t)bc_wire_read_be(data, 2);
            kvm->rect_y = (uint16_t)bc_wire_read_be(data + 2, 2);
            kvm->rect_w = (uint16_t)bc_wire_read_be(data + 4, 2);
            kvm->rect_h = (uint16_t)bc_wire_read_be(data + 6, 2);
            int32_t encoding = (int32_t)(uint32_t)bc_wire_read_be(data + 8, 4);
            drop(kvm, 12);
            BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "kvm.rect", "x=%u y=%u w=%u h=%u encoding=%d",
                kvm->rect_x, kvm->rect_y, kvm->rect_w, kvm->rect_h, encoding);
            if (encoding == KVM_ENCODING_DESKTOP_SIZE) {
                bc_status status = set_geometry(kvm, kvm->rect_w, kvm->rect_h);
                if (status != BC_OK) return status;
                kvm->flags |= BC_KVM_DESKTOP_RESIZED | BC_KVM_FRAME_READY;
                BC_LOG_INFO(BC_LOG_CATEGORY_KVM, "kvm.desktop_resize", "width=%u height=%u", kvm->width, kvm->height);
                if (--kvm->rect_count == 0) return finish_update(kvm);
                continue;
            }
            if ((uint32_t)kvm->rect_x + kvm->rect_w > kvm->width || (uint32_t)kvm->rect_y + kvm->rect_h > kvm->height)
                return BC_PROTOCOL_ERROR;
            if (encoding == 7) {
                if (!kvm->rect_w || !kvm->rect_h) return BC_PROTOCOL_ERROR;
                kvm->phase = KVM_MSG_TIGHT_CONTROL;
                continue;
            }
            if (encoding == KVM_ENCODING_RAW) {
                if (!kvm->rect_w || !kvm->rect_h) return BC_PROTOCOL_ERROR;
                kvm->rect_pixel = 0;
                kvm->phase = KVM_MSG_RECT_DATA;
                continue;
            }
            if (encoding == KVM_ENCODING_COPY_RECT) {
                kvm->phase = KVM_MSG_COPY_RECT;
                continue;
            }
            if (encoding == KVM_ENCODING_HEXTILE) {
                kvm->tile_x = kvm->tile_y = 0;
                memset(kvm->bg, 0, sizeof(kvm->bg));
                memset(kvm->fg, 0, sizeof(kvm->fg));
                kvm->phase = KVM_MSG_HEXTILE_FLAGS;
                continue;
            }
            BC_LOG_WARN(BC_LOG_CATEGORY_KVM, "kvm.encoding_unsupported", "encoding=%d", encoding);
            return BC_UNSUPPORTED;
        }
        if (kvm->phase == KVM_MSG_TIGHT_CONTROL) {
            uint8_t *data = need(kvm, 1); if (!data) return BC_OK;
            uint8_t method = data[0] >> 4; drop(kvm, 1);
            if (method == 9) {
                kvm->jpeg_size = kvm->jpeg_used = kvm->jpeg_shift = 0;
                kvm->phase = KVM_MSG_TIGHT_LENGTH;
            } else if (method == 8) kvm->phase = KVM_MSG_TIGHT_FILL;
            else return BC_UNSUPPORTED;
            continue;
        }
        if (kvm->phase == KVM_MSG_TIGHT_LENGTH) {
            uint8_t *data = need(kvm, 1); if (!data) return BC_OK;
            uint8_t byte = data[0]; drop(kvm, 1);
            kvm->jpeg_size |= (uint32_t)(kvm->jpeg_shift == 14 ? byte : byte & 127) << kvm->jpeg_shift;
            if (kvm->jpeg_shift < 14 && (byte & 128)) { kvm->jpeg_shift += 7; continue; }
            if (!kvm->jpeg_size || kvm->jpeg_size > 4u * 1024u * 1024u) return BC_LIMIT_EXCEEDED;
            kvm->jpeg = malloc(kvm->jpeg_size); if (!kvm->jpeg) return BC_NO_MEMORY;
            kvm->phase = KVM_MSG_TIGHT_JPEG;
            continue;
        }
        if (kvm->phase == KVM_MSG_TIGHT_JPEG) {
            uint32_t n = kvm->jpeg_size - kvm->jpeg_used;
            if (n > kvm->inlen) n = kvm->inlen;
            if (!n) return BC_OK;
            memcpy(kvm->jpeg + kvm->jpeg_used, kvm->inbuf, n); kvm->jpeg_used += n; drop(kvm, n);
            if (kvm->jpeg_used < kvm->jpeg_size) return BC_OK;
            bc_status status = bc_jpeg_decode(kvm->jpeg, kvm->jpeg_size,
                kvm->framebuffer + (uint64_t)kvm->rect_y * kvm->stride + kvm->rect_x * 4,
                kvm->rect_w, kvm->rect_h, kvm->stride);
            free(kvm->jpeg); kvm->jpeg = NULL;
            if (status != BC_OK) return status;
            status = finish_rect(kvm); if (status != BC_OK) return status;
            continue;
        }
        if (kvm->phase == KVM_MSG_TIGHT_FILL) {
            if (kvm->bits_per_pixel != 32 || kvm->red_max != 255 || kvm->green_max != 255 || kvm->blue_max != 255) return BC_UNSUPPORTED;
            uint8_t *data = need(kvm, 3); if (!data) return BC_OK;
            uint8_t color[4] = {data[0], data[1], data[2], 255}; drop(kvm, 3);
            for (uint32_t y = 0; y < kvm->rect_h; ++y)
                for (uint32_t x = 0; x < kvm->rect_w; ++x)
                    memcpy(kvm->framebuffer + (uint64_t)(kvm->rect_y + y) * kvm->stride + (kvm->rect_x + x) * 4, color, 4);
            bc_status status = finish_rect(kvm); if (status != BC_OK) return status;
            continue;
        }
        if (kvm->phase == KVM_MSG_RECT_DATA) {
            bc_status status = parse_rect_data(kvm);
            if (status != BC_OK) return status;
            if (kvm->phase == KVM_MSG_RECT_DATA) return BC_OK;
            continue;
        }
        if (kvm->phase == KVM_MSG_COPY_RECT) {
            uint8_t *data = need(kvm, 4);
            if (!data) return BC_OK;
            uint16_t src_x = (uint16_t)bc_wire_read_be(data, 2), src_y = (uint16_t)bc_wire_read_be(data + 2, 2);
            drop(kvm, 4);
            if ((uint32_t)src_x + kvm->rect_w > kvm->width || (uint32_t)src_y + kvm->rect_h > kvm->height)
                return BC_PROTOCOL_ERROR;
            int reverse = kvm->rect_y > src_y || (kvm->rect_y == src_y && kvm->rect_x > src_x);
            for (uint32_t i = 0; i < kvm->rect_h; ++i) {
                uint32_t row = reverse ? kvm->rect_h - 1 - i : i;
                uint8_t *target = kvm->framebuffer + (uint64_t)(kvm->rect_y + row) * kvm->stride + kvm->rect_x * KVM_BYTES_PER_PIXEL;
                const uint8_t *source = kvm->framebuffer + (uint64_t)(src_y + row) * kvm->stride + src_x * KVM_BYTES_PER_PIXEL;
                memmove(target, source, (size_t)kvm->rect_w * KVM_BYTES_PER_PIXEL);
            }
            bc_status status = finish_rect(kvm);
            if (status != BC_OK) return status;
            if (kvm->phase == KVM_MSG_RECT_HEADER) continue;
            return BC_OK;
        }
        if (kvm->phase >= KVM_MSG_HEXTILE_FLAGS && kvm->phase <= KVM_MSG_HEXTILE_RAW) {
            uint32_t before_length = kvm->inlen, before_pixel = kvm->rect_pixel;
            uint8_t before_phase = kvm->phase;
            uint16_t before_x = kvm->tile_x, before_y = kvm->tile_y;
            bc_status status = hextile_step(kvm);
            if (status != BC_OK) return status;
            if (kvm->inlen == before_length && kvm->rect_pixel == before_pixel &&
                kvm->phase == before_phase && kvm->tile_x == before_x && kvm->tile_y == before_y) return BC_OK;
            if (kvm->phase == KVM_MSG_RECT_HEADER) {
                bc_status finished = finish_rect(kvm);
                if (finished != BC_OK) return finished;
            }
            continue;
        }
        return BC_PROTOCOL_ERROR;
    }
}

static bc_status parse(bc_kvm *kvm) {
    if (kvm->extension && (kvm->state == KVM_VERSION || kvm->state == KVM_SECURITY_TYPES) &&
        kvm->inlen && kvm->inbuf[0] == kvm->extension_type) return parse_extension(kvm);
    switch (kvm->state) {
    case KVM_VERSION: {
        uint8_t *data = need(kvm, 12);
        if (!data) return BC_OK;
        if (memcmp(data, "RFB 003.", 8) || data[11] != '\n' ||
            data[8] < '0' || data[8] > '9' || data[9] < '0' || data[9] > '9' || data[10] < '0' || data[10] > '9') return BC_UNSUPPORTED;
        unsigned minor = (unsigned)(data[8] - '0') * 100 + (unsigned)(data[9] - '0') * 10 + (unsigned)(data[10] - '0');
        if (minor < 3) {
            BC_LOG_WARN(BC_LOG_CATEGORY_KVM, "kvm.version", "version=RFB_003.%03u supported=0", minor);
            return BC_UNSUPPORTED;
        }
        kvm->version = minor >= 8 ? 8 : minor >= 7 ? 7 : 3;
        BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "kvm.version", "version=RFB_003.%03u selected=%u", minor, kvm->version);
        drop(kvm, 12);
        const char *version = kvm->version == 8 ? "RFB 003.008\n" : kvm->version == 7 ? "RFB 003.007\n" : "RFB 003.003\n";
        bc_status status = queue(kvm, (const uint8_t *)version, 12);
        if (status != BC_OK) return status;
        kvm->state = KVM_SECURITY_TYPES;
        return BC_OK;
    }
    case KVM_SECURITY_TYPES: {
        if (kvm->version == 3) {
            uint8_t *data = need(kvm, 4);
            if (!data) return BC_OK;
            uint32_t type = (uint32_t)bc_wire_read_be(data, 4);
            drop(kvm, 4);
            if (!type) return BC_AUTHENTICATION_FAILED;
            if (type != 1) return BC_UNSUPPORTED;
            uint8_t shared = 1;
            bc_status status = queue(kvm, &shared, 1);
            if (status != BC_OK) return status;
            kvm->state = KVM_SERVER_INIT;
            return BC_OK;
        }
        uint8_t *data = need(kvm, 1);
        if (!data) return BC_OK;
        uint8_t count = data[0];
        if (!count) {
            BC_LOG_WARN(BC_LOG_CATEGORY_KVM, "kvm.security", "types=0 supported=0");
            return BC_AUTHENTICATION_FAILED;
        }
        if (kvm->inlen < 1u + count) return BC_OK;
        int selection = 0;
        for (uint8_t i = 0; i < count; ++i) if (kvm->inbuf[1 + i] == 1) selection = 1;
        drop(kvm, 1u + count);
        if (!selection) {
            BC_LOG_WARN(BC_LOG_CATEGORY_KVM, "kvm.security", "types=%u selected=none supported=0", count);
            return BC_UNSUPPORTED;
        }
        BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "kvm.security", "types=%u selected=None(1)", count);
        uint8_t type = 1;
        bc_status status = queue(kvm, &type, 1);
        if (status != BC_OK) return status;
        if (kvm->version == 7) {
            status = queue(kvm, &type, 1);
            if (status != BC_OK) return status;
            kvm->state = KVM_SERVER_INIT;
        } else kvm->state = KVM_SECURITY_RESULT;
        return BC_OK;
    }
    case KVM_SECURITY_RESULT: {
        uint8_t *data = need(kvm, 4);
        if (!data) return BC_OK;
        uint32_t result = (uint32_t)bc_wire_read_be(data, 4);
        drop(kvm, 4);
        if (result) return BC_AUTHENTICATION_FAILED;
        uint8_t shared = 1;
        bc_status status = queue(kvm, &shared, 1);
        if (status != BC_OK) return status;
        kvm->state = KVM_SERVER_INIT;
        return BC_OK;
    }
    case KVM_SERVER_INIT:
        return parse_server_init(kvm);
    case KVM_READY:
        return parse_ready(kvm);
    default:
        return BC_PROTOCOL_ERROR;
    }
}

bc_status bc_kvm_create(const bc_kvm_options *options, bc_kvm **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        (!options->framebuffer && options->framebuffer_capacity)) return BC_INVALID_ARGUMENT;
    int owned = !options->framebuffer;
    uint32_t max_width = options->max_width ? options->max_width : (owned ? KVM_MAX_DIMENSION : BC_KVM_DEFAULT_MAX_WIDTH);
    uint32_t max_height = options->max_height ? options->max_height : (owned ? KVM_MAX_DIMENSION : BC_KVM_DEFAULT_MAX_HEIGHT);
    if (max_width > KVM_MAX_DIMENSION || max_height > (owned ? KVM_MAX_DIMENSION : 2160u)) return BC_INVALID_ARGUMENT;
    if (!owned && (uint64_t)max_width * max_height * KVM_BYTES_PER_PIXEL > options->framebuffer_capacity)
        return BC_LIMIT_EXCEEDED;
    bc_kvm *kvm = calloc(1, sizeof(*kvm));
    if (!kvm) return BC_NO_MEMORY;
    kvm->max_width = max_width;
    kvm->max_height = max_height;
    kvm->framebuffer = options->framebuffer;
    kvm->framebuffer_capacity = options->framebuffer_capacity;
    kvm->owns_framebuffer = (uint8_t)owned;
    kvm->framebuffer_limit = owned ? KVM_MAX_FRAME_BYTES : options->framebuffer_capacity;
    kvm->frame.struct_size = sizeof(kvm->frame);
    *out = kvm;
    BC_LOG_INFO(BC_LOG_CATEGORY_KVM, "kvm.create", "max_width=%u max_height=%u framebuffer=%" PRIu64,
        max_width, max_height, options->framebuffer_capacity);
    return BC_OK;
}

bc_status bc_kvm_set_extension_handler(bc_kvm *kvm, uint8_t message_type,
    bc_kvm_extension_handler handler, void *userdata) {
    if (!kvm || kvm->state != KVM_VERSION || kvm->inlen || kvm->outlen || message_type < 240)
        return BC_INVALID_ARGUMENT;
    kvm->extension = handler;
    kvm->extension_userdata = userdata;
    kvm->extension_type = message_type;
    return BC_OK;
}

int bc_kvm_handshake_complete(const bc_kvm *kvm) { return kvm && kvm->state == KVM_READY; }

int bc_kvm_extension_boundary(const bc_kvm *kvm) {
    return kvm && !kvm->inlen && (kvm->state == KVM_VERSION || kvm->state == KVM_SECURITY_TYPES ||
        (kvm->state == KVM_READY && kvm->phase == KVM_MSG_NONE && !kvm->skip));
}

static bc_status parse_all(bc_kvm *kvm) {
    for (;;) {
        uint32_t inlen = kvm->inlen, outlen = kvm->outlen, pixel = kvm->rect_pixel;
        uint8_t state = kvm->state, phase = kvm->phase;
        bc_status status = parse(kvm);
        if (status != BC_OK) { kvm->state = KVM_FAILED; return status; }
        if (kvm->inlen == inlen && kvm->outlen == outlen && kvm->rect_pixel == pixel &&
            kvm->state == state && kvm->phase == phase) {
            BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "kvm.waiting",
                "state=%u phase=%u inlen=%u rects=%u tile=%u,%u rect=%u,%u,%u,%u",
                kvm->state, kvm->phase, kvm->inlen, kvm->rect_count, kvm->tile_x, kvm->tile_y,
                kvm->rect_x, kvm->rect_y, kvm->rect_w, kvm->rect_h);
            return BC_OK;
        }
    }
}

bc_status bc_kvm_feed(bc_kvm *kvm, const uint8_t *data, uint32_t length) {
    if (!kvm || (length && !data)) return BC_INVALID_ARGUMENT;
    if (kvm->state == KVM_FAILED) return BC_PROTOCOL_ERROR;
    while (length) {
        uint32_t room = (uint32_t)sizeof(kvm->inbuf) - kvm->inlen;
        if (!room) return BC_LIMIT_EXCEEDED;
        uint32_t count = length < room ? length : room;
        memcpy(kvm->inbuf + kvm->inlen, data, count);
        kvm->inlen += count;
        data += count;
        length -= count;
        bc_status status = parse_all(kvm);
        if (status != BC_OK) return status;
    }
    return BC_OK;
}

bc_status bc_kvm_output(bc_kvm *kvm, uint8_t *data, uint32_t capacity, uint32_t *written) {
    if (!kvm || !written || (capacity && !data)) return BC_INVALID_ARGUMENT;
    uint32_t count = kvm->outlen < capacity ? kvm->outlen : capacity;
    if (count) memcpy(data, kvm->outbuf, count);
    memmove(kvm->outbuf, kvm->outbuf + count, kvm->outlen - count);
    kvm->outlen -= count;
    *written = count;
    return BC_OK;
}

const bc_kvm_frame *bc_kvm_frame_get(const bc_kvm *kvm) {
    if (!kvm) return NULL;
    bc_kvm *mutable = (bc_kvm *)kvm;
    mutable->frame.flags = kvm->state == KVM_FAILED ? 0 : kvm->flags;
    mutable->frame.width = kvm->width;
    mutable->frame.height = kvm->height;
    mutable->frame.stride = kvm->stride;
    mutable->frame.pixels = kvm->framebuffer;
    mutable->frame.name = (bc_string){(const char *)kvm->name, kvm->name_length};
    mutable->frame.name_length = kvm->name_length;
    return &mutable->frame;
}

void bc_kvm_ack_frame(bc_kvm *kvm) { if (kvm) kvm->flags &= ~BC_KVM_FRAME_READY; }

#ifndef BC_KVM_DECODE_ONLY
bc_status bc_kvm_key_encode(int down, uint32_t keysym, uint8_t *out, uint32_t capacity) {
    if (!out) return BC_INVALID_ARGUMENT;
    if (capacity < BC_KVM_KEY_EVENT_SIZE) return BC_LIMIT_EXCEEDED;
    memset(out, 0, BC_KVM_KEY_EVENT_SIZE);
    out[0] = 4; out[1] = (uint8_t)(down ? 1 : 0);
    bc_wire_write_be(out + 4, keysym, 4);
    return BC_OK;
}
bc_status bc_kvm_pointer_encode(uint8_t buttons, uint16_t x, uint16_t y,
    uint32_t width, uint32_t height, uint8_t *out, uint32_t capacity) {
    if (!out || x >= width || y >= height) return BC_INVALID_ARGUMENT;
    if (capacity < BC_KVM_POINTER_EVENT_SIZE) return BC_LIMIT_EXCEEDED;
    out[0] = 5; out[1] = buttons;
    bc_wire_write_be(out + 2, x, 2); bc_wire_write_be(out + 4, y, 2);
    return BC_OK;
}

bc_status bc_kvm_key_event(bc_kvm *kvm, int down, uint32_t keysym) {
    if (!kvm) return BC_INVALID_ARGUMENT;
    if (kvm->state != KVM_READY) return BC_BUSY;
    uint8_t event[BC_KVM_KEY_EVENT_SIZE];
    bc_status status = bc_kvm_key_encode(down, keysym, event, sizeof(event));
    if (status != BC_OK) return status;
    return queue(kvm, event, sizeof(event));
}

bc_status bc_kvm_pointer_event(bc_kvm *kvm, uint8_t buttons, uint16_t x, uint16_t y) {
    if (!kvm) return BC_INVALID_ARGUMENT;
    if (kvm->state != KVM_READY) return BC_BUSY;
    uint8_t event[BC_KVM_POINTER_EVENT_SIZE];
    bc_status status = bc_kvm_pointer_encode(buttons, x, y, kvm->width, kvm->height, event, sizeof(event));
    if (status != BC_OK) return status;
    return queue(kvm, event, sizeof(event));
}
#endif

bc_status bc_kvm_close(bc_kvm *kvm) {
    if (!kvm) return BC_INVALID_ARGUMENT;
    kvm->state = KVM_FAILED;
    BC_LOG_INFO(BC_LOG_CATEGORY_KVM, "kvm.close", "width=%u height=%u", kvm->width, kvm->height);
    return BC_OK;
}

void bc_kvm_destroy(bc_kvm *kvm) {
    if (kvm) BC_LOG_INFO(BC_LOG_CATEGORY_KVM, "kvm.destroy", "width=%u height=%u", kvm->width, kvm->height);
    if (kvm) free(kvm->jpeg);
    if (kvm && kvm->owns_framebuffer) free(kvm->framebuffer);
    free(kvm);
}

#ifndef BC_KVM_DECODE_ONLY
static int contains(const uint8_t *data, uint32_t length, const char *needle) {
    size_t n = strlen(needle);
    if (!n || n > length) return 0;
    for (uint32_t i = 0; i + n <= length; ++i) if (!memcmp(data + i, needle, n)) return 1;
    return 0;
}

bc_status bc_kvm_classify_console(const uint8_t *data, uint32_t length, bc_kvm_detection *out) {
    if (!out || (length && !data)) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->flags = BC_KVM_DETECTION_INFERRED;
    if (contains(data, length, "JViewer") || contains(data, length, "jviewer") || contains(data, length, "com.ami.kvm")) {
        out->vendor = BC_KVM_VENDOR_MEGARAC;
        out->protocol = BC_KVM_CONSOLE_JVNL;
    } else if (contains(data, length, "H5Viewer") || contains(data, length, "h5viewer") || contains(data, length, "MegaRAC")) {
        out->vendor = BC_KVM_VENDOR_MEGARAC;
        out->protocol = BC_KVM_CONSOLE_HTML5;
    } else if (contains(data, length, "iDRAC") || contains(data, length, "com.avocent.idrac")) {
        out->vendor = BC_KVM_VENDOR_IDRAC;
        out->protocol = BC_KVM_CONSOLE_JVNL;
    } else if (contains(data, length, "com.avocent.kvm.client.Main") ||
        contains(data, length, "avctKVM") || contains(data, length, "MergePoint") || contains(data, length, "Avocent")) {
        out->vendor = BC_KVM_VENDOR_AVOCENT;
        out->protocol = BC_KVM_CONSOLE_JVNL;
    } else if (contains(data, length, "iLO") || contains(data, length, "HPE") || contains(data, length, "hp.ilo")) {
        out->vendor = BC_KVM_VENDOR_ILO;
        out->protocol = BC_KVM_CONSOLE_HTML5;
    } else if (contains(data, length, "ILOM") || contains(data, length, "ilom")) {
        out->vendor = BC_KVM_VENDOR_ILOM;
        out->protocol = BC_KVM_CONSOLE_HTML5;
    } else if (contains(data, length, "iBMC") || contains(data, length, "Huawei")) {
        out->vendor = BC_KVM_VENDOR_IBMC;
        out->protocol = BC_KVM_CONSOLE_HTML5;
    } else if (contains(data, length, "obmc-ikvm") || contains(data, length, "bmcweb") || contains(data, length, "noVNC")) {
        out->vendor = BC_KVM_VENDOR_OPENBMC;
        out->protocol = BC_KVM_CONSOLE_WS_RFB;
    } else if (contains(data, length, "RFB 003")) {
        out->vendor = BC_KVM_VENDOR_GENERIC;
        out->protocol = BC_KVM_CONSOLE_RFB;
    } else {
        out->vendor = BC_KVM_VENDOR_UNKNOWN;
    }
    BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "kvm.classify", "vendor=%u protocol=%u flags=%u",
        out->vendor, out->protocol, out->flags);
    return BC_OK;
}

const char *bc_kvm_vendor_name(uint32_t vendor) {
    switch (vendor) {
    case BC_KVM_VENDOR_GENERIC: return "generic";
    case BC_KVM_VENDOR_OPENBMC: return "openbmc";
    case BC_KVM_VENDOR_MEGARAC: return "megarac";
    case BC_KVM_VENDOR_ILO: return "ilo";
    case BC_KVM_VENDOR_IDRAC: return "idrac";
    case BC_KVM_VENDOR_IBMC: return "ibmc";
    case BC_KVM_VENDOR_ILOM: return "ilom";
    case BC_KVM_VENDOR_SUPERMICRO: return "supermicro";
    default: return "unknown";
    }
}

const char *bc_kvm_console_name(uint32_t protocol) {
    switch (protocol) {
    case BC_KVM_CONSOLE_RFB: return "rfb";
    case BC_KVM_CONSOLE_WS_RFB: return "websocket-rfb";
    case BC_KVM_CONSOLE_JVNL: return "jnlp";
    case BC_KVM_CONSOLE_HTML5: return "html5";
    default: return "unknown";
    }
}

#endif

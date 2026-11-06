#include "video_internal.h"
#include <stdlib.h>
#include <string.h>

enum phase {
    BEGIN, PIXEL, COLOR_KIND, LITERAL_KIND, GRAY, RGB, CACHE, SECOND_COLOR,
    REPEAT, REPEAT_KIND, REPEAT_SHORT, REPEAT_MEDIUM, REPEAT_LONG,
    COMMAND, COMMAND_KIND, MOVE_KIND, MOVE_SHORT, MOVE_LONG, MOVE_X, MOVE_Y,
    EXTENSION, EXTENSION_KIND, MODE_OR_ALIGN, MODE_X, MODE_Y, MODE_TAIL,
    BLOCK_REPEAT, BLOCK_REPEAT_KIND, BLOCK_SHORT, BLOCK_LONG,
    CONTROL_BYTE, CONTROL_MORE, TEXT_CHANNEL, TEXT_BYTE, STOPPED
};
struct bc_ilo_video {
    bc_ilo_bits bits;
    bc_ilo_palette palette;
    bc_kvm_frame frame;
    uint32_t max_width, max_height, x, y, new_x, new_y, used;
    uint16_t tile[256], last;
    uint8_t phase, bpc, tile_height, cache_width, control[32], control_size;
    uint8_t ack, power, license, text_channel;
    uint32_t zeros;
    int hunting;
    bc_status failure;
};
static bc_status resize_frame(bc_ilo_video *v, uint32_t width, uint32_t height) {
    if (!width || !height || width > v->max_width || height > v->max_height ||
        width > UINT32_MAX / 4 || height > SIZE_MAX / ((size_t)width * 4)) return BC_LIMIT_EXCEEDED;
    uint8_t *pixels = calloc(height, (size_t)width * 4);
    if (!pixels) return BC_NO_MEMORY;
    free((void *)v->frame.pixels); v->frame.pixels = pixels;
    v->frame.width = width; v->frame.height = height; v->frame.stride = width * 4;
    v->frame.flags |= BC_KVM_DESKTOP_RESIZED | BC_KVM_FRAME_READY;
    v->tile_height = width > 1616 ? 8 : 16;
    v->x = v->y = v->used = 0;
    memset(&v->palette, 0, sizeof(v->palette));
    return BC_OK;
}
static bc_status blocks(bc_ilo_video *v, unsigned count) {
    if (!v->frame.pixels) return BC_PROTOCOL_ERROR;
    for (unsigned i = 0; i < count; ++i) {
        bc_status s = bc_ilo_blit(&v->frame, v->tile, v->x * 16, v->y * v->tile_height, v->tile_height, v->bpc);
        if (s != BC_OK) return s;
        if (++v->x >= v->frame.width / 16) { v->x = 0; ++v->y; }
        if (v->y * v->tile_height >= v->frame.height) v->y = 0;
    }
    v->used = 0; v->phase = BEGIN; return BC_OK;
}
static bc_status pixels(bc_ilo_video *v, uint16_t color, unsigned count) {
    if (count > 16u * v->tile_height - v->used) return BC_PROTOCOL_ERROR;
    while (count--) v->tile[v->used++] = color;
    v->last = color; return BC_OK;
}
static unsigned field_width(const bc_ilo_video *v) {
    switch (v->phase) {
    case GRAY: return v->bpc;
    case RGB: return 3u * v->bpc;
    case CACHE: return v->cache_width;
    case REPEAT_SHORT: case REPEAT_MEDIUM: case MOVE_SHORT: case BLOCK_SHORT: return 3;
    case REPEAT_LONG: case CONTROL_BYTE: case TEXT_CHANNEL: case TEXT_BYTE: return 8;
    case MOVE_LONG: case MOVE_X: case MOVE_Y: case BLOCK_LONG: return v->tile_height == 8 ? 8 : 7;
    case MODE_X: case MODE_Y: return 7;
    case MODE_TAIL: return 4;
    default: return 1;
    }
}
static bc_status control(bc_ilo_video *v) {
    unsigned count = v->control_size;
    if (!count) return BC_PROTOCOL_ERROR;
    uint8_t cmd = v->control[count - 1];
    v->phase = BEGIN;
    switch (cmd) {
    case 1: v->phase = STOPPED; break;
    case 2: v->phase = TEXT_CHANNEL; break;
    case 4: v->power = 1; break;
    case 5: v->power = 0; /* fall through */
    case 6: case 10:
        if (v->frame.pixels) {
            memset((void *)v->frame.pixels, 0, (size_t)v->frame.stride * v->frame.height);
            v->frame.flags |= BC_KVM_FRAME_READY;
        }
        break;
    case 9: v->bits.pending >>= v->bits.count % 8; v->bits.count -= v->bits.count % 8; break;
    case 11:
        if (count < 2) return BC_PROTOCOL_ERROR;
        v->bpc = 5 - (v->control[0] & 3); break;
    case 13:
        if (count < 5) return BC_PROTOCOL_ERROR;
        v->bpc = 5 - (v->control[0] & 3); v->license = v->control[2]; break;
    case 16: v->ack = 1; break;
    default: break;
    }
    v->control_size = 0; return BC_OK;
}
static bc_status advance(bc_ilo_video *v, uint16_t code) {
    bc_status status = BC_OK; uint16_t color = 0;
    switch (v->phase) {
    case BEGIN: v->phase = code ? COMMAND : PIXEL; break;
    case PIXEL: v->phase = code ? SECOND_COLOR : COLOR_KIND; break;
    case COLOR_KIND:
        if (!code) v->phase = LITERAL_KIND;
        else {
            v->cache_width = bc_ilo_palette_bits(&v->palette);
            if (!v->cache_width) return BC_PROTOCOL_ERROR;
            v->phase = CACHE;
        }
        break;
    case LITERAL_KIND: v->phase = code ? RGB : GRAY; break;
    case GRAY: case RGB:
        color = v->phase == RGB ? code : (uint16_t)((code << (2*v->bpc)) | (code << v->bpc) | code);
        color = (uint16_t)((color << 1) | 1);
        bc_ilo_palette_insert(&v->palette,color);
        status = pixels(v,color,1); v->phase = REPEAT; break;
    case CACHE: case SECOND_COLOR: {
        unsigned index = v->palette.count == 1 || (v->phase == CACHE && v->palette.count == 2) ? 0 :
            v->phase == SECOND_COLOR ? 1 : code ? code + 1u : 0;
        status = bc_ilo_palette_get(&v->palette,(uint8_t)index,&color);
        if (status == BC_OK) status = pixels(v,color,1);
        v->phase = v->phase == SECOND_COLOR || v->palette.count == 2 ? (code ? REPEAT_KIND : PIXEL) : REPEAT;
        break;
    }
    case REPEAT: v->phase = code ? REPEAT_KIND : PIXEL; break;
    case REPEAT_KIND:
        v->phase = code ? REPEAT_SHORT : PIXEL;
        if (!code) status = pixels(v,v->last,1);
        break;
    case REPEAT_SHORT:
        v->phase = code == 7 ? REPEAT_LONG : code == 6 ? REPEAT_MEDIUM : PIXEL;
        if (code < 6) status = pixels(v,v->last,code+2);
        break;
    case REPEAT_MEDIUM: case REPEAT_LONG:
        status = pixels(v,v->last,code+(v->phase==REPEAT_MEDIUM?8:0)); v->phase=PIXEL; break;
    case COMMAND: v->phase = code ? MOVE_X : COMMAND_KIND; break;
    case COMMAND_KIND: v->phase = code ? EXTENSION : MOVE_KIND; break;
    case MOVE_KIND: v->phase = code ? MOVE_LONG : MOVE_SHORT; break;
    case MOVE_SHORT: v->x += code+1; v->phase=BEGIN; break;
    case MOVE_LONG: v->x=code; v->phase=BEGIN; break;
    case MOVE_X: v->new_x=code; v->phase=MOVE_Y; break;
    case MOVE_Y: v->x=v->new_x; v->y=code; v->phase=BEGIN; break;
    case EXTENSION: v->phase=code?EXTENSION_KIND:BLOCK_REPEAT; break;
    case EXTENSION_KIND: v->phase=code?CONTROL_BYTE:MODE_OR_ALIGN; break;
    case MODE_OR_ALIGN:
        if (code) { v->bits.pending >>= v->bits.count%8; v->bits.count -= v->bits.count%8; v->phase=BEGIN; }
        else v->phase=MODE_X;
        break;
    case MODE_X: v->new_x=code; v->phase=MODE_Y; break;
    case MODE_Y: v->new_y=code; v->phase=MODE_TAIL; break;
    case MODE_TAIL:
        if (!v->new_x || !v->new_y) { v->new_x=50; v->new_y=38; }
        status=resize_frame(v,v->new_x*16,v->new_y*16+code); v->phase=BEGIN; break;
    case BLOCK_REPEAT:
        if (code) v->phase=BLOCK_REPEAT_KIND; else status=blocks(v,1); break;
    case BLOCK_REPEAT_KIND: v->phase=code?BLOCK_LONG:BLOCK_SHORT; break;
    case BLOCK_SHORT: case BLOCK_LONG: status=blocks(v,code+(v->phase==BLOCK_SHORT?2:0)); break;
    case CONTROL_BYTE:
        if (v->control_size==sizeof(v->control)) return BC_LIMIT_EXCEEDED;
        v->control[v->control_size++]=(uint8_t)code; v->phase=CONTROL_MORE; break;
    case CONTROL_MORE: if (code) v->phase=CONTROL_BYTE; else status=control(v); break;
    case TEXT_CHANNEL: v->text_channel=(uint8_t)code; v->phase=TEXT_BYTE; break;
    case TEXT_BYTE: if (!code) v->phase=BEGIN; break;
    default: return BC_PROTOCOL_ERROR;
    }
    if (status==BC_OK && v->phase==PIXEL && v->used==16u*v->tile_height) {
        status=blocks(v,1); bc_ilo_palette_prune(&v->palette);
    }
    return status;
}
bc_status bc_ilo_video_create(uint32_t width, uint32_t height, bc_ilo_video **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out=NULL;
    if (!width || !height || width>8192 || height>8192) return BC_INVALID_ARGUMENT;
    bc_ilo_video *v=calloc(1,sizeof(*v)); if (!v) return BC_NO_MEMORY;
    v->max_width=width; v->max_height=height; v->bpc=4; v->tile_height=16;
    v->frame.struct_size=sizeof(v->frame); *out=v; return BC_OK;
}
bc_status bc_ilo_video_feed(bc_ilo_video *v, const uint8_t *data, uint32_t size) {
    if (!v || (!data && size)) return BC_INVALID_ARGUMENT;
    if (v->failure!=BC_OK) return v->failure;
    for (uint32_t i=0;i<size;++i) {
        uint8_t byte=data[i]; unsigned leading=0;
        while (leading<8 && !(byte & (1u<<leading))) ++leading;
        v->zeros += leading;
        if (v->zeros>30) { v->hunting=1; v->bits=(bc_ilo_bits){0}; }
        if (byte) { v->zeros=0; for (int bit=7;bit>=0 && !(byte&(1u<<bit));--bit) ++v->zeros; }
        if (v->hunting) {
            if (!byte) continue;
            v->hunting=0; v->phase=BEGIN; v->bits=(bc_ilo_bits){0}; v->used=v->x=v->y=0;
            memset(&v->palette,0,sizeof(v->palette)); continue;
        }
        bc_status status=bc_ilo_bits_append(&v->bits,byte);
        if (status!=BC_OK) return v->failure=status;
        while (v->phase!=STOPPED) {
            uint16_t code;
            if (!bc_ilo_bits_take(&v->bits,(uint8_t)field_width(v),&code)) break;
            status=advance(v,code);
            if (status!=BC_OK) return v->failure=status;
        }
        if (v->phase==STOPPED) break;
    }
    return BC_OK;
}
const bc_kvm_frame *bc_ilo_video_frame(const bc_ilo_video *v) { return v?&v->frame:NULL; }
void bc_ilo_video_destroy(bc_ilo_video *v) { if(v) {free((void *)v->frame.pixels);free(v);} }

int bc_ilo_video_take_ack(bc_ilo_video *v) { int ack=v->ack; v->ack=0; return ack; }
void bc_ilo_video_ack_frame(bc_ilo_video *v) { if(v) v->frame.flags &= ~(BC_KVM_FRAME_READY | BC_KVM_DESKTOP_RESIZED); }

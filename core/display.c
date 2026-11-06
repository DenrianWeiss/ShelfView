#include "bcontrol/display.h"

bc_status bc_display_tile_validate(const bc_display_tile *tile) {
    if (!tile || tile->struct_size != sizeof(*tile)) return BC_INVALID_ARGUMENT;
    if (tile->pixel_format != BC_PIXEL_RGBA8) return BC_UNSUPPORTED;
    if (!tile->width || !tile->height || !tile->pixels.data ||
        tile->x > tile->canvas_width || tile->width > tile->canvas_width - tile->x ||
        tile->y > tile->canvas_height || tile->height > tile->canvas_height - tile->y ||
        (uint64_t)tile->width * 4 > tile->stride) return BC_INVALID_ARGUMENT;
    uint64_t required = (uint64_t)(tile->height - 1) * tile->stride + (uint64_t)tile->width * 4;
    return required <= tile->pixels.length ? BC_OK : BC_INVALID_ARGUMENT;
}

bc_status bc_display_tile_from_frame(const bc_kvm_frame *frame, bc_display_tile *out) {
    if (!out || out->struct_size != sizeof(*out) || !frame || frame->struct_size != sizeof(*frame))
        return BC_INVALID_ARGUMENT;
    if (!(frame->flags & BC_KVM_FRAME_READY)) return BC_BUSY;
    bc_display_tile tile = {sizeof(tile), BC_PIXEL_RGBA8, frame->width, frame->height,
        0, 0, frame->width, frame->height, frame->stride,
        {frame->pixels, (uint64_t)frame->stride * frame->height}};
    bc_status status = bc_display_tile_validate(&tile);
    if (status == BC_OK) *out = tile;
    return status;
}

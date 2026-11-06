#include "bcontrol/display.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

int main(void) {
    uint8_t pixels[24] = {0};
    bc_display_tile tile = {sizeof(tile), BC_PIXEL_RGBA8, 8, 8, 6, 6, 2, 2, 16, {pixels, sizeof(pixels)}};
    CHECK(bc_display_tile_validate(&tile) == BC_OK);
    tile.pixels.length = 23;
    CHECK(bc_display_tile_validate(&tile) == BC_INVALID_ARGUMENT);
    tile.pixels.length = sizeof(pixels);
    tile.x = UINT32_MAX;
    CHECK(bc_display_tile_validate(&tile) == BC_INVALID_ARGUMENT);
    tile.x = 6; tile.stride = 7;
    CHECK(bc_display_tile_validate(&tile) == BC_INVALID_ARGUMENT);
    bc_kvm_frame frame = {0};
    frame.struct_size = sizeof(frame); frame.width = 2; frame.height = 2;
    frame.stride = 8; frame.pixels = pixels;
    CHECK(bc_display_tile_from_frame(&frame, &tile) == BC_BUSY);
    frame.flags = BC_KVM_FRAME_READY;
    CHECK(bc_display_tile_from_frame(&frame, &tile) == BC_OK);
    CHECK(tile.x == 0 && tile.y == 0 && tile.canvas_width == 2 && tile.pixels.length == 16);
    CHECK(tile.pixels.data == pixels);
    puts("display: tile bounds, padded rows and borrowed full frames passed");
    return 0;
}

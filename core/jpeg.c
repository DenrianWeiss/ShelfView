#include "jpeg.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <jpeglib.h>

typedef struct { struct jpeg_error_mgr base; jmp_buf jump; } jpeg_error;
static void failure(j_common_ptr jpeg) { longjmp(((jpeg_error *)jpeg->err)->jump, 1); }
static void quiet(j_common_ptr jpeg) { (void)jpeg; }
bc_status bc_jpeg_decode(const uint8_t *data, uint32_t size, uint8_t *pixels, uint32_t width, uint32_t height, uint32_t stride) {
    if (!data || !size || !pixels || !width || !height || width > 4096 || height > 4096 || stride < width * 4) return BC_INVALID_ARGUMENT;
    struct jpeg_decompress_struct *jpeg = calloc(1, sizeof(*jpeg));
    if (!jpeg) return BC_NO_MEMORY;
    jpeg_error error;
    jpeg->err = jpeg_std_error(&error.base); error.base.error_exit = failure; error.base.output_message = quiet;
    if (setjmp(error.jump)) { jpeg_destroy_decompress(jpeg); free(jpeg); return BC_PROTOCOL_ERROR; }
    jpeg_create_decompress(jpeg);
    jpeg_mem_src(jpeg, data, size);
    bc_status status = BC_PROTOCOL_ERROR;
    if (jpeg_read_header(jpeg, TRUE) == JPEG_HEADER_OK && jpeg->image_width == width && jpeg->image_height == height && jpeg->data_precision == 8) {
        jpeg->out_color_space = JCS_EXT_RGBA;
        if (jpeg_start_decompress(jpeg) && jpeg->output_width == width && jpeg->output_height == height && jpeg->output_components == 4) {
            while (jpeg->output_scanline < height) {
                JSAMPROW row = pixels + (uint64_t)jpeg->output_scanline * stride;
                if (jpeg_read_scanlines(jpeg, &row, 1) != 1) break;
            }
            if (jpeg->output_scanline == height && jpeg_finish_decompress(jpeg)) status = BC_OK;
        }
    }
    jpeg_destroy_decompress(jpeg); free(jpeg); return status;
}

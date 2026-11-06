#ifndef BCONTROL_DISPLAY_H
#define BCONTROL_DISPLAY_H
#include "kvm.h"
#ifdef __cplusplus
extern "C" {
#endif

#define BC_DISPLAY_TILE 1u
#define BC_DISPLAY_MEDIA_STREAM 2u
#define BC_PIXEL_RGBA8 1u
#define BC_STREAM_KEYFRAME 1u
#define BC_STREAM_DISCONTINUITY 2u
#define BC_STREAM_CONFIGURATION 4u

/* RGBA8 is four bytes in R,G,B,A order on every architecture, not a native u32.
 * Borrowed pixels remain valid only until the producer is advanced or acknowledged. */
typedef struct {
    uint32_t struct_size, pixel_format;
    uint32_t canvas_width, canvas_height;
    uint32_t x, y, width, height, stride;
    bc_bytes pixels;
} bc_display_tile;

/* Reserved: no current adapter advertises MEDIA_STREAM. Codec is an explicit
 * codec identifier, configuration and packets retain codec-defined byte order.
 * A new stream_id resets decoder state. Timestamp units are timebase_num/den seconds. */
typedef struct {
    uint32_t struct_size, flags;
    uint64_t stream_id;
    bc_string codec;
    uint32_t width, height, timebase_num, timebase_den;
    int64_t presentation_time, decode_time;
    bc_bytes payload;
} bc_display_stream_packet;

/* Adapts existing full-frame decoders to the shared tile contract without copying. */
BC_API bc_status bc_display_tile_from_frame(const bc_kvm_frame *, bc_display_tile *);
BC_API bc_status bc_display_tile_validate(const bc_display_tile *);

#ifdef __cplusplus
}
#endif
#endif

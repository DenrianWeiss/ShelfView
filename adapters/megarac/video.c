#include "megarac.h"
#include "bcontrol/wire.h"
#include "../ast/video.h"
#include "../ast/tables.h"

#define AST_TABLE_MASK 7u

bc_status bc_megarac_video_create(bc_megarac_video **out) { return bc_ast_video_create((bc_ast_video **)out); }
void bc_megarac_video_destroy(bc_megarac_video *video) { bc_ast_video_destroy((bc_ast_video *)video); }

bc_status bc_megarac_ast_header(const uint8_t *frame, bc_megarac_video_header *out) {
    if (frame[44] > AST_TABLE_MASK || frame[47] > AST_TABLE_MASK) return BC_PROTOCOL_ERROR;
    *out = (bc_megarac_video_header){
        sizeof(*out), (uint32_t)bc_wire_read_le(frame + 13, 2), (uint32_t)bc_wire_read_le(frame + 15, 2),
        (uint32_t)bc_wire_read_le(frame + 4, 2), (uint32_t)bc_wire_read_le(frame + 6, 2),
        (uint32_t)bc_wire_read_le(frame + 69, 4), (uint32_t)bc_wire_read_le(frame + 26, 4),
        (frame[53] == 1 ? BC_MEGARAC_VIDEO_RC4 : 0u) | (frame[55] ? BC_MEGARAC_VIDEO_420 : 0u) |
        ((uint32_t)frame[44] << BC_MEGARAC_VIDEO_JPEG_TABLE_SHIFT) |
        ((uint32_t)frame[47] << BC_MEGARAC_VIDEO_ADVANCE_TABLE_SHIFT) |
        (frame[45] == 1 ? BC_MEGARAC_VIDEO_YUV_TABLE_MAPPING : 0u)
    };
    return BC_OK;
}

bc_status bc_megarac_video_decode(bc_megarac_video *video, const uint8_t *frame, uint32_t length,
    uint8_t *rgba, uint32_t capacity, uint32_t *width, uint32_t *height) {
    if (!frame || length < BC_MEGARAC_AST_HEADER_SIZE) return BC_INVALID_ARGUMENT;
    bc_megarac_video_header info;
    bc_status status = bc_megarac_ast_header(frame, &info);
    uint32_t available = length - BC_MEGARAC_AST_HEADER_SIZE;
    if (status != BC_OK || info.compressed_size > available) return BC_PROTOCOL_ERROR;
    return bc_megarac_video_decode_payload(video, &info, frame + BC_MEGARAC_AST_HEADER_SIZE,
        info.compressed_size, rgba, capacity, width, height);
}

bc_status bc_megarac_video_decode_payload(bc_megarac_video *video, const bc_megarac_video_header *info,
    const uint8_t *payload, uint32_t length, uint8_t *rgba, uint32_t capacity, uint32_t *width, uint32_t *height) {
    const uint32_t known = BC_MEGARAC_VIDEO_RC4 | BC_MEGARAC_VIDEO_420 | BC_MEGARAC_VIDEO_YUV_TABLE_MAPPING |
        (AST_TABLE_MASK << BC_MEGARAC_VIDEO_JPEG_TABLE_SHIFT) | (AST_TABLE_MASK << BC_MEGARAC_VIDEO_ADVANCE_TABLE_SHIFT);
    if (!video || !info || info->struct_size != sizeof(*info) || info->compressed_size != length ||
        !width || !height || (info->flags & ~known)) return BC_INVALID_ARGUMENT;
    uint32_t q = (info->flags >> BC_MEGARAC_VIDEO_JPEG_TABLE_SHIFT) & AST_TABLE_MASK;
    uint32_t advance = (info->flags >> BC_MEGARAC_VIDEO_ADVANCE_TABLE_SHIFT) & AST_TABLE_MASK;
    int mapping = (info->flags & BC_MEGARAC_VIDEO_YUV_TABLE_MAPPING) != 0;
    bc_ast_parameters p = {info->width, info->height, (info->flags & BC_MEGARAC_VIDEO_420) != 0,
        (info->flags & BC_MEGARAC_VIDEO_RC4) != 0, 1, 0,
        {(const uint8_t *)ast_tbl_y[q], (const uint8_t *)(mapping ? ast_tbl_y[q] : ast_tbl_uv[q]),
         (const uint8_t *)ast_tbl_y[advance], (const uint8_t *)(mapping ? ast_tbl_y[advance] : ast_tbl_uv[advance])}};
    bc_status status = bc_ast_video_decode((bc_ast_video *)video, &p, payload, length, rgba, capacity);
    if (status == BC_OK) { *width = info->width; *height = info->height; }
    return status;
}

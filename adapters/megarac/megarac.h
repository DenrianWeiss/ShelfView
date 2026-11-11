#ifndef BCONTROL_MEGARAC_COMPAT_H
#define BCONTROL_MEGARAC_COMPAT_H
#include "bcontrol/megarac.h"

#define BC_MEGARAC_CURSOR_SIDE 64u
typedef struct {
    uint64_t revision;
    uint16_t x, y, x_offset, y_offset;
    uint8_t color, have_pattern, visible;
    uint16_t pattern[BC_MEGARAC_CURSOR_SIDE * BC_MEGARAC_CURSOR_SIDE];
} bc_megarac_cursor;

const bc_megarac_cursor *bc_megarac_session_cursor(const bc_megarac_session *);
int bc_megarac_session_is_irmc(const bc_megarac_session *);
bc_status bc_megarac_ast_header(const uint8_t *, bc_megarac_video_header *);
#endif

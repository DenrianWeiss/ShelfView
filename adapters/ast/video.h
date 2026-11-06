#ifndef BC_AST_VIDEO_H
#define BC_AST_VIDEO_H
#include "bcontrol/bcontrol.h"
typedef struct bc_ast_video bc_ast_video;
typedef struct {
    uint32_t width,height,mode420,rc4,legacy_quant,strict;
    const uint8_t *quant[4];
} bc_ast_parameters;
bc_status bc_ast_video_create(bc_ast_video **);
void bc_ast_video_destroy(bc_ast_video *);
bc_status bc_ast_video_decode(bc_ast_video *,const bc_ast_parameters *,const uint8_t *,uint32_t,uint8_t *,uint32_t);
#endif

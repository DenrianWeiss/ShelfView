#include "video.h"
#include "video_tables.h"
#include "bcontrol/wire.h"
bc_status bc_aten_ast_decode(bc_ast_video **video,const uint8_t *data,uint32_t length,
    uint32_t width,uint32_t height,uint8_t *rgba,uint32_t capacity){
    if(!video || !data)return BC_INVALID_ARGUMENT;
    if(length<8 || length%4)return BC_PROTOCOL_ERROR;
    uint32_t mode=(uint32_t)bc_wire_read_be(data+2,2);
    if(data[0]>11 || data[1]>11 || (mode!=422 && mode!=444))return BC_UNSUPPORTED;
    if(!*video){bc_status status=bc_ast_video_create(video);if(status!=BC_OK)return status;}
    bc_ast_parameters p={width,height,mode==422,0,0,1,
        {aten_luma[data[0]],aten_chroma[data[1]],aten_luma[data[0]],aten_chroma[data[1]]}};
    return bc_ast_video_decode(*video,&p,data+4,length-4,rgba,capacity);
}

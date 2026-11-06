#include "../adapters/aten/video.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
int main(int argc,char **argv){
    if(argc!=3)return 1;
#ifdef _WIN32
    _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
#endif
    uint32_t w=(uint32_t)strtoul(argv[1],NULL,10),h=(uint32_t)strtoul(argv[2],NULL,10);
    if(!w || !h || w>64 || h>64)return 1;
    uint8_t data[65536],pixels[64*64*4]={0};size_t n=fread(data,1,sizeof(data),stdin);
    bc_ast_video *video=NULL;bc_status status=bc_aten_ast_decode(&video,data,(uint32_t)n,w,h,pixels,sizeof(pixels));
    bc_ast_video_destroy(video);
    if(status!=BC_OK)return (int)status;
    return fwrite(pixels,4,(size_t)w*h,stdout)==(size_t)w*h?0:1;
}

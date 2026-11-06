#include "video_internal.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    FILE *f=fopen(argv[1],"rb");if(!f)return 3;
    bc_ilo_video *v=NULL; if(bc_ilo_video_create(4096,2160,&v)!=BC_OK)return 4;
    unsigned char byte;size_t offset=0;
    while(fread(&byte,1,1,f)) {
        bc_status s=bc_ilo_video_feed(v,&byte,1);
        if(s!=BC_OK){fprintf(stderr,"decode failed status=%u offset=%zu byte=%02x\n",s,offset,byte);return 5;}
        ++offset;
    }
    fclose(f);const bc_kvm_frame *frame=bc_ilo_video_frame(v);
    printf("bytes=%zu width=%u height=%u flags=%u\n",offset,frame->width,frame->height,frame->flags);
    if(!frame->pixels)return 6;
    f=fopen(argv[2],"wb");if(!f)return 7;
    fprintf(f,"P6\n%u %u\n255\n",frame->width,frame->height);
    for(unsigned y=0;y<frame->height;++y) for(unsigned x=0;x<frame->width;++x)
        fwrite(frame->pixels+(size_t)y*frame->stride+x*4,1,3,f);
    fclose(f);bc_ilo_video_destroy(v);return 0;
}

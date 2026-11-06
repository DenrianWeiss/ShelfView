#include "../adapters/ilo/video_internal.h"
#include <assert.h>
#include <string.h>
static uint8_t stream[128];
static unsigned bit_count;
static void field(unsigned value,unsigned count) {
    for(unsigned i=count;i;--i) {
        stream[bit_count/8] |= (uint8_t)(((value>>(i-1))&1)<<(bit_count%8));
        ++bit_count;
    }
}
static void decoder_test(void) {
    field(0x2c,6); field(1,7); field(1,7); field(0,4);
    field(0,4); field(15,4);
    field(3,2); field(7,3); field(255,8);
    field(0x2d,6);
    unsigned length=(bit_count+7)/8;
    for(unsigned chunk=1;chunk<=length;++chunk) {
        bc_ilo_video *video=NULL;
        assert(bc_ilo_video_create(1920,1200,&video)==BC_OK);
        for(unsigned offset=0;offset<length;) {
            unsigned size=length-offset<chunk?length-offset:chunk;
            assert(bc_ilo_video_feed(video,stream+offset,size)==BC_OK);
            offset+=size;
        }
        const bc_kvm_frame *frame=bc_ilo_video_frame(video);
        assert(frame->width==16 && frame->height==16);
        for(unsigned i=0;i<256;++i) {
            assert(frame->pixels[i*4]==240 && frame->pixels[i*4+1]==240 && frame->pixels[i*4+2]==240 && frame->pixels[i*4+3]==255);
        }
        bc_ilo_video_destroy(video);
    }
}
int main(void) {
    decoder_test();
    bc_ilo_bits bits={0}; uint16_t value=0;
    assert(bc_ilo_bits_append(&bits,0x95)==BC_OK);
    assert(bc_ilo_bits_take(&bits,3,&value) && value==5);
    assert(!bc_ilo_bits_take(&bits,6,&value) && bits.count==5);
    assert(bc_ilo_bits_append(&bits,0x36)==BC_OK);
    assert(bc_ilo_bits_take(&bits,9,&value) && value==150);
    assert(bc_ilo_bits_take(&bits,4,&value) && value==12);
    bc_ilo_palette palette={0};
    bc_ilo_palette_insert(&palette,0xf801);
    bc_ilo_palette_insert(&palette,0x003f);
    assert(palette.count==2 && bc_ilo_palette_bits(&palette)==1);
    assert(bc_ilo_palette_get(&palette,1,&value)==BC_OK && value==0xf801);
    bc_ilo_palette_prune(&palette);
    assert(palette.count==2);
    assert(bc_ilo_palette_get(&palette,0,&value)==BC_OK);
    bc_ilo_palette_prune(&palette);
    assert(palette.count==1 && palette.colors[0]==0xf800);
    assert(bc_ilo_palette_get(&palette,1,&value)==BC_PROTOCOL_ERROR);
    uint16_t tile[256]; for(unsigned i=0;i<256;++i) tile[i]=0xf801;
    uint8_t pixels[16*9*4]; memset(pixels,0,sizeof(pixels));
    bc_kvm_frame frame={0}; frame.pixels=pixels;frame.width=16;frame.height=9;frame.stride=64;
    assert(bc_ilo_blit(&frame,tile,0,0,16,5)==BC_OK);
    for(unsigned i=0;i<16*9;++i) assert(pixels[i*4]==248 && pixels[i*4+1]==0 && pixels[i*4+2]==0 && pixels[i*4+3]==255);
    assert(bc_ilo_blit(&frame,tile,1,0,16,5)==BC_PROTOCOL_ERROR);
    assert(bc_ilo_blit(&frame,tile,0,9,16,5)==BC_PROTOCOL_ERROR);
    return 0;
}

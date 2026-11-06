#include "bcontrol/ilo.h"
#include "bcontrol/wire.h"
#include "bcontrol/keyboard.h"
#include "wire.h"
#include "video_internal.h"
#include <stdlib.h>
#include <string.h>
struct bc_ilo_input {
    uint32_t pressed[32];
    uint16_t pointer_x, pointer_y;
};
struct bc_ilo_kvm {
    bc_ilo_video *video;
    uint8_t output[2][54], length[2], authenticated[2];
    bc_status failure;
    bc_ilo_input input;
};
static void erase(void *data, size_t length) {
    volatile uint8_t *p=data; while(length--) *p++=0;
}
bc_status bc_ilo_kvm_create(uint32_t generation, bc_string token, uint32_t width, uint32_t height, bc_ilo_kvm **out) {
    if(!out) return BC_INVALID_ARGUMENT;
    *out=NULL;
    if(generation!=5) return BC_UNSUPPORTED;
    bc_ilo_kvm *k=calloc(1,sizeof(*k)); if(!k) return BC_NO_MEMORY;
    bc_status s=bc_ilo_video_create(width,height,&k->video);
    for(unsigned ch=0;s==BC_OK && ch<2;++ch) {
        s=bc_ilo5_client_hello(token,(uint8_t)ch,k->output[ch]); k->length[ch]=54;
    }
    if(s!=BC_OK) {bc_ilo_kvm_destroy(k);return s;}
    *out=k;return BC_OK;
}
int bc_ilo_kvm_ready(const bc_ilo_kvm *k) {return k && k->failure==BC_OK && k->authenticated[0] && k->authenticated[1];}
bc_status bc_ilo_kvm_feed(bc_ilo_kvm *k,uint32_t ch,const uint8_t *data,uint32_t size) {
    if(!k || ch>1 || !data || !size) return BC_INVALID_ARGUMENT;
    if(k->failure!=BC_OK) return k->failure;
    if(k->length[ch]) return BC_BUSY;
    bc_status s=BC_OK;
    if(!k->authenticated[ch]) {
        uint8_t status;
        s=bc_ilo5_server_hello(data,size,&status);
        if(s==BC_OK && status) s=status==83?BC_BUSY:BC_AUTHENTICATION_FAILED;
        if(s==BC_OK) k->authenticated[ch]=1;
    } else if(ch==0) {
        s=bc_ilo_video_feed(k->video,data,size);
        if(s==BC_OK && bc_ilo_video_take_ack(k->video)) {k->output[0][0]=12;k->output[0][1]=0;k->length[0]=2;}
    } else {
        uint32_t offset=0;
        while(offset<size && s==BC_OK) {
            if(size-offset<12) {s=BC_PROTOCOL_ERROR;break;}
            uint32_t command=(uint32_t)bc_wire_read_le(data+offset,4);
            uint32_t length=(uint32_t)bc_wire_read_le(data+offset+4,4);
            if(length>size-offset-12) {s=BC_PROTOCOL_ERROR;break;}
            if(command==6 || command==9) {memset(k->output[1],0,4);k->output[1][0]=3;k->length[1]=4;}
            if(command==10 || command==15) s=BC_IO_ERROR;
            if(command==11 || command==14) s=BC_AUTHENTICATION_FAILED;
            offset+=12+length;
        }
    }
    if(s!=BC_OK) k->failure=s;
    return s;
}
bc_status bc_ilo_kvm_output(bc_ilo_kvm *k,uint32_t ch,uint8_t *out,uint32_t capacity,uint32_t *written) {
    if(!written) return BC_INVALID_ARGUMENT;
    *written=0;
    if(!k || ch>1 || (!out && capacity)) return BC_INVALID_ARGUMENT;
    if(k->failure!=BC_OK) return k->failure;
    if(capacity<k->length[ch]) return BC_LIMIT_EXCEEDED;
    *written=k->length[ch];
    if(*written) {memcpy(out,k->output[ch],*written);erase(k->output[ch],sizeof(k->output[ch]));k->length[ch]=0;}
    return BC_OK;
}
const bc_kvm_frame *bc_ilo_kvm_frame(const bc_ilo_kvm *k) {return k?bc_ilo_video_frame(k->video):NULL;}
void bc_ilo_kvm_ack_frame(bc_ilo_kvm *k) {if(k) bc_ilo_video_ack_frame(k->video);}
static bc_status input_ready(bc_ilo_kvm *k) {
    if(!k) return BC_INVALID_ARGUMENT;
    if(k->failure!=BC_OK) return k->failure;
    return bc_ilo_kvm_ready(k) && !k->length[0]?BC_OK:BC_BUSY;
}
bc_status bc_ilo_kvm_keyboard(bc_ilo_kvm *k,const uint8_t hid[8]) {
    if(!hid) return BC_INVALID_ARGUMENT;
    bc_status s=input_ready(k);if(s!=BC_OK) return s;
    bc_ilo5_keyboard(hid,k->output[0]);k->length[0]=10;return BC_OK;
}
bc_status bc_ilo_keyboard_encode(const uint8_t hid[8],uint8_t *out,uint32_t capacity) {
    if(!hid || !out) return BC_INVALID_ARGUMENT;
    if(capacity<10) return BC_LIMIT_EXCEEDED;
    bc_ilo5_keyboard(hid,out);return BC_OK;
}
bc_status bc_ilo_input_key(bc_ilo_input *k,uint32_t keysym,int down,uint8_t *out,uint32_t capacity) {
    if(!k || !out || (down!=0 && down!=1)) return BC_INVALID_ARGUMENT;
    if(capacity<10) return BC_LIMIT_EXCEEDED;
    uint8_t report[8];
    bc_status status=bc_keyboard_report(k->pressed,keysym,down,report);
    if(status!=BC_OK) return status;
    bc_ilo5_keyboard(report,out);
    return BC_OK;
}
bc_status bc_ilo_kvm_key_event(bc_ilo_kvm *k,uint32_t keysym,int down) {
    bc_status s=input_ready(k);if(s!=BC_OK) return s;
    s=bc_ilo_input_key(&k->input,keysym,down,k->output[0],sizeof(k->output[0]));
    if(s==BC_OK) k->length[0]=10;
    return s;
}
bc_status bc_ilo_kvm_pointer(bc_ilo_kvm *k,uint16_t x,uint16_t y,int8_t dx,int8_t dy,uint8_t buttons,int8_t wheel) {
    bc_status s=input_ready(k);if(s!=BC_OK) return s;
    bc_ilo5_pointer(x,y,dx,dy,buttons,wheel,k->output[0]);k->length[0]=10;return BC_OK;
}
bc_status bc_ilo_input_pointer(bc_ilo_input *k,uint16_t x,uint16_t y,uint32_t width,uint32_t height,
    uint8_t buttons,int8_t wheel,uint8_t *out,uint32_t capacity) {
    if(!k || !out || !width || !height || width>65536 || height>65536 || (buttons&~7u)) return BC_INVALID_ARGUMENT;
    if(capacity<10) return BC_LIMIT_EXCEEDED;
    if(x>=width) x=(uint16_t)(width-1);
    if(y>=height) y=(uint16_t)(height-1);
    int dx=(int)x-k->pointer_x, dy=(int)k->pointer_y-y;
    if(dx>127) dx=127;else if(dx< -127) dx=-127;
    if(dy>127) dy=127;else if(dy< -127) dy=-127;
    bc_ilo5_pointer((uint16_t)(3000u*x/width),(uint16_t)(3000u*y/height),
        (int8_t)dx,(int8_t)dy,buttons,wheel,out);
    k->pointer_x=x;k->pointer_y=y;
    return BC_OK;
}
bc_status bc_ilo_kvm_pointer_event(bc_ilo_kvm *k,uint16_t x,uint16_t y,uint8_t buttons,int8_t wheel) {
    bc_status s=input_ready(k);if(s!=BC_OK) return s;
    const bc_kvm_frame *f=bc_ilo_video_frame(k->video);
    if(!f || !f->width || !f->height) return BC_BUSY;
    s=bc_ilo_input_pointer(&k->input,x,y,f->width,f->height,buttons,wheel,k->output[0],sizeof(k->output[0]));
    if(s==BC_OK) k->length[0]=10;
    return s;
}
bc_status bc_ilo_input_create(bc_ilo_input **out) {
    if(!out) return BC_INVALID_ARGUMENT;
    *out=calloc(1,sizeof(**out));
    return *out?BC_OK:BC_NO_MEMORY;
}
void bc_ilo_input_destroy(bc_ilo_input *input) {
    if(input) {erase(input,sizeof(*input));free(input);}
}
bc_status bc_ilo_kvm_refresh(bc_ilo_kvm *k) {
    bc_status s=input_ready(k);if(s!=BC_OK) return s;
    k->output[0][0]=5;k->output[0][1]=0;k->length[0]=2;return BC_OK;
}
void bc_ilo_kvm_destroy(bc_ilo_kvm *k) {if(k){bc_ilo_video_destroy(k->video);erase(k,sizeof(*k));free(k);}}

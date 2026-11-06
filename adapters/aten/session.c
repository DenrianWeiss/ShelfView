#include "bcontrol/aten.h"
#include "video.h"
#include "bcontrol/console_provider.h"
#include "bcontrol/keyboard.h"
#include "bcontrol/wire.h"
#include "../../platform/mutex.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#define LIMIT (16u*1024u*1024u)
typedef struct {
    bc_aten_launch launch;
    bc_console_emit emit;
    void *user;
    bc_mutex mutex;
    uint8_t *buffer,*pixels;
    bc_ast_video *ast;
    uint32_t video_variant;
    uint8_t key_modifiers[256], physical_modifiers, modifiers;
    uint32_t used,capacity,phase,width,height,rectangles;
    uint32_t ready,input_enabled,dirty,closed,mouse_bytes,mouse_encrypted;
    char name[1025];
    bc_status failure;
} session;
static bc_status send(session *s,const uint8_t *p,uint32_t n) {return s->emit(s->user,p,n);}
static bc_status request(session *s,int incremental) {
    uint8_t p[10]={3,0};p[1]=(uint8_t)incremental;return send(s,p,sizeof(p));
}
static bc_status resize(session *s,uint32_t w,uint32_t h) {
    if(!w||!h||w>4096||h>4096)return BC_LIMIT_EXCEEDED;
    if(w==s->width&&h==s->height)return BC_OK;
    uint8_t *p=calloc((size_t)w*h,4);if(!p)return BC_NO_MEMORY;
    free(s->pixels);s->pixels=p;s->width=w;s->height=h;return BC_OK;
}
static void pixel(uint8_t *out,const uint8_t *in,uint32_t depth) {
    if(depth==0){uint32_t v=(uint32_t)bc_wire_read_le(in,2);for(unsigned i=0;i<3;++i){unsigned c=(v>>(10-5*i))&31;out[i]=(uint8_t)((c<<3)|(c>>2));}}
    else {out[0]=(uint8_t)((in[0]&3)*85);out[1]=(uint8_t)(((in[0]>>2)&3)*85);out[2]=(uint8_t)(((in[0]>>4)&3)*85);}
    out[3]=255;
}
static bc_status rectangle(session *s,const uint8_t *p,uint32_t n) {
    uint32_t x=(uint32_t)bc_wire_read_be(p,2),y=(uint32_t)bc_wire_read_be(p+2,2);
    uint32_t w=(uint32_t)bc_wire_read_be(p+4,2),h=(uint32_t)bc_wire_read_be(p+6,2),encoding=(uint32_t)bc_wire_read_be(p+8,4);
    if(w==0xfd80 && h==0xfe20){if(n)return BC_PROTOCOL_ERROR;if(s->pixels){memset(s->pixels,0,(size_t)s->width*s->height*4);s->dirty=1;}return BC_OK;}
    if(encoding==0x57){
        if(x || y)return BC_UNSUPPORTED;
        bc_status status=resize(s,w,h);if(status!=BC_OK)return status;
        status=bc_aten_ast_decode(&s->ast,p+20,n,w,h,s->pixels,w*h*4);
        if(status==BC_OK){s->dirty=1;s->video_variant=BC_SERVICE_ATEN_KVM_AST;}
        return status;
    }
    if(encoding!=0 && encoding!=0x59)return BC_UNSUPPORTED;
    if(n<10)return BC_PROTOCOL_ERROR;
    const uint8_t *body=p+20;uint32_t type=body[0],depth=body[1],count=(uint32_t)bc_wire_read_be(body+2,4);
    if(type>1||depth>1)return BC_UNSUPPORTED;
    uint32_t bpp=depth?1:2;body+=10;n-=10;
    if(!x&&!y){bc_status status=resize(s,w,h);if(status!=BC_OK)return status;}
    if(!s->pixels || x>s->width || y>s->height || w>s->width-x || h>s->height-y)return BC_PROTOCOL_ERROR;
    if(type==1) {
        if((uint64_t)w*h*bpp!=n)return BC_PROTOCOL_ERROR;
        for(uint32_t row=0;row<h;++row)for(uint32_t col=0;col<w;++col)
            pixel(s->pixels+((y+row)*s->width+x+col)*4,body+(row*w+col)*bpp,depth);
    } else {
        uint32_t stride=6+256*bpp;
        if(count>65536 || (uint64_t)count*stride!=n)return BC_PROTOCOL_ERROR;
        for(uint32_t i=0;i<count;++i) {
            const uint8_t *tile=body+i*stride;uint32_t ty=(uint32_t)tile[4]*16,tx=(uint32_t)tile[5]*16;
            if(tx>=s->width || ty>=s->height)return BC_PROTOCOL_ERROR;
            for(uint32_t row=0;row<16 && ty+row<s->height;++row)for(uint32_t col=0;col<16 && tx+col<s->width;++col)
                pixel(s->pixels+((ty+row)*s->width+tx+col)*4,tile+6+(row*16+col)*bpp,depth);
        }
    }
    s->dirty=1;s->video_variant=BC_SERVICE_ATEN_KVM_HERMON;return BC_OK;
}
static bc_status parse(session *s,uint32_t *consumed) {
    const uint8_t *p=s->buffer;uint32_t n=s->used,need=0;bc_status status=BC_OK;*consumed=0;
    if(s->phase==0) {
        need=12;if(n<need)return BC_BUSY;
        if(memcmp(p,"RFB 003.008\n",12) && memcmp(p,"RFB 055.008\n",12))return BC_UNSUPPORTED;
        status=send(s,p,12);s->phase=1;
    } else if(s->phase==1) {
        if(!n)return BC_BUSY;need=1+p[0];if(n<need)return BC_BUSY;
        if(!p[0]||!memchr(p+1,16,p[0]))return BC_UNSUPPORTED;
        uint8_t type=16;status=send(s,&type,1);s->phase=2;
    } else if(s->phase==2) {
        need=24;if(n<need)return BC_BUSY;
        uint8_t auth[48]={0};memcpy(auth,s->launch.username,strlen(s->launch.username));memcpy(auth+24,s->launch.password,strlen(s->launch.password));
        status=send(s,auth,sizeof(auth));memset(auth,0,sizeof(auth));memset(s->launch.username,0,sizeof(s->launch.username));memset(s->launch.password,0,sizeof(s->launch.password));s->phase=3;
    } else if(s->phase==3) {
        need=4;if(n<need)return BC_BUSY;if(bc_wire_read_be(p,4))return BC_AUTHENTICATION_FAILED;
        uint8_t shared=1;status=send(s,&shared,1);s->phase=4;
    } else if(s->phase==4) {
        if(n<24)return BC_BUSY;uint32_t length=(uint32_t)bc_wire_read_be(p+20,4);if(length>1024)return BC_LIMIT_EXCEEDED;
        need=36+length;if(n<need)return BC_BUSY;
        memcpy(s->name,p+24,length);s->name[length]=0;
        bc_mutex_lock(&s->mutex);s->input_enabled=p[24+length+9]!=0;s->ready=1;bc_mutex_unlock(&s->mutex);
        s->phase=5;status=request(s,0);
    } else if(s->rectangles) {
        if(n<20)return BC_BUSY;uint32_t length=(uint32_t)bc_wire_read_be(p+16,4);if(length>LIMIT-20)return BC_LIMIT_EXCEEDED;
        need=20+length;if(n<need)return BC_BUSY;status=rectangle(s,p,length);
        if(status==BC_OK && !--s->rectangles)status=request(s,1);
    } else {
        if(!n)return BC_BUSY;
        switch(p[0]) {
        case 0:
            need=4;if(n<need)return BC_BUSY;s->rectangles=(uint32_t)bc_wire_read_be(p+2,2);
            if(s->rectangles>4096)return BC_LIMIT_EXCEEDED;
            if(!s->rectangles)status=request(s,1);break;
        case 2:need=1;break;
        case 4:
            need=21;if(n<need)return BC_BUSY;
            if(bc_wire_read_be(p+17,4)==1){uint64_t w=bc_wire_read_be(p+9,4),h=bc_wire_read_be(p+13,4);if(w>4096 || h>4096)return BC_LIMIT_EXCEEDED;uint64_t size=w*h*2;if(size>1048576)return BC_LIMIT_EXCEEDED;need=25+(uint32_t)size;}
            else if(bc_wire_read_be(p+17,4)!=0)return BC_UNSUPPORTED;
            break;
        case 0x16:need=2;break;
        case 0x35:need=6;break;
        case 0x37:
            if(!s->mouse_bytes)return BC_UNSUPPORTED;
            need=1+s->mouse_bytes;if(n<need)return BC_BUSY;
            if(p[1] && s->launch.mouse_cipher!=1)return BC_UNSUPPORTED;
            bc_mutex_lock(&s->mutex);s->mouse_encrypted=p[1]!=0;bc_mutex_unlock(&s->mutex);
            break;
        case 0x39:
            need=265;if(n<need)return BC_BUSY;
            if(bc_wire_read_be(p+1,4)!=1)return BC_UNSUPPORTED;
            bc_mutex_lock(&s->mutex);s->input_enabled=s->input_enabled && bc_wire_read_be(p+5,4)!=4;bc_mutex_unlock(&s->mutex);break;
        case 0x3c:need=9;break;
        default:return BC_UNSUPPORTED;
        }
        if(n<need)return BC_BUSY;
    }
    if(status==BC_OK)*consumed=need;return status;
}
static bc_status feed(void *user,uint32_t channel,const uint8_t *data,uint32_t size) {
    session *s=user;if(channel || (!data&&size))return BC_INVALID_ARGUMENT;
    if(s->failure)return s->failure;
    if(size>LIMIT-s->used)return BC_LIMIT_EXCEEDED;
    uint32_t total=s->used+size;
    if(total>s->capacity){uint32_t cap=total<4096?4096:total;uint8_t *p=realloc(s->buffer,cap);if(!p)return BC_NO_MEMORY;s->buffer=p;s->capacity=cap;}
    if(size)memcpy(s->buffer+s->used,data,size);s->used=total;
    while(s->used){uint32_t consumed=0;bc_status status=parse(s,&consumed);if(status==BC_BUSY)return BC_OK;if(status!=BC_OK){s->failure=status;return status;}if(!consumed)return BC_PROTOCOL_ERROR;
        s->used-=consumed;memmove(s->buffer,s->buffer+consumed,s->used);}
    return BC_OK;
}
static bc_status pointer(session *s,const bc_console_input *event,uint32_t encrypted,uint8_t wheel){
    uint8_t bytes[18]={0};
        if(!event->width||!event->height||event->x>=event->width||event->y>=event->height||event->x>65535||event->y>65535)return BC_INVALID_ARGUMENT;
        bytes[0]=5;bytes[2]=(uint8_t)((event->buttons&1)|((event->buttons&2)<<1)|((event->buttons&4)>>1)|wheel);
        bc_wire_write_be(bytes+3,event->x,2);bc_wire_write_be(bytes+5,event->y,2);
        if(encrypted){
            static const uint8_t key[]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
            static const uint8_t iv[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
            uint8_t plain[16];memcpy(plain,bytes+2,5);
            if(RAND_bytes(plain+5,11)!=1)return BC_IO_ERROR;
            EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();if(!ctx)return BC_NO_MEMORY;
            int size=0,tail=0;
            int ok=EVP_EncryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,iv)==1 && EVP_CIPHER_CTX_set_padding(ctx,0)==1 &&
                EVP_EncryptUpdate(ctx,bytes+2,&size,plain,16)==1 && size==16 && EVP_EncryptFinal_ex(ctx,bytes+2+size,&tail)==1 && tail==0;
            EVP_CIPHER_CTX_free(ctx);OPENSSL_cleanse(plain,sizeof(plain));
            if(!ok)return BC_IO_ERROR;
            bytes[1]=1;
        }
    return send(s,bytes,sizeof(bytes));
}
static bc_status key_event(session *s,uint32_t usage,int down) {
    uint8_t bytes[18]={4,0};bytes[2]=(uint8_t)!!down;
    bc_wire_write_be(bytes+5,usage,4);return send(s,bytes,sizeof(bytes));
}
static bc_status key(session *s,const bc_console_input *event) {
    uint8_t implicit=0;uint32_t usage=bc_keyboard_keysym_to_usage(event->keysym,&implicit);
    if(!usage || usage>=256)return BC_UNSUPPORTED;
    uint8_t physical=s->physical_modifiers, next[256];memcpy(next,s->key_modifiers,sizeof(next));
    int modifier=usage>=0xe0 && usage<=0xe7;
    if(modifier) {
        uint8_t bit=(uint8_t)(1u<<(usage-0xe0));
        if(event->down)physical|=bit;else physical&=(uint8_t)~bit;
    } else next[usage]=event->down?implicit:0;
    uint8_t combined=physical;
    for(unsigned i=0;i<sizeof(next);++i)combined|=next[i];
    bc_status status=BC_OK;
    for(unsigned i=0;i<8 && status==BC_OK;++i)
        if((combined & (1u<<i)) && !(s->modifiers & (1u<<i)))status=key_event(s,0xe0+i,1);
    if(status==BC_OK && !modifier)status=key_event(s,usage,event->down);
    for(unsigned i=0;i<8 && status==BC_OK;++i)
        if((s->modifiers & (1u<<i)) && !(combined & (1u<<i)))status=key_event(s,0xe0+i,0);
    if(status==BC_OK) {
        memcpy(s->key_modifiers,next,sizeof(next));s->physical_modifiers=physical;s->modifiers=combined;
    }
    return status;
}
static bc_status input(void *user,const bc_console_input *event) {
    session *s=user;bc_mutex_lock(&s->mutex);int allowed=s->ready && s->input_enabled && !s->closed;uint32_t encrypted=s->mouse_encrypted;bc_mutex_unlock(&s->mutex);
    if(!allowed)return BC_UNSUPPORTED;
    if(event->type==BC_CONSOLE_INPUT_KEY)return key(s,event);
    if(event->type==BC_CONSOLE_INPUT_POINTER)return pointer(s,event,encrypted,0);
    if(event->type!=BC_CONSOLE_INPUT_SCROLL)return BC_UNSUPPORTED;
    if(event->wheel < -127 || event->wheel > 127)return BC_INVALID_ARGUMENT;
    uint32_t steps=(uint32_t)(event->wheel<0?-event->wheel:event->wheel);
    for(uint32_t i=0;i<steps;++i){
        bc_status status=pointer(s,event,encrypted,event->wheel>0?8:16);
        if(status==BC_OK)status=pointer(s,event,encrypted,0);
        if(status!=BC_OK)return status;
    }
    return BC_OK;
}
static bc_status tile(void *user,bc_display_tile *out) {
    session *s=user;if(!s->dirty||!s->pixels)return BC_BUSY;
    *out=(bc_display_tile){sizeof(*out),BC_PIXEL_RGBA8,s->width,s->height,0,0,s->width,s->height,s->width*4,{s->pixels,(uint64_t)s->width*s->height*4}};return BC_OK;
}
static void ack(void *user){((session *)user)->dirty=0;}
static bc_status info(void *user,bc_console_info *out) {
    session *s=user;out->flags=BC_CONSOLE_INFO_READY_KNOWN|BC_CONSOLE_INFO_PROFILE_VALID;
    if(s->ready)out->flags|=BC_CONSOLE_INFO_READY;
    out->profile=(bc_service_profile){sizeof(bc_service_profile),BC_SERVICE_KVM,BC_SERVICE_FAMILY_ATEN,
        s->pixels?s->video_variant:0,BC_SERVICE_EVIDENCE_DESCRIPTOR|(s->pixels?BC_SERVICE_EVIDENCE_HANDSHAKE:0)};
    if(s->failure){out->flags|=BC_CONSOLE_INFO_FAILED|BC_CONSOLE_INFO_FAILURE_VALID;out->failure=(bc_console_failure){sizeof(bc_console_failure),s->failure,BC_CONSOLE_PHASE_TRANSPORT,BC_CONSOLE_CAUSE_PROTOCOL,0,0,0,BC_SERVICE_KVM,BC_SERVICE_FAMILY_ATEN};}
    return BC_OK;
}
static bc_status control(void *user,uint32_t operation) {
    session *s=user;
    if(operation==BC_CONSOLE_CONTROL_CLOSE){bc_mutex_lock(&s->mutex);s->closed=1;bc_mutex_unlock(&s->mutex);return BC_OK;}
    if(operation==BC_CONSOLE_CONTROL_REFRESH||operation==BC_CONSOLE_CONTROL_HEARTBEAT)return s->ready?request(s,0):BC_BUSY;
    return BC_UNSUPPORTED;
}
static void destroy(void *user){session *s=user;bc_ast_video_destroy(s->ast);free(s->buffer);free(s->pixels);bc_mutex_destroy(&s->mutex);memset(s,0,sizeof(*s));free(s);}
bc_status bc_aten_console_create(const bc_aten_launch *launch,bc_console_emit emit,void *user,bc_console_session **out) {
    if(!out)return BC_INVALID_ARGUMENT;*out=NULL;
    if(!launch||(launch->mouse_bytes && launch->mouse_bytes!=3)||launch->mouse_cipher>1||launch->struct_size!=sizeof(*launch)||!emit||
        !memchr(launch->username,0,sizeof(launch->username))||!memchr(launch->password,0,sizeof(launch->password)))return BC_INVALID_ARGUMENT;
    session *s=calloc(1,sizeof(*s));if(!s)return BC_NO_MEMORY;
    s->launch=*launch;s->mouse_bytes=launch->mouse_bytes;s->emit=emit;s->user=user;bc_mutex_init(&s->mutex);
    bc_console_provider provider={0};provider.struct_size=sizeof(provider);provider.display_modes=BC_DISPLAY_TILE;provider.input_capabilities=BC_CONSOLE_INPUT_HAS_SCROLL;
    provider.input=input;provider.tile=tile;provider.ack_display=ack;provider.destroy=destroy;provider.feed=feed;provider.info=info;
    provider.controls=BC_CONSOLE_CONTROL_REFRESH|BC_CONSOLE_CONTROL_HEARTBEAT|BC_CONSOLE_CONTROL_CLOSE;provider.control=control;
    bc_status status=bc_console_session_wrap(&provider,s,out);if(status!=BC_OK)destroy(s);return status;
}

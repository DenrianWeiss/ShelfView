#include "bcontrol/aten.h"
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/media_provider.h"
#include "bcontrol/wire.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
typedef struct {uint8_t data[262144];uint32_t length,read;uint64_t now;uint8_t last[65544];uint32_t last_size,emitted;uint8_t previous[18];} io;
static bc_status emit(void *user,const uint8_t *p,uint32_t n){io *s=user;assert(n<=sizeof(s->last));if(s->last_size==18)memcpy(s->previous,s->last,18);++s->emitted;memcpy(s->last,p,n);s->last_size=n;return BC_OK;}
static uint64_t clock_ms(void *user){return ++((io *)user)->now;}
static bc_status receive(void *user,uint8_t *p,uint32_t n,uint32_t *got,uint32_t timeout){io *s=user;(void)timeout;*got=0;if(s->read==s->length)return BC_TIMEOUT;if(n>3)n=3;if(n>s->length-s->read)n=s->length-s->read;memcpy(p,s->data+s->read,n);s->read+=n;*got=n;return BC_OK;}
static void packet(io *s,uint8_t endpoint,uint8_t tag,const uint8_t *p,uint32_t n){uint8_t *b=s->data+s->length;memset(b,0,8);b[0]=endpoint;b[3]=tag;bc_wire_write_le(b+4,n,4);if(n)memcpy(b+8,p,n);s->length+=8+n;}
static bc_status read_source(void *u,uint64_t off,uint32_t n,uint8_t *out){(void)u;if(off+n>16*2048)return BC_IO_ERROR;memset(out,0x5a,n);return BC_OK;}
static bc_aten_launch descriptor(void){
    const char *xml="<jnlp><resources><jar href='iKVM.jar' version='1.69.21.0x0'/></resources><application-desc main-class='tw.com.aten.ikvm.KVMMain'><argument>192.0.2.1</argument><argument>ticket</argument><argument>password</argument><argument>null</argument><argument>5900</argument><argument>623</argument><argument>2</argument><argument>0</argument></application-desc></jnlp>";
    bc_aten_launch out;assert(bc_aten_launch_parse((const uint8_t *)xml,(uint32_t)strlen(xml),&out)==BC_OK);
    assert(out.port==5900&&out.media_port==623&&!out.tls&&!strcmp(out.viewer_version,"1.69.21.0x0"));
    assert(bc_aten_launch_parse((const uint8_t *)"<jnlp><information>ATEN Supermicro</information></jnlp>",strlen("<jnlp><information>ATEN Supermicro</information></jnlp>"),&out)!=BC_OK);
    assert(bc_aten_launch_parse((const uint8_t *)xml,(uint32_t)strlen(xml),&out)==BC_OK);return out;
}
static void tls_descriptor(void) {
    const char *args[]={"http://192.0.2.1:80/","iKVM__V1.69.39.0x0.jar","a.jar","b.jar","b.jar","c.jar","c.jar","d.jar","d.jar","e.jar",
        "192.0.2.1","ticket","password","null","63630","63631","0","0","1","5900","623","1"};
    char xml[4096];size_t n=(size_t)snprintf(xml,sizeof(xml),"<jnlp><resources><jar href='iKVM__V1.69.39.0x0.jar'/></resources><resources os='Linux' arch='amd64'><nativelib href='liblinux_x86_64.jar'/></resources><application-desc main-class='tw.com.aten.ikvm.KVMMain'>");
    for(unsigned i=0;i<22;++i)n+=(size_t)snprintf(xml+n,sizeof(xml)-n,"<argument>%s</argument>",args[i]);
    n+=(size_t)snprintf(xml+n,sizeof(xml)-n,"</application-desc></jnlp>");
    bc_aten_launch out;assert(bc_aten_launch_parse((const uint8_t *)xml,(uint32_t)n,&out)==BC_OK);
    assert(out.tls==1&&out.port==63630&&out.tls_port==5900&&out.media_port==63631&&out.media_tls_port==623&&out.media_enabled==1);
    assert(!strcmp(out.username,"ticket")&&!strcmp(out.viewer_version,"1.69.39.0x0"));
    assert(!strcmp(out.jar_path,args[1])&&!strcmp(out.native_path,"liblinux_x86_64.jar"));
}
static void console(bc_aten_launch *launch){
    io s={0};bc_console_session *session=NULL;assert(bc_aten_console_create(launch,emit,&s,&session)==BC_OK);
    const uint8_t banner[]="RFB 003.008\n";for(unsigned i=0;i<12;++i)assert(bc_console_session_feed(session,0,banner+i,1)==BC_OK);
    assert(s.last_size==12&&!memcmp(s.last,banner,12));uint8_t types[]={2,1,16};assert(bc_console_session_feed(session,0,types,3)==BC_OK&&s.last[0]==16);
    uint8_t bytes[100]={0};assert(bc_console_session_feed(session,0,bytes,24)==BC_OK&&s.last_size==48&&!memcmp(s.last,"ticket",6));
    assert(bc_console_session_feed(session,0,bytes,4)==BC_OK&&s.last_size==1&&s.last[0]==1);
    bc_wire_write_be(bytes,2,2);bc_wire_write_be(bytes+2,2,2);bytes[33]=1;assert(bc_console_session_feed(session,0,bytes,36)==BC_OK&&s.last[0]==3);
    uint8_t frame[42]={0};frame[3]=1;frame[9]=2;frame[11]=2;frame[15]=0x59;frame[23]=18;frame[24]=1;
    for(unsigned i=34;i<42;i+=2){frame[i]=0;frame[i+1]=0x7c;}
    for(unsigned i=0;i<sizeof(frame);++i)assert(bc_console_session_feed(session,0,frame+i,1)==BC_OK);
    bc_display_tile tile={0};tile.struct_size=sizeof(tile);assert(bc_console_session_tile(session,&tile)==BC_OK&&tile.width==2&&tile.height==2);
    assert(tile.pixels.data[0]==255&&tile.pixels.data[1]==0&&tile.pixels.data[3]==255);
    bc_console_input event={0};event.struct_size=sizeof(event);event.type=BC_CONSOLE_INPUT_KEY;event.keysym='a';event.down=1;
    assert(bc_console_session_input(session,&event)==BC_OK&&s.last_size==18&&s.last[0]==4&&s.last[8]==4);
    event.down=0;assert(bc_console_session_input(session,&event)==BC_OK);
    event.keysym='A';event.down=1;uint32_t count=s.emitted;
    assert(bc_console_session_input(session,&event)==BC_OK&&s.emitted==count+2&&s.previous[8]==0xe1&&s.previous[2]==1&&s.last[8]==4);
    event.down=0;assert(bc_console_session_input(session,&event)==BC_OK&&s.previous[8]==4&&s.previous[2]==0&&s.last[8]==0xe1&&s.last[2]==0);
    event.keysym=0xffe1;event.down=1;assert(bc_console_session_input(session,&event)==BC_OK);
    event.keysym='!';count=s.emitted;
    assert(bc_console_session_input(session,&event)==BC_OK&&s.emitted==count+1&&s.last[8]==0x1e);
    event.down=0;assert(bc_console_session_input(session,&event)==BC_OK&&s.emitted==count+2&&s.last[8]==0x1e);
    event.keysym=0xffe1;assert(bc_console_session_input(session,&event)==BC_OK&&s.last[8]==0xe1&&s.last[2]==0);
    event.type=BC_CONSOLE_INPUT_POINTER;event.width=2;event.height=2;event.x=1;event.y=1;event.buttons=2;
    assert(bc_console_session_input(session,&event)==BC_OK&&s.last[0]==5&&s.last[2]==4&&s.last[4]==1);
    uint8_t mouse_info[]={0x37,0,1,0};
    for(unsigned i=0;i<sizeof(mouse_info);++i)assert(bc_console_session_feed(session,0,mouse_info+i,1)==BC_OK);
    mouse_info[1]=1;assert(bc_console_session_feed(session,0,mouse_info,sizeof(mouse_info))==BC_OK);
    assert(bc_console_session_input(session,&event)==BC_OK&&s.last[0]==5&&s.last[1]==1);
    const uint8_t key[]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    const uint8_t iv[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};uint8_t plain[32];int size=0,tail=0;
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();assert(ctx);
    assert(EVP_DecryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,iv)==1&&EVP_CIPHER_CTX_set_padding(ctx,0)==1);
    assert(EVP_DecryptUpdate(ctx,plain,&size,s.last+2,16)==1&&EVP_DecryptFinal_ex(ctx,plain+size,&tail)==1&&size+tail==16);
    assert(plain[0]==4&&plain[1]==0&&plain[2]==1&&plain[3]==0&&plain[4]==1);EVP_CIPHER_CTX_free(ctx);
    mouse_info[1]=0;assert(bc_console_session_feed(session,0,mouse_info,sizeof(mouse_info))==BC_OK);
    assert(bc_console_session_input(session,&event)==BC_OK&&s.last[1]==0&&s.last[2]==4);
    assert(bc_console_session_input_capabilities(session)&BC_CONSOLE_INPUT_HAS_SCROLL);
    uint32_t emitted=s.emitted;event.type=BC_CONSOLE_INPUT_SCROLL;event.wheel=2;
    assert(bc_console_session_input(session,&event)==BC_OK&&s.emitted==emitted+4&&s.previous[2]==12&&s.last[2]==4);
    event.wheel=-1;assert(bc_console_session_input(session,&event)==BC_OK&&s.previous[2]==20&&s.last[2]==4);
    event.wheel=128;assert(bc_console_session_input(session,&event)==BC_INVALID_ARGUMENT);
    uint8_t unknown=0xee;assert(bc_console_session_feed(session,0,&unknown,1)==BC_UNSUPPORTED);bc_console_session_destroy(session);
}
static void media(bc_aten_launch *launch,uint32_t layout,uint32_t response_size){
    io s={0};bc_aten_media_ticket ticket={*launch,layout};bc_media_offer *offer=NULL;
    bc_media_offer_info offer_info={sizeof(offer_info),BC_MEDIA_OFFER_READY,623};assert(bc_media_offer_create(BC_MEDIA_OFFER_ATEN,&offer_info,&ticket,sizeof(ticket),&offer)==BC_OK);
    bc_media_source source={sizeof(source),NULL,16*2048,read_source};bc_media_options o={0};o.struct_size=sizeof(o);o.abi_version=BC_ABI_VERSION;o.offer=offer;o.source=&source;o.timeout_ms=10000;o.clock=clock_ms;o.emit=emit;o.receive=receive;o.user=&s;
    bc_media_session *session=NULL;assert(bc_aten_media_create(&o,&session)==BC_OK);assert(bc_media_session_control(session,BC_MEDIA_CONTROL_START)==BC_OK);assert(s.last_size==226&&s.last[3]==1&&s.last[4]==44);
    uint8_t response[9]={0};packet(&s,0,2,response,response_size);while(s.read<s.length)assert(bc_media_session_poll(session,20)==BC_OK);
    bc_media_session_info info={0};info.struct_size=sizeof(info);assert(bc_media_session_info_get(session,&info)==BC_OK&&(info.flags&BC_MEDIA_MOUNT_CONFIRMED));
    uint8_t cbw[31]={0x55,0x53,0x42,0x43};cbw[4]=7;cbw[9]=8;cbw[12]=0x80;cbw[14]=10;cbw[15]=0x28;cbw[23]=1;
    packet(&s,0x11,0,cbw,sizeof(cbw));while(s.read<s.length)assert(bc_media_session_poll(session,20)==BC_OK);
    bc_media_session_info_get(session,&info);assert(info.bytes_read==2048&&s.last_size==21&&s.last[3]==0xff&&s.last[20]==0);
    packet(&s,0,6,response,1);assert(bc_media_session_control(session,BC_MEDIA_CONTROL_EJECT)==BC_OK);
    bc_media_session_info_get(session,&info);assert((info.flags&BC_MEDIA_REMOVAL_CONFIRMED)&&!(info.flags&BC_MEDIA_REMOVAL_UNCONFIRMED));
    bc_media_session_own(session);bc_media_session_destroy(session);bc_media_offer_destroy(offer);
}
int main(void){bc_aten_launch launch=descriptor();tls_descriptor();launch.mouse_bytes=3;launch.mouse_cipher=1;console(&launch);media(&launch,1,5);media(&launch,2,9);puts("ATEN descriptor, fragmented console and CD exchange passed");return 0;}

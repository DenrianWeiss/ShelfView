#include "bcontrol/nbd_media.h"
#include "bcontrol/media_provider.h"
#include "bcontrol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while(0)
static uint8_t output[4096]; static uint32_t used;
static bc_status send(void *u,const uint8_t *p,uint32_t n) { (void)u; CHECK(n<=sizeof(output)-used); memcpy(output+used,p,n);used+=n;return BC_OK; }
static bc_status receive(void *u,uint8_t *p,uint32_t n,uint32_t *size,uint32_t t) { (void)u;(void)p;(void)n;(void)t;*size=0;return BC_TIMEOUT; }
static bc_status read_source(void *u,uint64_t offset,uint32_t n,uint8_t *p) { (void)u;for(uint32_t i=0;i<n;++i)p[i]=(uint8_t)(offset+i);return BC_OK; }
static void feed(bc_media_session *s,const uint8_t *p,uint32_t n) { for(uint32_t i=0;i<n;++i)CHECK(bc_media_session_feed(s,(bc_bytes){p+i,1})==BC_OK); }
int main(void) {
    bc_media_source source={sizeof(source),NULL,8192,read_source};
    bc_media_options options={0}; options.struct_size=sizeof(options);options.abi_version=BC_ABI_VERSION;
    options.source=&source;options.emit=send;options.receive=receive;
    bc_media_session *s=NULL;CHECK(bc_nbd_media_create(&options,&s)==BC_OK);bc_media_session_own(s);
    CHECK(bc_media_session_control(s,BC_MEDIA_CONTROL_START)==BC_OK);
    CHECK(used==18&&!memcmp(output,"NBDMAGICIHAVEOPT",16));used=0;
    uint8_t flags[4]={0,0,0,3};feed(s,flags,4);
    uint8_t option[16]="IHAVEOPT";bc_wire_write_be(option+8,8,4);feed(s,option,16);
    CHECK(used==20&&bc_wire_read_be(output+12,4)==0x80000001u);used=0;
    bc_wire_write_be(option+8,1,4);feed(s,option,16);
    CHECK(used==10&&bc_wire_read_be(output,8)==8192&&bc_wire_read_be(output+8,2)==3);used=0;
    bc_media_session_info info={.struct_size=sizeof(info)};CHECK(bc_media_session_info_get(s,&info)==BC_OK);
    CHECK((info.flags&BC_MEDIA_CONNECTED)&&!(info.flags&BC_MEDIA_MOUNT_CONFIRMED));
    uint8_t request[28]={0};bc_wire_write_be(request,0x25609513,4);
    memcpy(request+8,"HANDLE01",8);bc_wire_write_be(request+16,512,8);bc_wire_write_be(request+24,32,4);
    feed(s,request,28);CHECK(used==48&&bc_wire_read_be(output+4,4)==0&&!memcmp(output+8,"HANDLE01",8));
    for(unsigned i=0;i<32;++i)CHECK(output[16+i]==i);
    used=0;bc_wire_write_be(request+16,8190,8);feed(s,request,28);CHECK(used==16&&bc_wire_read_be(output+4,4)==22);
    used=0;request[7]=1;bc_wire_write_be(request+24,2,4);feed(s,request,28);CHECK(used==0);
    feed(s,(const uint8_t *)"ab",2);CHECK(used==16&&bc_wire_read_be(output+4,4)==1);
    CHECK(bc_media_session_info_get(s,&info)==BC_OK&&info.bytes_read==32);
    CHECK(bc_media_session_control(s,BC_MEDIA_CONTROL_EJECT)==BC_OK);
    CHECK(bc_media_session_info_get(s,&info)==BC_OK&&!(info.flags&BC_MEDIA_REMOVAL_CONFIRMED));
    bc_media_session_destroy(s);puts("nbd: fragmented negotiation, read, bounds, write rejection and unconfirmed removal passed");return 0;
}

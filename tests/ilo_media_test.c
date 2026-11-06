#include "bcontrol/ilo_media.h"
#include "bcontrol/wire.h"
#include <assert.h>
#include <string.h>
typedef struct {uint8_t header[54];uint32_t length,reads,payloads;} fixture;
static bc_status emit(void *user,const uint8_t *data,uint32_t length) {
    fixture *f=user;
    if(length<=54) {memcpy(f->header,data,length);f->length=length;}
    else {for(uint32_t i=0;i<length;++i) assert(data[i]==0xa5);++f->payloads;}
    return BC_OK;
}
static bc_status read_block(void *user,uint64_t offset,uint32_t length,uint8_t *out) {
    fixture *f=user;assert(offset==2048 && length==2048);++f->reads;memset(out,0xa5,length);return BC_OK;
}
int main(void) {
    fixture f={0};bc_ilo_media *m=NULL;
    bc_ilo_media_source source={8192,&f,read_block};
    bc_string token={"0123456789abcdef0123456789abcdef",32};
    assert(bc_ilo_media_create(BC_ILO_MEDIA_CD,token,&source,emit,&f,&m)==BC_OK);
    assert(f.length==54 && f.header[17]==3);
    bc_media_session *session=NULL;
    assert(bc_ilo_media_wrap(m,&session)==BC_OK);
    uint8_t hello[53]={0},cmd[12]={0};
    assert(bc_media_session_feed(session,(bc_bytes){hello,53})==BC_OK);
    assert(bc_media_session_feed(session,(bc_bytes){cmd,12})==BC_OK && f.header[9]==6 && f.header[10]==0x28);
    assert(bc_media_session_feed(session,(bc_bytes){cmd,12})==BC_OK && f.header[9]==0);
    cmd[0]=0x28;cmd[5]=1;cmd[8]=1;
    assert(bc_media_session_feed(session,(bc_bytes){cmd,12})==BC_OK && f.reads==1 && f.payloads==1);
    assert(bc_wire_read_le(f.header,4)==0x0badc0de && bc_wire_read_le(f.header+12,4)==2048);
    cmd[5]=4;
    assert(bc_media_session_feed(session,(bc_bytes){cmd,12})==BC_OK && f.header[9]==5 && f.header[10]==0x21 && f.reads==1);
    cmd[0]=0x2a;
    assert(bc_media_session_feed(session,(bc_bytes){cmd,12})==BC_OK && f.header[9]==7 && f.header[10]==0x27 && f.reads==1);
    assert(bc_media_session_control(session,BC_MEDIA_CONTROL_KEEPALIVE)==BC_OK && (f.header[4]&2));
    assert(bc_media_session_control(session,BC_MEDIA_CONTROL_EJECT)==BC_OK && (f.header[4]&4));
    assert(!bc_ilo_media_state_get(m)->attached && bc_ilo_media_state_get(m)->bytes_read==2048);
    bc_media_session_info info = {.struct_size = sizeof(info)};
    assert(bc_media_session_info_get(session,&info)==BC_OK);
    assert(info.bytes_read==2048 && !(info.flags & (BC_MEDIA_MOUNT_CONFIRMED|BC_MEDIA_REMOVAL_CONFIRMED)));
    bc_media_session_destroy(session);
    bc_ilo_media_destroy(m);m=NULL;
    assert(bc_ilo_media_create(BC_ILO_MEDIA_CD,token,&source,emit,&f,&m)==BC_OK);
    hello[16]=1;
    assert(bc_ilo_media_feed(m,hello,53)==BC_AUTHENTICATION_FAILED);
    assert(bc_ilo_media_state_get(m)->server_status==1 && !bc_ilo_media_state_get(m)->authenticated);
    assert(bc_ilo_media_feed(m,cmd,12)==BC_AUTHENTICATION_FAILED && f.reads==1);
    assert(bc_ilo_media_heartbeat(m)==BC_AUTHENTICATION_FAILED);
    bc_ilo_media_destroy(m);return 0;
}

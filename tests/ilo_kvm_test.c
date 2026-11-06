#include "bcontrol/ilo_session.h"
#include "bcontrol/ilo.h"
#include <assert.h>
#include <string.h>
static bc_status capture(void *user, const uint8_t *bytes, uint32_t length) {
    assert(length == 10); memcpy(user, bytes, length); return BC_OK;
}
int main(void) {
    bc_ilo_kvm *k=NULL;
    bc_string token={"0123456789abcdef0123456789abcdef",32};
    assert(bc_ilo_kvm_create(4,token,1920,1200,&k)==BC_UNSUPPORTED && !k);
    assert(bc_ilo_kvm_create(5,token,1920,1200,&k)==BC_OK);
    uint8_t out[64],hello[53]={0},hid[8]={0};uint32_t size;
    assert(bc_ilo_kvm_keyboard(k,hid)==BC_BUSY);
    for(unsigned ch=0;ch<2;++ch) {
        assert(bc_ilo_kvm_feed(k,ch,hello,53)==BC_BUSY);
        assert(bc_ilo_kvm_output(k,ch,out,53,&size)==BC_LIMIT_EXCEEDED && size==0);
        assert(bc_ilo_kvm_output(k,ch,out,sizeof(out),&size)==BC_OK && size==54 && out[17]==ch);
        assert(!memcmp(out+22,token.data,32));
        assert(bc_ilo_kvm_feed(k,ch,hello,53)==BC_OK);
    }
    assert(bc_ilo_kvm_ready(k));
    hid[2]=4;
    assert(bc_ilo_kvm_keyboard(k,hid)==BC_OK);
    assert(bc_ilo_kvm_refresh(k)==BC_BUSY);
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK && size==10 && out[4]==4);
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK && size==0);
    assert(bc_ilo_kvm_key_event(k,0xffe1,1)==BC_OK);
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK && out[2]==2);
    assert(bc_ilo_kvm_key_event(k,'A',1)==BC_OK);
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK && out[2]==2 && out[4]==4);
    assert(bc_ilo_kvm_key_event(k,0xffe1,0)==BC_OK);
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK && out[2]==2 && out[4]==4);
    assert(bc_ilo_kvm_key_event(k,'A',0)==BC_OK);
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK && out[2]==0 && out[4]==0);
    for(uint32_t key='a';key<='f';++key) {
        assert(bc_ilo_kvm_key_event(k,key,1)==BC_OK);
        assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK);
    }
    assert(bc_ilo_kvm_key_event(k,'g',1)==BC_LIMIT_EXCEEDED);
    assert(bc_ilo_kvm_key_event(k,0,0)==BC_OK);
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK && size==10);
    for(unsigned i=2;i<10;++i) assert(out[i]==0);
    assert(bc_ilo_kvm_pointer_event(k,8,4,2,0)==BC_BUSY);
    const uint8_t frame[]={0x0d,0x10,0x08,0xf0,0xff,0xbf,0x05};
    assert(bc_ilo_kvm_feed(k,0,frame,sizeof(frame))==BC_OK);
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK);
    assert(bc_ilo_kvm_pointer_event(k,8,4,2,-1)==BC_OK);
    const uint8_t mouse[]={2,0,0xdc,5,0xee,2,8,252,2,255};
    assert(bc_ilo_kvm_output(k,0,out,sizeof(out),&size)==BC_OK && size==sizeof(mouse));
    assert(!memcmp(out,mouse,sizeof(mouse)));
    bc_ilo_input *input=NULL;
    assert(bc_ilo_input_create(&input)==BC_OK);
    uint8_t independent[10];
    assert(bc_ilo_input_pointer(input,8,4,16,16,2,-1,independent,9)==BC_LIMIT_EXCEEDED);
    assert(bc_ilo_input_pointer(input,8,4,16,16,2,-1,independent,10)==BC_OK);
    assert(!memcmp(independent,mouse,sizeof(mouse)));
    assert(bc_ilo_input_key(input,'A',1,independent,9)==BC_LIMIT_EXCEEDED);
    assert(bc_ilo_input_key(input,'a',1,independent,10)==BC_OK);
    assert(independent[2]==0 && independent[4]==4);
    assert(bc_ilo_input_key(input,0,0,independent,10)==BC_OK);
    for(unsigned i=2;i<10;++i) assert(independent[i]==0);
    bc_ilo_input_destroy(input);
    assert(bc_ilo_input_create(&input)==BC_OK);
    bc_console_session *session=NULL;
    assert(bc_ilo_session_wrap(k,input,capture,independent,&session)==BC_OK);
    bc_console_input event={0}; event.struct_size=sizeof(event); event.type=BC_CONSOLE_INPUT_SCROLL;
    event.x=8; event.y=4; event.width=event.height=16; event.buttons=2; event.wheel=-1;
    assert(bc_console_session_input(session,&event)==BC_OK);
    assert(!memcmp(independent,mouse,sizeof(mouse)));
    bc_display_tile tile={0}; tile.struct_size=sizeof(tile);
    assert(bc_console_session_tile(session,&tile)==BC_OK && tile.canvas_width==16);
    bc_console_session_ack_display(session);
    assert(bc_console_session_tile(session,&tile)==BC_BUSY);
    bc_console_session_destroy(session);
    uint8_t share[12]={9};
    assert(bc_ilo_kvm_feed(k,1,share,sizeof(share))==BC_OK);
    assert(bc_ilo_kvm_output(k,1,out,sizeof(out),&size)==BC_OK && size==4 && out[0]==3);
    share[4]=1;
    assert(bc_ilo_kvm_feed(k,1,share,sizeof(share))==BC_PROTOCOL_ERROR);
    assert(!bc_ilo_kvm_ready(k));
    assert(bc_ilo_kvm_keyboard(k,hid)==BC_PROTOCOL_ERROR);
    assert(bc_ilo_input_key(input,'b',1,independent,10)==BC_OK);
    bc_ilo_input_destroy(input);
    bc_ilo_kvm_destroy(k);
    return 0;
}

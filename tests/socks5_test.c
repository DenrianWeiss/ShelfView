#include "bcontrol/socks5.h"
#include <assert.h>
#include <string.h>
typedef struct { const uint8_t *input; uint32_t size, offset, written; uint8_t output[600]; } exchange;
static bc_status read_bytes(void *user, uint8_t *out, uint32_t n) {
    exchange *e = user;
    if (n > e->size - e->offset) return BC_TIMEOUT;
    memcpy(out, e->input + e->offset, n); e->offset += n; return BC_OK;
}
static bc_status write_bytes(void *user, const uint8_t *data, uint32_t n) {
    exchange *e = user;
    assert(n <= sizeof(e->output) - e->written);
    memcpy(e->output + e->written, data, n); e->written += n; return BC_OK;
}
int main(void) {
    bc_socks5_address target = {BC_SOCKS5_DOMAIN, 3, {'b','m','c'}, 443}, parsed;
    uint8_t data[520], reply; uint32_t n, used;
    const uint8_t request[] = {5,1,0,3,3,'b','m','c',1,187};
    assert(bc_socks5_request(BC_SOCKS5_CONNECT,&target,data,sizeof(data),&n)==BC_OK);
    assert(n==sizeof(request) && !memcmp(data,request,n));
    data[1]=0;
    for (uint32_t size=0;size<n;++size) {
        assert(bc_socks5_reply(data,size,&parsed,&reply,&used)==BC_OK);
        assert(used==0 && reply==255);
    }
    assert(bc_socks5_reply(data,n,&parsed,&reply,&used)==BC_OK);
    assert(used==n && reply==0 && parsed.port==443 && parsed.length==3);
    data[1]=5;
    assert(bc_socks5_reply(data,n,&parsed,&reply,&used)==BC_OK && reply==5);
    data[2]=1;
    assert(bc_socks5_reply(data,n,&parsed,&reply,&used)==BC_PROTOCOL_ERROR);
    assert(bc_socks5_udp_header(&target,data,sizeof(data),&n)==BC_OK);
    assert(bc_socks5_udp_parse(data,n,&parsed,&used)==BC_OK && used==n);
    for (uint32_t size=0;size<n;++size)
        assert(bc_socks5_udp_parse(data,size,&parsed,&used)!=BC_OK && used==0);
    data[2]=1;
    assert(bc_socks5_udp_parse(data,n,&parsed,&used)==BC_UNSUPPORTED);
    for (unsigned family=0;family<2;++family) {
        target.type=family?BC_SOCKS5_IPV6:BC_SOCKS5_IPV4;
        target.length=family?16:4; target.port=623;
        memset(target.address,0xff,target.length);
        assert(bc_socks5_request(BC_SOCKS5_UDP_ASSOCIATE,&target,data,sizeof(data),&n)==BC_OK);
        data[1]=0;
        assert(bc_socks5_reply(data,n,&parsed,&reply,&used)==BC_OK);
        assert(parsed.port==623 && parsed.length==target.length && !memcmp(parsed.address,target.address,target.length));
    }
    const uint8_t response[] = {5,2,1,0,5,0,0,1,127,0,0,1,0x12,0x34};
    exchange e = {response,sizeof(response),0,0,{0}};
    assert(bc_socks5_negotiate(BC_SOCKS5_CONNECT,&target,(bc_string){"u",1},(bc_string){"p",1},
        read_bytes,write_bytes,&e,&parsed,&reply)==BC_OK);
    assert(e.offset==sizeof(response) && parsed.port==0x1234);
    const uint8_t prefix[] = {5,1,2,1,1,'u',1,'p'};
    assert(!memcmp(e.output,prefix,sizeof(prefix)));
    const uint8_t downgrade[] = {5,0};
    e=(exchange){downgrade,sizeof(downgrade),0,0,{0}};
    assert(bc_socks5_negotiate(BC_SOCKS5_CONNECT,&target,(bc_string){"u",1},(bc_string){"p",1},
        read_bytes,write_bytes,&e,&parsed,&reply)==BC_AUTHENTICATION_FAILED);
    assert(e.written==3);
    char full[255]; memset(full,'x',sizeof(full));
    assert(bc_socks5_auth((bc_string){full,255},(bc_string){full,255},data,512,&n)==BC_LIMIT_EXCEEDED && n==0);
    assert(bc_socks5_auth((bc_string){full,255},(bc_string){full,255},data,513,&n)==BC_OK && n==513);
    assert(data[0]==1 && data[1]==255 && data[257]==255);
    assert(bc_socks5_auth((bc_string){full,256},(bc_string){full,1},data,sizeof(data),&n)==BC_INVALID_ARGUMENT);
    return 0;
}

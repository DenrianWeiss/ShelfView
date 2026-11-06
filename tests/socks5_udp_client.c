#define _POSIX_C_SOURCE 200809L
#include "bcontrol/ipmi_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../platform/monotonic.h"
int main(int argc,char **argv) {
    if(argc!=4 && argc!=5) return 2;
    bc_socks5_proxy proxy={sizeof(proxy),{"127.0.0.1",9},{0},{0},(uint32_t)atoi(argv[1])};
    if(argc==5) { proxy.username=(bc_string){"user",4}; proxy.password=(bc_string){"secret",6}; }
    bc_ipmi_io *io=NULL;
    bc_status s=bc_ipmi_socks5_create((bc_string){argv[2],strlen(argv[2])},623,&proxy,1000,&io);
    if(s!=BC_OK) { fprintf(stderr,"create %u\n",s);return 3; }
    s=io->send(io->userdata,(const uint8_t *)"ping",4);
    uint8_t data[16]; uint32_t size=0;
    uint64_t start=bc_monotonic_ms();
    if(s==BC_OK) s=io->receive(io->userdata,data,sizeof(data),&size,1000);
    uint64_t elapsed=bc_monotonic_ms()-start;
    bc_ipmi_socks5_destroy(io);
    if(atoi(argv[3])==BC_IO_ERROR && elapsed>500) return 6;
    if(s!=(bc_status)atoi(argv[3])) { fprintf(stderr,"receive %u\n",s);return 4; }
    return s==BC_OK && (size!=4 || memcmp(data,"pong",4)) ? 5:0;
}

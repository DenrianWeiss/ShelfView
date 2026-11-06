#include "bcontrol/kvm_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    bc_kvm_transport_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.url = (bc_string){argv[2], strlen(argv[2])}; options.timeout_ms = 1000;
    bc_socks5_proxy proxy = {sizeof(proxy), {"127.0.0.1",9}, {"user",4}, {"secret",6}, (uint32_t)atoi(argv[1])};
    bc_kvm_transport *transport = NULL;
    bc_status status = bc_kvm_transport_connect_proxy(&options, &proxy, &transport);
    if (status != (bc_status)atoi(argv[3])) { fprintf(stderr,"status %u\n",status); return 3; }
    if (status != BC_OK) return transport ? 4 : 0;
    uint8_t reply[4]; uint32_t received = 0;
    status = bc_kvm_transport_send(transport,(const uint8_t *)"ping",4);
    if (status == BC_OK) status = bc_kvm_transport_recv(transport,reply,4,&received,1000);
    bc_kvm_transport_destroy(transport);
    return status == BC_OK && received == 4 && !memcmp(reply,"pong",4) ? 0 : 5;
}

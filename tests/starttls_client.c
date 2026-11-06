#include "bcontrol/kvm_transport.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 4 && argc != 6) return 2;
    bc_kvm_transport_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.url = (bc_string){argv[1], strlen(argv[1])}; options.timeout_ms = 1000;
    bc_kvm_transport *t = NULL;
    bc_status status = bc_kvm_transport_connect(&options, &t);
    uint8_t reply[4]; uint32_t got = 0;
    if (status == BC_OK) status = bc_kvm_transport_send(t, (const uint8_t *)"ping", 4);
    if (status == BC_OK) status = bc_kvm_transport_recv(t, reply, 4, &got, 1000);
    if (status != BC_OK || got != 4 || memcmp(reply, "pong", 4)) { bc_kvm_transport_destroy(t); return 3; }
    bc_kvm_tls_options tls = {0}; tls.struct_size = sizeof(tls); tls.abi_version = BC_ABI_VERSION;
    tls.ca_file = (bc_string){argv[2], strlen(argv[2])}; tls.timeout_ms = 1000;
    char certificate[65536], key[65536];
    if(argc==6) {
        FILE *cf=fopen(argv[4],"rb"),*kf=fopen(argv[5],"rb");
        if(!cf || !kf){if(cf)fclose(cf);if(kf)fclose(kf);bc_kvm_transport_destroy(t);return 5;}
        size_t cn=fread(certificate,1,sizeof(certificate),cf),kn=fread(key,1,sizeof(key),kf);
        fclose(cf);fclose(kf);
        bc_string cp={certificate,cn},kp={key,kn};
        bc_string invalid={"invalid",7};
        if(bc_kvm_transport_start_tls_identity(t,&tls,cp,invalid)==BC_OK || bc_kvm_transport_kind(t)!=BC_KVM_TRANSPORT_TCP) {
            bc_kvm_transport_destroy(t);return 6;
        }
        status=bc_kvm_transport_start_tls_identity(t,&tls,cp,kp);
        memset(certificate,0,sizeof(certificate));memset(key,0,sizeof(key));
    } else status = bc_kvm_transport_start_tls(t, &tls);
    int failed = 0;
    if (!strcmp(argv[3], "fail")) {
        failed = status == BC_OK || bc_kvm_transport_send(t, (const uint8_t *)"leak", 4) == BC_OK;
    } else {
        failed = status != BC_OK || bc_kvm_transport_kind(t) != BC_KVM_TRANSPORT_TLS;
        if (!failed) failed = bc_kvm_transport_start_tls(t, &tls) != BC_BUSY;
        if (!failed) failed = bc_kvm_transport_send(t, (const uint8_t *)"safe", 4) != BC_OK;
        if (!failed) failed = bc_kvm_transport_recv(t, reply, 4, &got, 1000) != BC_OK || got != 4 || memcmp(reply, "done", 4);
    }
    bc_kvm_transport_destroy(t); return failed ? 4 : 0;
}

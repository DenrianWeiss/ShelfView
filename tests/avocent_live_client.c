#include "bcontrol/avocent.h"
#include "bcontrol/kvm_transport.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bc_status receive(bc_kvm_transport *t, uint8_t *p, uint32_t size) {
    uint32_t n = 0;
    while (n < size) {
        uint32_t got = 0; bc_status s = bc_kvm_transport_recv(t, p + n, size - n, &got, 5000);
        if (s != BC_OK) return s;
        if (!got) return BC_IO_ERROR;
        n += got;
    }
    return BC_OK;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    uint8_t xml[65537]; size_t size = fread(xml, 1, sizeof(xml), f); fclose(f);
    bc_avocent_launch launch; bc_status status = bc_avocent_launch_parse(xml, (uint32_t)size, &launch);
    memset(xml, 0, sizeof(xml));
    bc_kvm_transport *t = NULL;
    if (status != BC_OK) goto done;
    char url[300]; snprintf(url, sizeof(url), strchr(launch.host, ':') ? "tcp://[%s]:%u" : "tcp://%s:%u", launch.host, launch.port);
    bc_kvm_transport_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.url = (bc_string){url, strlen(url)}; options.timeout_ms = 5000;
    status = bc_kvm_transport_connect(&options, &t); if (status != BC_OK) goto done;
    uint8_t nonce[32], packet[256]; if (RAND_bytes(nonce, sizeof(nonce)) != 1) { status = BC_IO_ERROR; goto done; }
    status = bc_avocent_apcp_request(launch.service, BC_AVOCENT_TRANSPORT_TLS, nonce, packet);
    if (status == BC_OK) status = bc_kvm_transport_send(t, packet, BC_AVOCENT_APCP_SIZE);
    if (status == BC_OK) status = receive(t, packet, BC_AVOCENT_APCP_SIZE);
    bc_avocent_setup setup;
    if (status == BC_OK) status = bc_avocent_apcp_parse(packet, BC_AVOCENT_APCP_SIZE, &setup);
    if (status != BC_OK) goto done;
    if (setup.port || setup.transports != BC_AVOCENT_TRANSPORT_TLS) { status = BC_UNSUPPORTED; goto done; }
    bc_kvm_tls_options tls = {0}; tls.struct_size = sizeof(tls); tls.abi_version = BC_ABI_VERSION;
    tls.cert_policy = BC_CERT_SKIP_ALL; tls.tls_min = BC_TLS_1_2; tls.timeout_ms = 5000;
    status = bc_kvm_transport_start_tls(t, &tls); if (status != BC_OK) goto done;
    uint32_t written = 0;
    status = bc_avocent_login_encode(&launch, 12345, packet, sizeof(packet), &written);
    if (status == BC_OK) status = bc_kvm_transport_send(t, packet, written);
    memset(packet, 0, sizeof(packet));
    uint32_t expected = launch.service == BC_AVOCENT_MEDIA ? 111 : 115;
    if (status == BC_OK) status = receive(t, packet, expected);
    bc_avocent_login_result result;
    if (status == BC_OK) status = bc_avocent_login_parse(launch.service, packet, expected, &result);
    if (status == BC_OK && result.status) status = BC_AUTHENTICATION_FAILED;
done:
    memset(&launch, 0, sizeof(launch)); bc_kvm_transport_destroy(t);
    printf("%s\n", bc_status_string(status)); return status == BC_OK ? 0 : 1;
}

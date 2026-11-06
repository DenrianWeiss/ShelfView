#include "bcontrol/avocent.h"
#include "bcontrol/kvm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
int main(void) {
    const char *xml = "<jnlp><application-desc main-class='com.avocent.kvm.client.Main'>"
        "<argument>ip=2001:db8::1</argument><argument>user=test</argument><argument>passwd=a&amp;b</argument>"
        "<argument>kmport=2068</argument><argument>vport=2068</argument><argument>apcp=1</argument>"
        "</application-desc></jnlp>";
    bc_avocent_launch launch;
    CHECK(bc_avocent_launch_parse((const uint8_t *)xml, (uint32_t)strlen(xml), &launch) == BC_OK);
    CHECK(launch.service == BC_AVOCENT_CONTROL && launch.port == 2068 && launch.apcp == 1);
    CHECK(!strcmp(launch.password, "a&b") && !strcmp(launch.host, "2001:db8::1"));
    uint8_t login[256]; uint32_t written = 0;
    CHECK(bc_avocent_login_encode(&launch, 0x12345678u, login, sizeof(login), &written) == BC_OK);
    CHECK(written == 217 && !memcmp(login, "BEEF", 4));
    CHECK(login[8] == 4 && login[105] == 3 && !memcmp(login + 106, "a&b", 3));
    CHECK(login[212] == 0x12 && login[213] == 0x34 && login[214] == 0x56 && login[215] == 0x78);
    CHECK(bc_avocent_login_encode(&launch, 1, login, 216, &written) == BC_LIMIT_EXCEEDED && !written);
    launch.service = BC_AVOCENT_MEDIA;
    CHECK(bc_avocent_login_encode(&launch, 0, login, sizeof(login), &written) == BC_OK && written == 153);
    CHECK(!memcmp(login, "AVMP", 4) && !memcmp(login + 109, "a&b", 3));
    memset(launch.password, 'x', 33); launch.password[33] = 0;
    CHECK(bc_avocent_login_encode(&launch, 0, login, sizeof(login), &written) == BC_INVALID_ARGUMENT);
    const uint8_t accepted[115] = {'B','E','E','F',0x83,5,0,115,0,35,0,30,0x12,0x34,0x56,0x78,0,2};
    bc_avocent_login_result result;
    CHECK(bc_avocent_login_parse(BC_AVOCENT_CONTROL, accepted, sizeof(accepted), &result) == BC_OK);
    CHECK(!result.status && result.session_id == 0x12345678u && result.flags == 2);
    CHECK(bc_avocent_login_parse(BC_AVOCENT_CONTROL, accepted, sizeof(accepted) - 1, &result) == BC_PROTOCOL_ERROR);
    const char *invalid = "<jnlp><application-desc main-class='com.avocent.vm.VirtualMedia'>"
        "<argument>ip=host</argument><argument>user=test</argument><argument>password=p</argument>"
        "<argument>port=65536</argument></application-desc></jnlp>";
    CHECK(bc_avocent_launch_parse((const uint8_t *)invalid, (uint32_t)strlen(invalid), &launch) == BC_PROTOCOL_ERROR);
    CHECK(!launch.password[0] && !launch.host[0]);
    uint8_t nonce[32] = {1}, request[53];
    CHECK(bc_avocent_apcp_request(BC_AVOCENT_CONTROL, BC_AVOCENT_TRANSPORT_TLS, nonce, request) == BC_OK);
    CHECK(!memcmp(request, "APCP\0\0\0\x35\x01\0\0\0\x03\x02\x22\0\0\0\0\x04\x20\x01", 22));
    const uint8_t reply[53] = {'A','P','C','P',0,0,0,53,0x81,0,0,0,2,34,0,0,0,4};
    bc_avocent_setup setup;
    CHECK(bc_avocent_apcp_parse(reply, sizeof(reply), &setup) == BC_OK);
    CHECK(setup.major == 2 && setup.minor == 34 && setup.transports == BC_AVOCENT_TRANSPORT_TLS);
    for (uint32_t n = 0; n < sizeof(reply); ++n)
        CHECK(bc_avocent_apcp_parse(reply, n, &setup) == BC_PROTOCOL_ERROR);
    memcpy(request, reply, sizeof(reply)); request[20] = 33;
    CHECK(bc_avocent_apcp_parse(request, sizeof(request), &setup) == BC_PROTOCOL_ERROR);
    bc_kvm_detection detection;
    CHECK(bc_kvm_classify_console((const uint8_t *)xml, (uint32_t)strlen(xml), &detection) == BC_OK);
    CHECK(detection.vendor == BC_KVM_VENDOR_AVOCENT);
    const char *dell = "com.avocent.idrac.kvm.Main avctKVM";
    CHECK(bc_kvm_classify_console((const uint8_t *)dell, (uint32_t)strlen(dell), &detection) == BC_OK);
    CHECK(detection.vendor == BC_KVM_VENDOR_IDRAC);
    uint8_t key[16];
    CHECK(bc_avocent_key_encode(0x1234, 1, key) == BC_OK);
    CHECK(!memcmp(key, "BEEF\x02\x00\x00\x10\x00\x00\x12\x34\x00\x00\x00\x00", 16));
    CHECK(bc_avocent_key_encode(4, 0, key) == BC_OK && key[9] == 1 && key[11] == 4);
    CHECK(bc_avocent_key_encode(0x10000, 1, key) == BC_INVALID_ARGUMENT);
    CHECK(bc_avocent_key_encode(4, 2, key) == BC_INVALID_ARGUMENT);
    CHECK(bc_avocent_key_encode(4, 1, NULL) == BC_INVALID_ARGUMENT);
    return 0;
}

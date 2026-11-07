#include "bcontrol/avocent.h"
#include "bcontrol/kvm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
int main(void) {
    bc_avocent_video *video = NULL;
    CHECK(bc_avocent_video_create(2, 2, &video) == BC_OK);
    uint8_t part[26] = {0xde,0xad,0xbe,0xef,0,0x8b,0,26,10,5,0,0,0,2,0,2,0,0,0,0,0,1,0,1,0x81,0x23};
    CHECK(bc_avocent_video_feed(video, part, sizeof(part)) == BC_OK);
    CHECK(!(bc_avocent_video_frame(video)->flags & BC_KVM_FRAME_READY));
    part[7] = 25; part[9] = 6; part[10] = 1; part[24] = 0x45;
    CHECK(bc_avocent_video_feed(video, part, 25) == BC_OK);
    const bc_kvm_frame *decoded = bc_avocent_video_frame(video);
    CHECK(decoded->width == 2 && decoded->height == 2 && (decoded->flags & BC_KVM_FRAME_READY));
    CHECK(!memcmp(decoded->pixels, "\x02\x46\x8a\xff", 4));
    bc_avocent_video_ack(video);
    CHECK(!(decoded->flags & BC_KVM_FRAME_READY));
    bc_avocent_video_destroy(video);
    uint32_t pixels[8] = {0};
    const uint8_t dvc[] = {0x81, 0x23, 0x45, 0x23, 0x44};
    CHECK(bc_avocent_dvc23_decode(dvc, sizeof(dvc), 4, 2, pixels, 8) == BC_OK);
    for (unsigned i = 0; i < 8; ++i) CHECK(pixels[i] == 0x12345);
    const uint8_t skip[] = {8};
    CHECK(bc_avocent_dvc23_decode(skip, sizeof(skip), 4, 2, pixels, 8) == BC_OK);
    CHECK(pixels[7] == 0x12345);
    const uint8_t overflow[] = {0x29}, above[] = {0x48}, truncated[] = {0x80, 0};
    CHECK(bc_avocent_dvc23_decode(overflow, sizeof(overflow), 4, 2, pixels, 8) == BC_PROTOCOL_ERROR);
    CHECK(bc_avocent_dvc23_decode(above, sizeof(above), 4, 2, pixels, 8) == BC_PROTOCOL_ERROR);
    CHECK(bc_avocent_dvc23_decode(truncated, sizeof(truncated), 4, 2, pixels, 8) == BC_PROTOCOL_ERROR);
    const uint8_t bitmap[] = {0x80, 0, 1, 0x80, 0, 2, 0x6a, 0x22};
    CHECK(bc_avocent_dvc23_decode(bitmap, sizeof(bitmap), 4, 2, pixels, 8) == BC_OK);
    CHECK(pixels[2] == 1 && pixels[3] == 2 && pixels[4] == 1 && pixels[5] == 2 && pixels[7] == 2);
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
    CHECK(bc_avocent_login_v4_encode((bc_string){"user", 4}, (bc_string){"ticket", 6},
        0x12345678, login, sizeof(login), &written) == BC_OK);
    CHECK(written == 41 && !memcmp(login, "BEEF\x01\x04\0\x29\0\x04\0\x1f\0\x06\0\x23", 16));
    CHECK(!memcmp(login + 26, "\x12\x34\x56\x78\0userticket", 15));
    CHECK(bc_avocent_login_v4_encode((bc_string){"user", 4}, (bc_string){"ticket", 6},
        0, login, 40, &written) == BC_LIMIT_EXCEEDED && !written);
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
    uint8_t extended[68];
    CHECK(bc_avocent_apcp_websocket_request(BC_AVOCENT_CONTROL, 0x12345678, extended) == BC_OK);
    CHECK(!memcmp(extended, "APCP\0\0\0\x44\x01\0\x01\x04\x03\x02\x29\0\0\0\x06\x05\x20", 21));
    CHECK(extended[54] == 20 && extended[57] == 180 && extended[59] == 30);
    CHECK(!memcmp(extended + 60, "\x12\x34\x56\x78", 4));
    const uint8_t extended_reply[68] = {'A','P','C','P',0,0,0,68,0x81,0,1,4,2,41,0,0,6,4};
    CHECK(bc_avocent_apcp_parse(extended_reply, sizeof(extended_reply), &setup) == BC_OK);
    CHECK(setup.major == 2 && setup.minor == 41 && setup.transports == 0x604);
    bc_avocent_kvm *kvm = NULL;
    CHECK(bc_avocent_kvm_create((bc_string){"user",4}, (bc_string){"ticket",6}, 7, 2, 2, &kvm) == BC_OK);
    CHECK(bc_avocent_kvm_output(kvm, 0, login, sizeof(login), &written) == BC_OK && written == 68);
    for (uint32_t i = 0; i < sizeof(extended_reply); ++i)
        CHECK(bc_avocent_kvm_feed(kvm, 0, extended_reply + i, 1) == BC_OK);
    CHECK(bc_avocent_kvm_output(kvm, 0, login, sizeof(login), &written) == BC_OK && written == 41);
    CHECK(bc_avocent_kvm_feed(kvm, 0, accepted, sizeof(accepted)) == BC_OK);
    CHECK(bc_avocent_kvm_output(kvm, 1, login, sizeof(login), &written) == BC_OK && written == 68);
    CHECK(bc_avocent_kvm_feed(kvm, 1, extended_reply, sizeof(extended_reply)) == BC_OK);
    CHECK(bc_avocent_kvm_output(kvm, 1, login, sizeof(login), &written) == BC_OK && written == 16);
    const uint8_t commands[][2] = {{2,8},{3,14},{3,1}};
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(bc_avocent_kvm_output(kvm, 0, login, sizeof(login), &written) == BC_OK && written == 16);
        CHECK(!memcmp(login + 4, commands[i], 2));
    }
    CHECK(bc_avocent_kvm_output(kvm, 0, login, sizeof(login), &written) == BC_OK && !written);
    bc_avocent_kvm_destroy(kvm);
    CHECK(bc_avocent_apcp_websocket_request(BC_AVOCENT_MEDIA, 0, extended) == BC_OK);
    CHECK(extended[11] == 3 && extended[12] == 2 && extended[13] == 1 && extended[14] == 14);
    CHECK(bc_avocent_media_login_v4_encode((bc_string){"user",4}, (bc_string){"ticket",6}, login, sizeof(login), &written) == BC_OK && written == 74);
    CHECK(login[9] == 4 && login[13] == 4 && login[15] == 64 && login[17] == 6 && login[19] == 68);
    CHECK(!memcmp(login + 64, "userticket", 10));
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
    CHECK(bc_avocent_pointer_encode(1023, 767, 5, -1, key) == BC_OK);
    CHECK(!memcmp(key, "BEEF\x02\x01\x00\x10\x00\x05\x03\xff\x02\xff\xff\xff", 16));
    CHECK(bc_avocent_pointer_encode(65536, 0, 0, 0, key) == BC_INVALID_ARGUMENT);
    CHECK(bc_avocent_pointer_encode(0, 0, 8, 0, key) == BC_INVALID_ARGUMENT);
    CHECK(bc_avocent_key_encode(0x1234, 1, key) == BC_OK);
    CHECK(!memcmp(key, "BEEF\x02\x00\x00\x10\x00\x00\x12\x34\x00\x00\x00\x00", 16));
    CHECK(bc_avocent_key_encode(4, 0, key) == BC_OK && key[9] == 1 && key[11] == 4);
    CHECK(bc_avocent_key_encode(0x10000, 1, key) == BC_INVALID_ARGUMENT);
    CHECK(bc_avocent_key_encode(4, 2, key) == BC_INVALID_ARGUMENT);
    CHECK(bc_avocent_key_encode(4, 1, NULL) == BC_INVALID_ARGUMENT);
    return 0;
}

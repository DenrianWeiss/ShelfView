#include "megarac.h"
#include "bcontrol/megarac_session.h"
#include "bcontrol/zte.h"
#include "bcontrol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static void tunnel_contract(void) {
    bc_megarac_kvm_info info = {0};
    info.struct_size = sizeof(info); info.single_port = 1; info.secure = 1; info.port = 443;
    strcpy(info.host, "192.0.2.1"); strcpy(info.cookie, "cookie");
    uint8_t out[512]; uint32_t n = 99;
    CHECK(bc_megarac_tunnel_request(&info, BC_MEGARAC_TUNNEL_CD, out, sizeof(out), &n) == BC_OK);
    const char expected[] = "CONNECT 192.0.2.1:443 HTTPS/1.1\r\n cookie cookie\r\n\r\nJVIEWER CDMEDIA cookie cookie\r\n\r\n";
    CHECK(n == sizeof(expected) - 1 && !memcmp(out, expected, n));
    CHECK(bc_megarac_tunnel_request(&info, BC_MEGARAC_TUNNEL_CD, out, 1, &n) == BC_LIMIT_EXCEEDED && !n);
    CHECK(bc_megarac_tunnel_request(&info, 3, out, sizeof(out), &n) == BC_INVALID_ARGUMENT);
    strcpy(info.cookie, "cookie\r\nInjected: value");
    CHECK(bc_megarac_tunnel_request(&info, BC_MEGARAC_TUNNEL_CD, out, sizeof(out), &n) == BC_INVALID_ARGUMENT);
    const char reply[] = "HTTP/1.0 200 OK  \r\n\r\n";
    for (unsigned i = 0; i < sizeof(reply) - 1; ++i)
        CHECK(bc_megarac_tunnel_response((const uint8_t *)reply, i, &n) == BC_BUSY && !n);
    CHECK(bc_megarac_tunnel_response((const uint8_t *)reply, sizeof(reply), &n) == BC_OK && n == sizeof(reply) - 1);
    const uint8_t irmc_reply[] = "HTTP/1.1 200 OK\r\n\x17\0\0\0\0\0\x01\0";
    CHECK(bc_megarac_tunnel_status_line(irmc_reply, 16, &n) == BC_BUSY && !n);
    CHECK(bc_megarac_tunnel_status_line(irmc_reply, sizeof(irmc_reply), &n) == BC_OK && n == 17);
    const char denied[] = "HTTP/1.1 403 Forbidden\r\n\r\n";
    CHECK(bc_megarac_tunnel_response((const uint8_t *)denied, sizeof(denied), &n) == BC_AUTHENTICATION_FAILED && !n);
    memset(out, 'X', sizeof(out));
    CHECK(bc_megarac_tunnel_response(out, 256, &n) == BC_LIMIT_EXCEEDED);
}

static void auto_break_keyboard(bc_megarac_session *session) {
    uint8_t out[64], keys[6] = {8}; uint32_t n;
    /* USBKeyboardRep + USBKeyProcessorEnglish, autoKeybreakMode=true, seq=0. */
    const uint8_t original[] = {
        1,0,41,0,0,0,0,0,73,85,83,66,32,32,32,32,1,0,32,97,9,0,0,0,
        0,48,16,128,2,0,0,0,0,0,0,0,0,0,0,0,8,0,1,8,0,0,0,0,0
    };
    CHECK(bc_megarac_session_flags(session) & BC_MEGARAC_KEYBOARD_AUTOBREAK);
    bc_kvm_frame frame = {0}; frame.struct_size = sizeof(frame);
    bc_console_session *console = NULL;
    CHECK(bc_megarac_console_wrap(session, &frame, &console) == BC_OK);
    bc_console_info schedule = {0}; schedule.struct_size = sizeof(schedule);
    CHECK(bc_console_session_info_get(console, &schedule) == BC_OK && schedule.tick_interval_ms == 25);
    bc_console_session_destroy(console);
    CHECK(bc_megarac_session_keyboard(session, 0, keys) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && n == sizeof(original));
    CHECK(!memcmp(out, original, sizeof(original)));
    CHECK(bc_megarac_session_tick(session, 1000) == BC_OK);
    CHECK(bc_megarac_session_keyboard(session, 0, keys) == BC_OK);
    CHECK(bc_megarac_session_tick(session, 1499) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && !n);
    CHECK(bc_megarac_session_tick(session, 1500) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && n == 49 && out[42] == 1 && out[43] == 8);
    memset(keys, 0, sizeof(keys));
    CHECK(bc_megarac_session_keyboard(session, 0, keys) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && !n);
    CHECK(bc_megarac_session_tick(session, 2000) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && !n);
    CHECK(bc_megarac_session_keyboard(session, 2, NULL) == BC_OK);
    CHECK(bc_megarac_session_keyboard(session, 0, NULL) == BC_OK);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && n == 49 && out[41] == (i ? 0 : 2));
    CHECK(bc_megarac_session_tick(session, 2100) == BC_OK);
    CHECK(bc_megarac_session_tick(session, 2200) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && n == 49 && out[41] == 0 && out[43] == 0);
    CHECK(bc_megarac_session_tick(session, 3000) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && !n);
    CHECK(bc_megarac_session_tick(session, 2999) == BC_INVALID_ARGUMENT);
    keys[0] = 8;
    CHECK(bc_megarac_session_keyboard(session, 2, keys) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && n == 49);
    CHECK(bc_megarac_session_keyboard_release(session) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && n == 49 && out[41] == 0 && out[43] == 0);
    CHECK(bc_megarac_session_tick(session, 4000) == BC_OK);
    CHECK(bc_megarac_session_output(session, out, sizeof(out), &n) == BC_OK && !n);
    CHECK(bc_megarac_session_keyboard_mode(session, BC_MEGARAC_KEYBOARD_REPORT) == BC_BUSY);
}
static void single_port_session(uint32_t kind) {
    bc_megarac_kvm_info info = {0};
    info.struct_size = sizeof(info); info.single_port = 1; info.secure = 1; info.port = 443;
    strcpy(info.host, "192.0.2.1"); strcpy(info.cookie, "web-cookie"); strcpy(info.token, "kvm-token");
    uint8_t frames[4096], output[4096]; uint32_t n;
    bc_megarac_session_options options = {sizeof(options), kind, &info,
        "192.0.2.2", "admin", "", frames, sizeof(frames)};
    int irmc = kind == BC_MEGARAC_KVM_JVIEWER_IRMC;
    const char *reply = irmc ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.0 200 OK  \r\n\r\n";
    uint32_t length = (uint32_t)strlen(reply) + 1;
    for (uint32_t split = 0; split <= length; ++split) {
        bc_megarac_session *session = NULL;
        CHECK(bc_megarac_session_create(&options, &session) == BC_OK);
        CHECK(bc_megarac_session_start(session) == BC_OK);
        CHECK(bc_megarac_session_output(session, output, sizeof(output), &n) == BC_OK);
        const char request[] = "CONNECT 192.0.2.1:443 HTTPS/1.1\r\n cookie web-cookie\r\n\r\n"
            "JVIEWER VIDEO cookie web-cookie\r\n\r\n";
        CHECK(n == sizeof(request) - 1 && !memcmp(output, request, n));
        CHECK(bc_megarac_session_feed(session, (const uint8_t *)reply, split) == BC_OK);
        CHECK(bc_megarac_session_feed(session, (const uint8_t *)reply + split, length - split) == BC_OK);
        CHECK(bc_megarac_session_output(session, output, sizeof(output), &n) == BC_OK && n == 0);
        const uint8_t accepted[] = {23,0,0,0,0,0,0,0};
        CHECK(bc_megarac_session_feed(session, accepted, sizeof(accepted)) == BC_OK);
        const uint32_t sizes[] = {8,381,8}; const uint8_t ops[] = {58,18,6};
        CHECK(bc_megarac_session_output(session, output, 7, &n) == BC_LIMIT_EXCEEDED && !n);
        for (unsigned i = 0; i < 3; ++i) {
            CHECK(bc_megarac_session_output(session, output, sizeof(output), &n) == BC_OK);
            CHECK(n == sizes[i] && output[0] == ops[i]);
            if (i == 1) CHECK(bc_wire_read_le(output + 2, 4) == 381);
        }
        CHECK(bc_megarac_session_feed(session, accepted, sizeof(accepted)) == BC_OK);
        CHECK(bc_megarac_session_output(session, output, sizeof(output), &n) == BC_OK && !n);
        const uint8_t valid[] = {19,0,2,0,0,0,0,0,1,0};
        CHECK(bc_megarac_session_feed(session, valid, sizeof(valid)) == BC_OK);
        CHECK(bc_megarac_session_state(session) == BC_MEGARAC_STATE_STREAMING);
        if (irmc) {
            const uint8_t startup[] = {6, 20, 4, 6, 20, 34};
            for (size_t i = 0; i < sizeof(startup); ++i) {
                CHECK(bc_megarac_session_output(session, output, sizeof(output), &n) == BC_OK && n == 8);
                CHECK(output[0] == startup[i]);
            }
            uint8_t fragment[45] = {BC_MEGARAC_OP_VIDEO_FRAGMENT, 0, 37, 0, 0, 0, 0, 0, 0, 128};
            bc_wire_write_le(fragment + 15, 1, 4);
            bc_wire_write_le(fragment + 19, 640, 2);
            bc_wire_write_le(fragment + 21, 480, 2);
            CHECK(bc_megarac_session_feed(session, fragment, sizeof(fragment)) == BC_OK);
            const bc_megarac_video_header *frame = bc_megarac_session_frame(session);
            CHECK(frame && frame->width == 640 && frame->height == 480 && frame->flags == BC_MEGARAC_VIDEO_SOC);
            bc_megarac_session_ack_frame(session);
            const uint8_t media_states[] = {1, 0};
            for (size_t i = 0; i < sizeof(media_states); ++i) {
                uint8_t connected = media_states[i];
                CHECK(bc_megarac_session_media_state(session, connected) == BC_OK);
                CHECK(bc_megarac_session_output(session, output, sizeof(output), &n) == BC_OK && n == 8);
                CHECK(output[0] == BC_MEGARAC_OP_MEDIA_STATE && output[6] == connected);
            }
        }
        const uint8_t heartbeat[] = {57,0,0,0,0,0,0,0};
        CHECK(bc_megarac_session_feed(session, heartbeat, sizeof(heartbeat)) == BC_OK);
        CHECK(bc_megarac_session_output(session, output, sizeof(output), &n) == BC_OK && !n);
        if (!split) auto_break_keyboard(session);
        bc_megarac_session_destroy(session);
    }
    bc_megarac_session *session = NULL;
    CHECK(bc_megarac_session_create(&options, &session) == BC_OK);
    CHECK(bc_megarac_session_start(session) == BC_OK);
    const char denied[] = "HTTP/1.0 ERROR:4 \r\n\r\n";
    CHECK(bc_megarac_session_feed(session, (const uint8_t *)denied, sizeof(denied)) == BC_HTTP_ERROR);
    CHECK(bc_megarac_session_state(session) == BC_MEGARAC_STATE_ERROR);
    bc_megarac_session_destroy(session);
    strcpy(info.cookie, "injected\r\nheader");
    CHECK(bc_megarac_session_create(&options, &session) == BC_OK);
    CHECK(bc_megarac_session_start(session) == BC_INVALID_ARGUMENT);
    bc_megarac_session_destroy(session);
}

static bc_status cd_read(void *userdata, uint64_t offset, uint32_t length, uint8_t *out) {
    (void)userdata;
    if (offset != 2048 || length != 2048) return BC_IO_ERROR;
    memset(out, 0x5a, length);
    return BC_OK;
}
static void cd_command(uint8_t request[61], uint8_t opcode, uint32_t allocation) {
    memset(request, 0, 61); memcpy(request, "IUSB    ", 8);
    request[8] = 1; request[10] = 32; request[12] = 29; request[17] = 5; request[18] = 1;
    request[11] = bc_wire_checksum(request, 32);
    bc_wire_write_le(request + 32, allocation, 4); request[41] = opcode;
}
static void zte_contract(void) {
    const char *root = "{\"Product\":\"ZTE Redfish Server\",\"RedfishVersion\":\"1.15.1\"}";
    CHECK(bc_zte_service_root_matches((const uint8_t *)root, (uint32_t)strlen(root)));
    char json[1024], token[129];
    const char *urls[] = {"https://bmc/viewer.html?&token=abc123", "https://other/viewer.html?token=abc123",
        "https://bmc.evil/viewer.html?token=abc123", "https://bmc/viewer.html?token=abc&password=x",
        "https://bmc/viewer.html?token=abc%0d", "https://bmc/viewer.html?token="};
    for (unsigned i = 0; i < sizeof(urls) / sizeof(urls[0]); ++i) {
        snprintf(json, sizeof(json), "{\"@odata.id\":\"/redfish/v1/Managers/Self/KvmService\","
            "\"@odata.type\":\"#KvmService.v1_0_0.KvmService\",\"KvmUrl\":\"%s\"}", urls[i]);
        bc_status status = bc_zte_kvm_token((const uint8_t *)json, (uint32_t)strlen(json),
            (bc_string){"https://bmc", 11}, token, sizeof(token));
        CHECK(i ? status == BC_PROTOCOL_ERROR && !token[0] : status == BC_OK && !strcmp(token, "abc123"));
    }
    const char *config = "{\"num_cd\":1,\"kvm_num_cd\":1,\"kvm_service_status\":1}";
    bc_megarac_media_parameters media;
    CHECK(bc_megarac_h5_media_parameters((const uint8_t *)config, (uint32_t)strlen(config), &media) == BC_OK);
    CHECK(bc_megarac_media_parameters_transport_usable(&media));
    CHECK(bc_megarac_h5_media_parameters((const uint8_t *)"{}", 2, &media) == BC_UNSUPPORTED);
    CHECK(!bc_megarac_media_parameters_transport_usable(&media));
    uint8_t request[62] = {0}, reply[4096]; uint32_t written = 0;
    memcpy(request, "IUSB    ", 8); request[12] = 30; request[41] = 0xa8;
    request[46] = 1; request[47] = 1; /* LBA BE, legacy READ(12) transfer length LE. */
    bc_megarac_cd_source source = {sizeof(source), NULL, 4096, cd_read};
    CHECK(bc_megarac_cd_respond(request, sizeof(request), &source, reply, sizeof(reply), &written) == BC_OK);
    CHECK(written == 61 + 2048 && reply[61] == 0x5a && !bc_wire_checksum(reply, written));
    request[47] = 3;
    CHECK(bc_megarac_cd_respond(request, sizeof(request), &source, reply, sizeof(reply), &written) == BC_PROTOCOL_ERROR);
    request[16] = 1;
    bc_megarac_media_packet packet;
    CHECK(bc_megarac_media_packet_decode(request, sizeof(request), &packet) == BC_PROTOCOL_ERROR);
    CHECK(bc_megarac_media_disconnect(0, reply, sizeof(reply), &written) == BC_OK);
    CHECK(written == 62 && reply[41] == 0xf7 && !bc_wire_checksum(reply, 32));
}

static void stateful_cd(void) {
    bc_megarac_cd_source source = {sizeof(source), NULL, 4096, cd_read};
    bc_megarac_cd *cd = NULL, *other = NULL;
    CHECK(bc_megarac_cd_create(&source, &cd) == BC_OK);
    CHECK(bc_megarac_cd_create(&source, &other) == BC_OK);
    uint8_t request[61], reply[4096]; uint32_t n = 0;
    bc_megarac_cd_info info = {0}; info.struct_size = sizeof(info);
    cd_command(request, 0, 0);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, 60, &n) == BC_LIMIT_EXCEEDED && n == 0);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    CHECK(n == 61 && reply[53] == 1 && reply[54] == 6 && reply[55] == 0x28);
    cd_command(request, 3, 18); request[45] = 18;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, 61, &n) == BC_LIMIT_EXCEEDED);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    CHECK(n == 79 && reply[63] == 6 && reply[73] == 0x28);
    CHECK(bc_megarac_cd_info_get(cd, &info) == BC_OK && info.sense_key == 0);
    cd_command(request, 0x4a, 8); request[42] = 1; request[45] = 0x10; request[49] = 4;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    CHECK(n == 65 && reply[62] == 6 && reply[63] == 4 && reply[64] == 0x10);
    CHECK(bc_megarac_cd_info_get(cd, &info) == BC_OK && (info.flags & BC_MEGARAC_CD_EVENT_PENDING));
    request[49] = 8;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    CHECK(n == 69 && reply[65] == 2 && reply[66] == 2);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && reply[65] == 0);
    request[45] = 0;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && n == 65 && reply[63] == 0x80);
    cd_command(request, 0x2a, 2048);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    CHECK(reply[53] == 1 && reply[54] == 7 && reply[55] == 0x27 && n == 61);
    cd_command(request, 0x1e, 0); request[45] = 1;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    cd_command(request, 0x1b, 0); request[45] = 2;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    CHECK(reply[53] == 1 && reply[54] == 5 && reply[55] == 0x53 && reply[56] == 2);
    cd_command(request, 0x1e, 0);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    cd_command(request, 0x1b, 0); request[45] = 2;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && reply[53] == 0);
    CHECK(bc_megarac_cd_info_get(cd, &info) == BC_OK && !(info.flags & BC_MEGARAC_CD_PRESENT));
    cd_command(request, 0, 0);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && reply[54] == 6);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && reply[54] == 2 && reply[55] == 0x3a);
    cd_command(request, 0x1b, 0); request[45] = 3;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && reply[53] == 0);
    cd_command(request, 3, 18); request[45] = 18;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    CHECK(reply[63] == 2 && reply[73] == 0x3a);
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK);
    CHECK(reply[63] == 6 && reply[73] == 0x28);
    cd_command(request, 0x28, 2048); request[48] = 0; request[49] = 1; request[46] = 2;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && reply[55] == 0x21);
    request[46] = 0;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && reply[54] == 3 && reply[55] == 0x11);
    request[46] = 1;
    CHECK(bc_megarac_cd_handle(cd, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && n == 2109 && reply[61] == 0x5a);
    CHECK(bc_megarac_cd_info_get(other, &info) == BC_OK && info.sense_key == 0 && (info.flags & BC_MEGARAC_CD_PRESENT));
    cd_command(request, 0, 0);
    CHECK(bc_megarac_cd_handle(other, request, sizeof(request), reply, sizeof(reply), &n) == BC_OK && reply[54] == 6);
    bc_megarac_cd_destroy(cd); bc_megarac_cd_destroy(other);
}
static void media_launch_parameters(void) {
    const char *variants[] = {
        "<argument>-kvmtokentype</argument><argument>0</argument><argument>-singleportenabled</argument><argument>0</argument>",
        "", "<argument>-kvmtokentype</argument><argument>1</argument>",
        "<argument>-vmsecure</argument><argument>1</argument>",
        "<argument>-cdport</argument><argument>0</argument>",
        "<argument>-kvmtokentype</argument><argument>0</argument><argument>-kvmtokentype</argument><argument>0</argument>"
    };
    for (uint32_t i = 0; i < 6; ++i) {
        char xml[2048];
        snprintf(xml, sizeof(xml), "<jnlp><application-desc main-class='com.ami.kvm.jviewer.JViewer'>"
            "<argument>-hostname</argument><argument>bmc.example</argument>"
            "<argument>-kvmtoken</argument><argument>fixture</argument>"
            "<argument>-kvmport</argument><argument>7582</argument><argument>-kvmsecure</argument><argument>1</argument>"
            "<argument>-vmsecure</argument><argument>0</argument><argument>-cdport</argument><argument>6200</argument>"
            "<argument>-cdnum</argument><argument>1</argument>%s</application-desc></jnlp>", variants[i]);
        bc_megarac_media_parameters params;
        bc_status status = bc_megarac_jviewer_media_parameters((const uint8_t *)xml, (uint32_t)strlen(xml), &params);
        CHECK(status == (i >= 3 ? BC_PROTOCOL_ERROR : BC_OK));
        if (status == BC_OK) {
            CHECK(params.port == 6200 && !params.secure && params.devices == 1);
            CHECK(bc_megarac_media_parameters_transport_usable(&params) == (i == 0));
            CHECK(!!(params.flags & BC_MEGARAC_MEDIA_TOKEN_TYPE_PRESENT) == (i != 1));
            if (i == 0) {
                params.flags &= ~BC_MEGARAC_MEDIA_SINGLE_PORT_PRESENT;
                CHECK(!bc_megarac_media_parameters_transport_usable(&params));
                params.flags |= BC_MEGARAC_MEDIA_SINGLE_PORT_RESOURCE_DEFAULT;
                CHECK(bc_megarac_media_parameters_transport_usable(&params));
                params.single_port = 1;
                CHECK(!bc_megarac_media_parameters_transport_usable(&params));
            }
        }
        bc_megarac_kvm_info info; bc_service_profile profile;
        CHECK(bc_megarac_discover_jnlp((const uint8_t *)xml, (uint32_t)strlen(xml), &info, &profile) ==
            (i == 2 ? BC_UNSUPPORTED : i == 5 ? BC_PROTOCOL_ERROR : BC_OK));
    }
    const char *minimal = "<jnlp><application-desc main-class='com.ami.kvm.jviewer.JViewer'/></jnlp>";
    bc_megarac_media_parameters params;
    CHECK(bc_megarac_jviewer_media_parameters((const uint8_t *)minimal, (uint32_t)strlen(minimal), &params) == BC_OK);
    CHECK(!params.flags && !bc_megarac_media_parameters_transport_usable(&params));
}
int main(void) {
    zte_contract();
    media_launch_parameters();
    uint8_t packet[1024];
    bc_megarac_ivtp header = {0x12, 1, 3};
    const uint8_t payload[3] = {1, 2, 3};
    uint32_t written = 0;
    CHECK(bc_megarac_ivtp_encode(&header, payload, packet, sizeof(packet), &written) == BC_OK && written == 11);
    CHECK(packet[0] == 0x12 && packet[1] == 0 && packet[2] == 3 && packet[6] == 1 && packet[8] == 1);
    bc_megarac_ivtp decoded;
    const uint8_t *view = NULL;
    uint32_t consumed = 0;
    CHECK(bc_megarac_ivtp_decode(packet, written, &decoded, &view, &consumed) == BC_OK);
    CHECK(decoded.type == 0x12 && decoded.status == 1 && decoded.length == 3 && consumed == 11 && view[2] == 3);
    CHECK(bc_megarac_ivtp_decode(packet, 5, &decoded, &view, &consumed) == BC_INVALID_ARGUMENT);

    const char jnlp[] = "<jnlp><application-desc main-class=\"com.ami.kvm.jviewer.JViewer\">"
        "<argument>-hostname</argument><argument>10.0.0.5</argument>"
        "<argument>-kvmport</argument><argument>7582</argument>"
        "<argument>-kvmsecure</argument><argument>1</argument>"
        "<argument>-kvmtoken</argument><argument>ABC</argument>"
        "<argument>-webcookie</argument><argument>COOKIE</argument>"
        "<argument>-singleportenabled</argument><argument>0</argument></application-desc></jnlp>";
    bc_megarac_kvm_info info;
    CHECK(bc_megarac_parse_jnlp((const uint8_t *)jnlp, (uint32_t)strlen(jnlp), &info) == BC_OK);
    CHECK(info.kind == BC_MEGARAC_KVM_JVIEWER && !strcmp(info.host, "10.0.0.5") && info.port == 7582 && info.secure == 1);
    CHECK(!strcmp(info.token, "ABC") && !strcmp(info.cookie, "COOKIE") && info.single_port == 0);
    bc_megarac_kvm_info legacy_discovered;
    bc_service_profile legacy_profile;
    CHECK(bc_megarac_discover_jnlp((const uint8_t *)jnlp, (uint32_t)strlen(jnlp),
        &legacy_discovered, &legacy_profile) == BC_OK);
    CHECK(legacy_discovered.port == 7582 && !legacy_discovered.kind && !legacy_profile.variant);
    CHECK(!bc_service_profile_can_attempt(&legacy_profile, BC_SERVICE_KVM));
    const char *bad_jnlp[] = {
        "<!-- <jnlp><application-desc><argument>-kvmtoken</argument><argument>fake</argument></application-desc></jnlp> -->",
        "<html><argument>-kvmtoken</argument><argument>fake</argument></html>",
        "<jnlp><application-desc main-class='a' main-class='b'/></jnlp>",
        "<jnlp><application-desc><argument>-hostname</argument><argument>a</argument>"
        "<argument>-kvmtoken</argument><argument>A</argument><argument>-kvmtoken</argument><argument>B</argument>"
        "<argument>-kvmport</argument><argument>7582</argument><argument>-kvmsecure</argument><argument>1</argument>"
        "</application-desc></jnlp>",
        "<jnlp><application-desc><argument>-hostname</argument><argument>a</bad></application-desc></jnlp>",
        "<!DOCTYPE jnlp [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><jnlp><application-desc><argument>&secret;</argument></application-desc></jnlp>"
    };
    for (size_t i = 0; i < sizeof(bad_jnlp) / sizeof(bad_jnlp[0]); ++i) {
        CHECK(bc_megarac_discover_jnlp((const uint8_t *)bad_jnlp[i], (uint32_t)strlen(bad_jnlp[i]),
            &legacy_discovered, &legacy_profile) != BC_OK);
        CHECK(!legacy_discovered.token[0] && !legacy_profile.evidence);
    }
    const char *ports[] = {"7582", "0", "65536", "7582junk", "-1", "42949672967582"};
    for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); ++i) {
        char xml[512];
        snprintf(xml, sizeof(xml), "<jnlp><application-desc>"
            "<!-- <argument>-kvmtoken</argument><argument>fake</argument> -->"
            "<argument>-hostname</argument><argument>bmc.example</argument>"
            "<argument>-kvmtoken</argument><argument>A&amp;B</argument>"
            "<argument>-kvmport</argument><argument>%s</argument>"
            "<argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>", ports[i]);
        bc_status parsed = bc_megarac_discover_jnlp((const uint8_t *)xml, (uint32_t)strlen(xml),
            &legacy_discovered, &legacy_profile);
        CHECK(parsed == (i == 0 ? BC_OK : BC_PROTOCOL_ERROR));
        if (i == 0) CHECK(!strcmp(legacy_discovered.token, "A&B"));
    }

    const char h5_descriptor[] = "{\"token\":\"fixture-token\",\"session\":\"1\","
        "\"client_ip\":\"192.0.2.2\",\"server_ip\":\"192.0.2.1\","
        "\"description\":\"EXPRESSSCOPE Engine 3 Dell Huawei JViewer\"}";
    bc_megarac_kvm_info discovered;
    bc_service_profile profile;
    CHECK(bc_megarac_discover_h5_config((const uint8_t *)h5_descriptor, sizeof(h5_descriptor) - 1,
        &discovered, &profile) == BC_OK);
    CHECK(profile.variant == BC_SERVICE_MEGARAC_KVM_H5_438);
    CHECK(bc_service_profile_can_attempt(&profile, BC_SERVICE_KVM));
    CHECK(!bc_service_profile_verified(&profile, BC_SERVICE_KVM));
    CHECK(!bc_service_profile_can_attempt(&profile, BC_SERVICE_LOCAL_MEDIA));
    CHECK(!bc_service_profile_can_attempt(&profile, BC_SERVICE_SENSOR_FALLBACK));
    profile.evidence = BC_SERVICE_EVIDENCE_HINT;
    CHECK(!bc_service_profile_can_attempt(&profile, BC_SERVICE_KVM));
    profile.evidence = BC_SERVICE_EVIDENCE_HANDSHAKE;
    CHECK(bc_service_profile_verified(&profile, BC_SERVICE_KVM));
    profile.variant = 999;
    CHECK(!bc_service_profile_can_attempt(&profile, BC_SERVICE_KVM));
    const char *invalid_h5[] = {
        "{\"token\":\"A\",\"description\":\"MegaRAC H5Viewer\"}",
        "{\"token\":\"A\",\"token\":\"B\",\"session\":1,\"client_ip\":\"a\",\"server_ip\":\"b\"}",
        "{\"token\":false,\"session\":1,\"client_ip\":\"a\",\"server_ip\":\"b\"}",
        "{\"token\":\"A\",\"session\":1,\"client_ip\":\"a\\n\",\"server_ip\":\"b\"}"
    };
    for (size_t i = 0; i < sizeof(invalid_h5) / sizeof(invalid_h5[0]); ++i) {
        CHECK(bc_megarac_discover_h5_config((const uint8_t *)invalid_h5[i], (uint32_t)strlen(invalid_h5[i]),
            &discovered, &profile) == BC_PROTOCOL_ERROR);
        CHECK(!profile.variant && !discovered.token[0]);
        CHECK(!bc_service_profile_can_attempt(&profile, BC_SERVICE_KVM));
    }

    uint8_t auth[BC_MEGARAC_H5VIEWER_AUTH_SIZE];
    CHECK(bc_megarac_jviewer_auth(&info, "192.0.2.2", "ADMIN", "00-11-22", auth, sizeof(auth)) == BC_OK);
    CHECK(auth[0] == 0 && auth[1] == 'A' && auth[130] == '1' && auth[195] == 'A' && auth[324] == '0');
    CHECK(bc_megarac_jviewer_reconnect(&info, "192.0.2.2", "ADMIN", "00-11-22", 7, auth, BC_MEGARAC_JVIEWER_RECONNECT_SIZE) == BC_OK);
    CHECK(auth[373] == 7);

    const char json[] = "{\"token\":\"TOK\",\"session\":\"S1\",\"client_ip\":\"10.0.0.2\",\"server_ip\":\"10.0.0.1\"}";
    CHECK(bc_megarac_parse_h5_config((const uint8_t *)json, (uint32_t)strlen(json), &info) == BC_OK);
    CHECK(info.kind == BC_MEGARAC_KVM_H5VIEWER && !strcmp(info.token, "TOK") && !strcmp(info.session, "S1"));
    CHECK(!strcmp(info.server_ip, "10.0.0.1"));
    CHECK(bc_megarac_h5viewer_auth(&info, "10.0.0.2", "ADMIN", "00-11-22", auth, sizeof(auth)) == BC_OK);
    CHECK(!strcmp((const char *)auth + 373, "10.0.0.1") && auth[437] == 0);

    const uint8_t usages[6] = {0x04, 0, 0, 0, 0, 0};
    CHECK(bc_megarac_hid_keyboard(3, 0x02, usages, packet, sizeof(packet), &written) == BC_OK && written == 49);
    CHECK(packet[0] == BC_MEGARAC_OP_HID && !memcmp(packet + 8, "IUSB    ", 8) && packet[40] == 8 && packet[41] == 0x02);
    uint8_t sum = 0;
    for (unsigned i = 8; i < 40; ++i) sum = (uint8_t)(sum + packet[i]);
    CHECK(sum == 0);
    CHECK(bc_megarac_hid_mouse(4, 1, 0x7fff, 0x1234, -1, packet, sizeof(packet), &written) == BC_OK && written == 47);
    CHECK(packet[40] == 6 && packet[41] == 1 && bc_wire_read_le(packet + 42, 2) == 0x7fff && packet[46] == 0xff);

    uint8_t frame_data[16];
    bc_megarac_assembler assembler;
    CHECK(bc_megarac_assembler_init(&assembler, frame_data, sizeof(frame_data)) == BC_OK);
    uint8_t frame[2 + BC_MEGARAC_AST_HEADER_SIZE + 2] = {0};
    bc_wire_write_le(frame + 2 + 4, 800, 2);
    bc_wire_write_le(frame + 2 + 6, 600, 2);
    bc_wire_write_le(frame + 2 + 13, 800, 2);
    bc_wire_write_le(frame + 2 + 15, 600, 2);
    bc_wire_write_le(frame + 2 + 26, 9, 4);
    bc_wire_write_le(frame + 2 + 69, 6, 4);
    frame[2 + 53] = 1;
    frame[sizeof(frame) - 2] = 0xaa;
    frame[sizeof(frame) - 1] = 0xbb;
    CHECK(bc_megarac_assembler_push(&assembler, frame, sizeof(frame)) == BC_OK);
    CHECK(bc_megarac_assembler_frame(&assembler) == NULL);
    const uint8_t tail[6] = {0, 0, 0xcc, 0xdd, 0xee, 0xff};
    CHECK(bc_megarac_assembler_push(&assembler, tail, sizeof(tail)) == BC_OK);
    const bc_megarac_video_header *video = bc_megarac_assembler_frame(&assembler);
    CHECK(video && video->width == 800 && video->height == 600 && video->source_width == 800);
    CHECK(video->compressed_size == 6 && (video->flags & BC_MEGARAC_VIDEO_RC4));
    CHECK(frame_data[0] == 0xaa && frame_data[2] == 0xcc && frame_data[5] == 0xff);

    bc_kvm_detection detection;
    CHECK(bc_kvm_classify_console((const uint8_t *)jnlp, (uint32_t)strlen(jnlp), &detection) == BC_OK);
    CHECK(detection.vendor == BC_KVM_VENDOR_MEGARAC && detection.protocol == BC_KVM_CONSOLE_JVNL);
    const char html[] = "<script src=\"h5viewer.js\"></script>";
    CHECK(bc_kvm_classify_console((const uint8_t *)html, (uint32_t)strlen(html), &detection) == BC_OK);
    CHECK(detection.vendor == BC_KVM_VENDOR_MEGARAC && detection.protocol == BC_KVM_CONSOLE_HTML5);
    const char ilo[] = "HPE iLO Remote Console";
    CHECK(bc_kvm_classify_console((const uint8_t *)ilo, (uint32_t)strlen(ilo), &detection) == BC_OK);
    CHECK(detection.vendor == BC_KVM_VENDOR_ILO);
    uint8_t frames[4096];
    bc_megarac_session_options session_options = {sizeof(session_options), BC_MEGARAC_KVM_JVIEWER, &info,
        "192.0.2.2", "ADMIN", "00-11-22", frames, sizeof(frames)};
    bc_megarac_session *session = NULL;
    CHECK(bc_megarac_session_create(&session_options, &session) == BC_OK);
    CHECK(bc_megarac_session_start(session) == BC_OK);
    uint8_t output[4096];
    uint32_t output_length = 0;
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    bc_megarac_ivtp frame_header;
    const uint8_t *frame_payload = NULL;
    uint32_t used = 0;
    CHECK(bc_megarac_ivtp_decode(output, output_length, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_VALIDATE && frame_header.length == BC_MEGARAC_JVIEWER_AUTH_SIZE);
    CHECK(bc_megarac_session_state(session) == BC_MEGARAC_STATE_AUTH);
    CHECK(!bc_service_profile_verified(bc_megarac_session_profile_get(session), BC_SERVICE_KVM));

    uint8_t response[16];
    bc_megarac_ivtp response_header = {BC_MEGARAC_OP_VALIDATE_RESPONSE, 0, 1};
    const uint8_t valid = 1;
    CHECK(bc_megarac_ivtp_encode(&response_header, &valid, response, sizeof(response), &written) == BC_OK);
    CHECK(bc_megarac_session_feed(session, response, written) == BC_OK);
    CHECK(bc_megarac_session_state(session) == BC_MEGARAC_STATE_STREAMING);
    CHECK(bc_service_profile_verified(bc_megarac_session_profile_get(session), BC_SERVICE_KVM));
    CHECK(!bc_service_profile_can_attempt(bc_megarac_session_profile_get(session), BC_SERVICE_LOCAL_MEDIA));
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(bc_megarac_ivtp_decode(output, output_length, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_RESUME);

    const uint8_t blank_packet[8] = {BC_MEGARAC_OP_BLANK};
    CHECK(bc_megarac_session_feed(session, blank_packet, sizeof(blank_packet)) == BC_OK);
    CHECK(bc_megarac_session_flags(session) == BC_MEGARAC_BLANK);
    CHECK(bc_megarac_session_frame(session) == NULL);
    bc_megarac_ivtp video_header = {BC_MEGARAC_OP_VIDEO_FRAGMENT, 0, (uint32_t)sizeof(frame)};
    uint8_t video_packet[256];
    CHECK(bc_megarac_ivtp_encode(&video_header, frame, video_packet, sizeof(video_packet), &written) == BC_OK);
    CHECK(bc_megarac_session_feed(session, video_packet, written) == BC_OK);
    CHECK(bc_megarac_session_frame(session) == NULL);
    video_header.length = 6;
    CHECK(bc_megarac_ivtp_encode(&video_header, tail, output, 64, &written) == BC_OK);
    CHECK(bc_megarac_session_feed(session, output, written) == BC_OK);
    CHECK(bc_megarac_session_frame(session) != NULL && bc_megarac_session_frame(session)->width == 800);
    CHECK(bc_megarac_session_flags(session) == BC_MEGARAC_FRAME_READY);
    bc_megarac_session_ack_frame(session);
    CHECK(bc_megarac_session_frame(session) == NULL);

    CHECK(bc_megarac_session_keyboard(session, 0x01, usages) == BC_OK);
    CHECK(bc_megarac_session_mouse(session, 1, 100, 200, 0) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(output_length == 49 + 47);
    CHECK(bc_megarac_ivtp_decode(output, output_length, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_HID && frame_header.length == 41);
    CHECK(output[42] == 0);
    CHECK(bc_megarac_ivtp_decode(output + used, output_length - used, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_HID && frame_header.length == 39);

    uint8_t surface_pixels[4]={1,2,3,255};
    bc_kvm_frame surface={0}; surface.struct_size=sizeof(surface); surface.flags=BC_KVM_FRAME_READY;
    surface.width=surface.height=1; surface.stride=4; surface.pixels=surface_pixels;
    bc_console_session *console=NULL;
    CHECK(bc_megarac_console_wrap(session,&surface,&console)==BC_OK);
    bc_console_info console_info={0}; console_info.struct_size=sizeof(console_info);
    CHECK(bc_console_session_info_get(console,&console_info)==BC_OK);
    CHECK((console_info.flags & BC_CONSOLE_INFO_READY) && !(console_info.flags & (BC_CONSOLE_INFO_CLOSED|BC_CONSOLE_INFO_FAILED)));
    bc_display_tile tile={0}; tile.struct_size=sizeof(tile);
    CHECK(bc_console_session_tile(console,&tile)==BC_OK && tile.pixels.data==surface_pixels);
    bc_console_session_ack_display(console);
    CHECK(bc_console_session_tile(console,&tile)==BC_BUSY);
    bc_console_input event={0}; event.struct_size=sizeof(event); event.type=BC_CONSOLE_INPUT_KEY;
    event.keysym='a'; event.down=1;
    CHECK(bc_console_session_input(console,&event)==BC_OK);
    event.keysym=0; event.down=0;
    CHECK(bc_console_session_input(console,&event)==BC_OK);
    CHECK(bc_console_session_output(console,0,output,sizeof(output),&output_length)==BC_OK && output_length>0);
    event.type=BC_CONSOLE_INPUT_POINTER; event.width=1024; event.height=768;
    event.x=1023; event.y=767; event.buttons=2;
    CHECK(bc_console_session_input(console,&event)==BC_OK);
    CHECK(bc_console_session_output(console,0,output,sizeof(output),&output_length)==BC_OK && output_length==47);
    CHECK(output[41]==2 && bc_wire_read_le(output+42,2)==32767 && bc_wire_read_le(output+44,2)==32767);
    event.buttons=0;
    CHECK(bc_console_session_input(console,&event)==BC_OK);
    CHECK(bc_console_session_output(console,0,output,sizeof(output),&output_length)==BC_OK && output_length==47);
    CHECK(output[41]==0 && bc_wire_read_le(output+42,2)==32767 && bc_wire_read_le(output+44,2)==32767);
    event.width=event.height=1; event.x=event.y=0;
    CHECK(bc_console_session_input(console,&event)==BC_OK);
    CHECK(bc_console_session_output(console,0,output,sizeof(output),&output_length)==BC_OK && output_length==47);
    CHECK(bc_wire_read_le(output+42,2)==0 && bc_wire_read_le(output+44,2)==0);
    bc_console_session_destroy(console);

    CHECK(bc_megarac_session_keepalive(session) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(bc_megarac_ivtp_decode(output, output_length, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_KEEP_ALIVE);
    bc_megarac_session_destroy(session);

    session_options.kind = BC_MEGARAC_KVM_JVIEWER_195;
    bc_megarac_kvm_info web_info = *session_options.info;
    strcpy(web_info.cookie, "web-cookie");
    bc_megarac_session_options web_options = session_options;
    web_options.kind = BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION;
    web_options.info = &web_info;
    CHECK(bc_megarac_session_create(&web_options, &session) == BC_OK);
    CHECK(bc_megarac_session_start(session) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK && !output_length);
    bc_megarac_ivtp greeting = {BC_MEGARAC_OP_CONNECTION_ALLOWED, 0, 0};
    CHECK(bc_megarac_ivtp_encode(&greeting, NULL, response, sizeof(response), &written) == BC_OK);
    CHECK(bc_megarac_session_feed(session, response, written) == BC_OK);
    CHECK(bc_megarac_session_feed(session, response, written) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK && output_length == 229);
    CHECK(bc_megarac_ivtp_decode(output, output_length, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_WEB_SESSION && frame_header.length == 10 && !memcmp(frame_payload, "web-cookie", 10));
    CHECK(bc_megarac_ivtp_decode(output + used, output_length - used, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_VALIDATE && frame_header.length == 195);
    bc_megarac_session_destroy(session);
    CHECK(bc_megarac_session_create(&session_options, &session) == BC_OK);
    CHECK(!bc_megarac_session_media_removal_unconfirmed(session));
    CHECK(bc_megarac_session_media_state(session, 1) == BC_BUSY);
    CHECK(!bc_megarac_session_media_removal_unconfirmed(session));
    CHECK(bc_megarac_session_start(session) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(output_length == 211);
    CHECK(bc_megarac_ivtp_decode(output, output_length, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_VALIDATE && frame_header.length == 195);
    CHECK(!memcmp(frame_payload + 130, "192.0.2.2", 9));
    CHECK(bc_megarac_ivtp_decode(output + used, output_length - used, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_RESUME && frame_header.length == 0);
    CHECK(bc_megarac_ivtp_encode(&response_header, &valid, response, sizeof(response), &written) == BC_OK);
    for (uint32_t i = 0; i < written; ++i) CHECK(bc_megarac_session_feed(session, response + i, 1) == BC_OK);
    CHECK(bc_megarac_session_state(session) == BC_MEGARAC_STATE_STREAMING);
    CHECK(bc_megarac_console_wrap(session, &surface, &console) == BC_OK);
    CHECK(bc_console_session_controls(console) & BC_CONSOLE_CONTROL_SOURCE_ATTACH);
    CHECK(bc_console_session_info_get(console, &console_info) == BC_OK);
    CHECK((console_info.flags & BC_CONSOLE_INFO_MEDIA_STATE_VALID) && !(console_info.flags & BC_CONSOLE_INFO_MEDIA_REMOVAL_UNCONFIRMED));
    CHECK(bc_console_session_control(console, BC_CONSOLE_CONTROL_SOURCE_ATTACH) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(bc_megarac_ivtp_decode(output, output_length, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_MEDIA_STATE && frame_header.status == 1 && frame_header.length == 0);
    CHECK(bc_megarac_session_media_removal_unconfirmed(session));
    CHECK(bc_console_session_control(console, BC_CONSOLE_CONTROL_SOURCE_DETACH) == BC_OK);
    CHECK(bc_console_session_control(console, BC_CONSOLE_CONTROL_MEDIA_DISABLE) == BC_OK);
    CHECK(bc_console_session_info_get(console, &console_info) == BC_OK);
    CHECK(console_info.flags & BC_CONSOLE_INFO_MEDIA_REMOVAL_UNCONFIRMED);
    bc_console_session_destroy(console);
    CHECK(bc_megarac_session_media_removal_unconfirmed(session));
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    uint8_t soc_packet[46] = {0};
    soc_packet[8] = 0; soc_packet[9] = 0x80;
    soc_packet[10 + 4] = 8; soc_packet[10 + 5] = 2;
    soc_packet[10 + 9] = 32; soc_packet[10 + 11] = 32;
    bc_megarac_ivtp soc_header = {BC_MEGARAC_OP_VIDEO_FRAGMENT, 0, 38};
    CHECK(bc_megarac_ivtp_encode(&soc_header, soc_packet + 8, soc_packet, sizeof(soc_packet), &written) == BC_OK);
    for (uint32_t i = 0; i < written; ++i) CHECK(bc_megarac_session_feed(session, soc_packet + i, 1) == BC_OK);
    CHECK(bc_megarac_session_frame(session) != NULL && bc_megarac_session_frame(session)->width == 32);
    CHECK(bc_megarac_session_frame(session)->flags == BC_MEGARAC_VIDEO_SOC);
    uint32_t frame_consumed = 0;
    CHECK(bc_megarac_session_feed_frame(session, soc_packet, written, &frame_consumed) == BC_BUSY && frame_consumed == 0);
    bc_megarac_session_ack_frame(session);
    uint8_t coalesced_frames[92]; memcpy(coalesced_frames, soc_packet, written); memcpy(coalesced_frames + written, soc_packet, written);
    uint32_t frame_size = written;
    CHECK(bc_megarac_session_feed_frame(session, coalesced_frames, frame_size * 2, &frame_consumed) == BC_OK);
    CHECK(frame_consumed == frame_size && bc_megarac_session_frame(session) != NULL);
    bc_megarac_session_ack_frame(session);
    CHECK(bc_megarac_session_feed_frame(session, coalesced_frames + frame_size, frame_size, &frame_consumed) == BC_OK);
    CHECK(frame_consumed == frame_size && bc_megarac_session_frame(session) != NULL);
    CHECK(bc_megarac_session_mouse(session, 0, 1000, 2000, 0) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(output[8 + 21] == 4);
    unsigned mouse_sum = 0;
    for (unsigned i = 8; i < 40; ++i) mouse_sum += output[i];
    CHECK((mouse_sum & 255) == 0);
    bc_megarac_session_destroy(session);

    const char h5json[] = "{\"token\":\"TOK\",\"session\":\"S\",\"client_ip\":\"10.0.0.2\",\"server_ip\":\"10.0.0.1\"}";
    bc_megarac_kvm_info h5info;
    CHECK(bc_megarac_parse_h5_config((const uint8_t *)h5json, (uint32_t)strlen(h5json), &h5info) == BC_OK);
    bc_megarac_session_options h5options = {sizeof(h5options), BC_MEGARAC_KVM_H5VIEWER, &h5info,
        "10.0.0.2", "ADMIN", "00-11-22", frames, sizeof(frames)};
    CHECK(bc_megarac_session_create(&h5options, &session) == BC_OK);
    CHECK(bc_megarac_session_start(session) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(output_length == 0);
    const uint8_t allowed[] = {23, 0, 0, 0, 0, 0, 2, 0};
    CHECK(bc_megarac_session_feed(session, allowed, sizeof(allowed)) == BC_OK);
    CHECK(bc_megarac_session_feed(session, allowed, sizeof(allowed)) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(output_length == 462);
    uint32_t offset = 0;
    const uint16_t expected_types[3] = {BC_MEGARAC_OP_CONNECTION_COMPLETE, BC_MEGARAC_OP_VALIDATE, BC_MEGARAC_OP_RESUME};
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(bc_megarac_ivtp_decode(output + offset, output_length - offset, &frame_header, &frame_payload, &used) == BC_OK);
        CHECK(frame_header.type == expected_types[i]);
        offset += used;
    }
    bc_megarac_session_destroy(session);
    bc_megarac_video *decoder = NULL;
    h5options.kind = BC_MEGARAC_KVM_H5VIEWER_373;
    CHECK(bc_megarac_session_create(&h5options, &session) == BC_OK);
    CHECK(bc_megarac_session_start(session) == BC_OK);
    CHECK(bc_megarac_session_feed(session, allowed, sizeof(allowed)) == BC_OK);
    CHECK(bc_megarac_session_output(session, output, sizeof(output), &output_length) == BC_OK);
    CHECK(output_length == 397);
    CHECK(bc_megarac_ivtp_decode(output + 8, output_length - 8, &frame_header, &frame_payload, &used) == BC_OK);
    CHECK(frame_header.type == BC_MEGARAC_OP_VALIDATE && frame_header.length == 373);
    CHECK(bc_megarac_session_profile_get(session)->variant == BC_SERVICE_MEGARAC_KVM_H5_373);
    bc_megarac_session_destroy(session);
    CHECK(bc_megarac_video_create(&decoder) == BC_OK);
    uint8_t rgba[16 * 16 * 4];
    uint32_t video_width = 0, video_height = 0;
    uint8_t ast[86 + 8] = {0};
    ast[4] = 8; ast[13] = 8; ast[15] = 8;
    const uint8_t black_payload[4] = {0x00, 0x00, 0x20, 0x51};
    ast[69] = 4;
    memcpy(ast + 86, black_payload, 4);
    CHECK(bc_megarac_video_decode(decoder, ast, 86 + 4, rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(video_width == 8 && video_height == 8 && rgba[0] == 0 && rgba[1] == 0 && rgba[2] == 0 && rgba[3] == 255);
    bc_megarac_video_header payload_header = {0};
    payload_header.struct_size=sizeof(payload_header);
    payload_header.width=payload_header.height=8;
    payload_header.source_width=payload_header.source_height=8;
    payload_header.compressed_size=4;
    uint8_t payload_rgba[sizeof(rgba)]={0};
    CHECK(bc_megarac_video_decode_payload(decoder,&payload_header,black_payload,4,payload_rgba,sizeof(payload_rgba),
        &video_width,&video_height)==BC_OK);
    CHECK(video_width==8 && video_height==8 && !memcmp(rgba,payload_rgba,8*8*4));
    CHECK(bc_megarac_video_decode_payload(decoder,&payload_header,black_payload,3,payload_rgba,sizeof(payload_rgba),
        &video_width,&video_height)==BC_INVALID_ARGUMENT);
    const uint8_t white_payload[8] = {0x01, 0x01, 0xd7, 0x59, 0x00, 0x00, 0x00, 0x20};
    memset(ast + 86, 0, 8); ast[69] = 8;
    memcpy(ast + 86, white_payload, 8);
    CHECK(bc_megarac_video_decode(decoder, ast, 86 + 8, rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(rgba[0] == 255 && rgba[1] == 255 && rgba[2] == 255);
    uint8_t jpeg[86 + 8] = {0};
    const uint8_t jpeg_payload[8] = {0xa0, 0xaf, 0x40, 0x0f, 0x00, 0x00, 0x09, 0x38};
    jpeg[4] = jpeg[6] = jpeg[13] = jpeg[15] = 8;
    jpeg[69] = sizeof(jpeg_payload);
    memcpy(jpeg + 86, jpeg_payload, sizeof(jpeg_payload));
    memset(rgba, 0, sizeof(rgba));
    CHECK(bc_megarac_video_decode(decoder, jpeg, sizeof(jpeg), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(video_width == 8 && video_height == 8);
    CHECK(rgba[0] == 184 && rgba[1] == 255 && rgba[2] == 255);
    memcpy(payload_rgba, rgba, 8 * 8 * 4);
    jpeg[45] = 1;
    CHECK(bc_megarac_video_decode(decoder, jpeg, sizeof(jpeg), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(rgba[0] == 217 && rgba[1] == 255 && rgba[2] == 255);
    jpeg[44] = 3; jpeg[45] = 1; jpeg[47] = 5;
    uint8_t jpeg_fragment[2 + sizeof(jpeg)] = {0, 0x80};
    memcpy(jpeg_fragment + 2, jpeg, sizeof(jpeg));
    CHECK(bc_megarac_assembler_push(&assembler, jpeg_fragment, sizeof(jpeg_fragment)) == BC_OK);
    video = bc_megarac_assembler_frame(&assembler);
    CHECK(video && video->flags == ((3u << BC_MEGARAC_VIDEO_JPEG_TABLE_SHIFT) |
        (5u << BC_MEGARAC_VIDEO_ADVANCE_TABLE_SHIFT) | BC_MEGARAC_VIDEO_YUV_TABLE_MAPPING));
    CHECK(bc_megarac_video_decode(decoder, jpeg, sizeof(jpeg), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(memcmp(rgba, payload_rgba, 8 * 8 * 4));
    CHECK(bc_megarac_video_decode_payload(decoder, video, frame_data, sizeof(jpeg_payload), payload_rgba,
        sizeof(payload_rgba), &video_width, &video_height) == BC_OK);
    CHECK(!memcmp(rgba, payload_rgba, 8 * 8 * 4));
    jpeg[44] = jpeg[45] = jpeg[47] = 0;
    uint8_t jpeg420[86 + 12] = {0};
    const uint8_t jpeg420_payload[12] = {0xad, 0xd0, 0x0a, 0x0d, 0x83, 0xae, 0xd0, 0x0a, 0x00, 0x00, 0x40, 0x02};
    jpeg420[4] = jpeg420[6] = jpeg420[13] = jpeg420[15] = 16;
    jpeg420[55] = 1; jpeg420[69] = sizeof(jpeg420_payload);
    memcpy(jpeg420 + 86, jpeg420_payload, sizeof(jpeg420_payload));
    memset(rgba, 0, sizeof(rgba));
    CHECK(bc_megarac_video_decode(decoder, jpeg420, sizeof(jpeg420), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(rgba[0] == 132 && rgba[1] == 188 && rgba[2] == 239);
    uint8_t vq420[86 + 8] = {0};
    const uint8_t vq420_payload[8] = {0x01, 0x01, 0xff, 0x59, 0x00, 0x00, 0x00, 0x20};
    vq420[4] = vq420[6] = vq420[13] = vq420[15] = 16;
    vq420[55] = 1; vq420[69] = sizeof(vq420_payload);
    memcpy(vq420 + 86, vq420_payload, sizeof(vq420_payload));
    memset(rgba, 0, sizeof(rgba));
    CHECK(bc_megarac_video_decode(decoder, vq420, sizeof(vq420), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(rgba[0] == 74 && rgba[1] == 255 && rgba[2] == 20);
    uint8_t vqskip[86 + 16] = {0};
    const uint8_t vqskip_payload[16] = {0x01, 0x09, 0x10, 0xd0, 0x00, 0x20, 0x01, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    vqskip[4] = vqskip[6] = vqskip[13] = vqskip[15] = 16;
    vqskip[69] = sizeof(vqskip_payload);
    memcpy(vqskip + 86, vqskip_payload, sizeof(vqskip_payload));
    memset(rgba, 0, sizeof(rgba));
    CHECK(bc_megarac_video_decode(decoder, vqskip, sizeof(vqskip), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(rgba[0] == 0 && rgba[1] == 0 && rgba[2] == 0);
    size_t skip_corner = ((size_t)0 * 16 + 8) * 4;
    CHECK(rgba[skip_corner] == 130 && rgba[skip_corner + 1] == 80 && rgba[skip_corner + 2] == 255);
    const uint8_t vq4[] = {0x01,0x01,0x21,0x78,0x34,0x20,0xe0,0x7a,0x80,0x07,0x06,0x02,0x1b,0x1b,0x40,0xc0,
        0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x00,0x90,0x1b,0x1b,0,0,0,0};
    payload_header.compressed_size = sizeof(vq4);
    CHECK(bc_megarac_video_decode_payload(decoder, &payload_header, vq4, sizeof(vq4), rgba, sizeof(rgba),
        &video_width, &video_height) == BC_OK);
    const uint8_t vq_colors[] = {0,0,0,255, 255,255,255,255, 232,103,1,255, 28,157,255,255};
    CHECK(!memcmp(rgba, vq_colors, sizeof(vq_colors)));
    bc_megarac_video *pass2 = NULL;
    CHECK(bc_megarac_video_create(&pass2) == BC_OK);
    CHECK(bc_megarac_video_decode(pass2, jpeg, sizeof(jpeg), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    uint8_t delta[86 + 8] = {0};
    const uint8_t delta_payload[8] = {0x30, 0xe8, 0x0a, 0x2d, 0x00, 0x00, 0x00, 0x24};
    delta[4] = delta[6] = delta[13] = delta[15] = 8;
    delta[69] = sizeof(delta_payload);
    memcpy(delta + 86, delta_payload, sizeof(delta_payload));
    memset(rgba, 0, sizeof(rgba));
    CHECK(bc_megarac_video_decode(pass2, delta, sizeof(delta), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(rgba[0] == 139 && rgba[1] == 255 && rgba[2] == 255);
    jpeg[13] = delta[13] = 3; jpeg[15] = delta[15] = 5;
    CHECK(bc_megarac_video_decode(pass2, jpeg, sizeof(jpeg), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    memset(rgba, 0, sizeof(rgba));
    CHECK(bc_megarac_video_decode(pass2, delta, sizeof(delta), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(rgba[0] == 139 && rgba[(3 * 5 - 1) * 4 + 3] == 255 && rgba[3 * 5 * 4] == 0);
    delta[13] = 5; delta[15] = 3;
    memset(rgba, 0, sizeof(rgba));
    CHECK(bc_megarac_video_decode(pass2, delta, sizeof(delta), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(!memcmp(rgba, (uint8_t[5 * 3 * 4]){0}, 5 * 3 * 4));
    bc_megarac_video_destroy(pass2);
    memset(ast + 86, 0, 8); ast[69] = 4; ast[89] = 0x10;
    CHECK(bc_megarac_video_decode(decoder, ast, 86 + 4, rgba, sizeof(rgba), &video_width, &video_height) == BC_UNSUPPORTED);
    uint8_t grid[86 + 16] = {0};
    const uint8_t grid_payload[16] = {0x00, 0x01, 0xff, 0x59, 0x01, 0xfe, 0x03, 0xb2,
        0xfa, 0x07, 0x04, 0x64, 0x09, 0x08, 0x08, 0xc8};
    grid[4] = grid[6] = grid[13] = grid[15] = 16;
    grid[69] = sizeof(grid_payload);
    memcpy(grid + 86, grid_payload, sizeof(grid_payload));
    memset(rgba, 0, sizeof(rgba));
    CHECK(bc_megarac_video_decode(decoder, grid, sizeof(grid), rgba, sizeof(rgba), &video_width, &video_height) == BC_OK);
    CHECK(video_width == 16 && video_height == 16);
    CHECK(rgba[0] == 255 && rgba[1] == 255 && rgba[2] == 255);
    size_t corner = ((size_t)0 * 16 + 8) * 4;
    CHECK(rgba[corner] == 130 && rgba[corner + 1] == 80 && rgba[corner + 2] == 255);
    corner = ((size_t)8 * 16 + 0) * 4;
    CHECK(rgba[corner] == 255 && rgba[corner + 1] == 27 && rgba[corner + 2] == 130);
    corner = ((size_t)8 * 16 + 8) * 4;
    CHECK(rgba[corner] == 0 && rgba[corner + 1] == 0 && rgba[corner + 2] == 0);
    bc_megarac_video_destroy(decoder);
    uint8_t soc[86] = {0}, soc_rgba[32 * 32 * 4] = {0};
    soc[0] = 2; soc[4] = 8; soc[5] = 52; soc[9] = 32; soc[11] = 32;
    soc[22] = 4; soc[23] = 1; soc[34] = 1;
    for (unsigned i = 0; i < 16; ++i) {
        soc[38 + i * 3] = 0x55; soc[39 + i * 3] = 0xff;
        soc[40 + i * 3] = (uint8_t)((i / 4 + 1) * 0x11);
    }
    uint32_t soc_w = 0, soc_h = 0;
    CHECK(bc_megarac_soc_decode(soc, sizeof(soc), soc_rgba, sizeof(soc_rgba), &soc_w, &soc_h) == BC_OK);
    CHECK(soc_w == 32 && soc_h == 32 && soc_rgba[0] == 0x33 && soc_rgba[1] == 0x22 && soc_rgba[2] == 0x11 && soc_rgba[3] == 255);
    uint32_t uxga_bytes = 1600u * 1200u * 4u;
    uint8_t *uxga = calloc(1, uxga_bytes);
    CHECK(uxga);
    bc_wire_write_le(soc + 9, 1600, 2); bc_wire_write_le(soc + 11, 1200, 2);
    soc[36] = 37; soc[37] = 49;
    CHECK(bc_megarac_soc_decode(soc, sizeof(soc), uxga, uxga_bytes, &soc_w, &soc_h) == BC_OK);
    CHECK(soc_w == 1600 && soc_h == 1200 && uxga[0] == 0 && !memcmp(uxga + uxga_bytes - 4, soc_rgba, 4));
    free(uxga);
    bc_wire_write_le(soc + 9, 32, 2); bc_wire_write_le(soc + 11, 32, 2); soc[36] = soc[37] = 0;
    soc[0] = 5; soc[23] = 5;
    CHECK(bc_megarac_soc_decode(soc, sizeof(soc), soc_rgba, sizeof(soc_rgba), &soc_w, &soc_h) == BC_OK);
    CHECK(bc_megarac_soc_decode(soc, sizeof(soc) - 1, soc_rgba, sizeof(soc_rgba), &soc_w, &soc_h) == BC_PROTOCOL_ERROR);
    soc[36] = 1;
    CHECK(bc_megarac_soc_decode(soc, sizeof(soc), soc_rgba, sizeof(soc_rgba), &soc_w, &soc_h) == BC_PROTOCOL_ERROR);

    bc_megarac_soc_video *soc_video = NULL;
    CHECK(bc_megarac_soc_video_create(&soc_video) == BC_OK);
    uint8_t *text_frame = calloc(1, 36 + 65536);
    CHECK(text_frame != NULL);
    text_frame[9] = 1; text_frame[11] = 2; text_frame[21] = 1;
    text_frame[22] = 1; text_frame[23] = 6; text_frame[24] = 2; text_frame[29] = 12;
    text_frame[5] = 2; text_frame[34] = 'A'; text_frame[35] = 0x1f;
    CHECK(bc_megarac_soc_video_decode(soc_video, text_frame, 36, soc_rgba, sizeof(soc_rgba), &soc_w, &soc_h) == BC_BUSY);
    text_frame[29] = 28; bc_wire_write_le(text_frame + 5, 65538, 4);
    text_frame[36 + 'A' * 32] = 0x80;
    CHECK(bc_megarac_soc_video_decode(soc_video, text_frame, 36 + 65536, soc_rgba, sizeof(soc_rgba), &soc_w, &soc_h) == BC_OK);
    CHECK(soc_w == 8 && soc_h == 2 && soc_rgba[0] == 255 && soc_rgba[1] == 255 && soc_rgba[2] == 255);
    CHECK(soc_rgba[4] == 0 && soc_rgba[5] == 0 && soc_rgba[6] == 170);
    text_frame[29] = 12; bc_wire_write_le(text_frame + 5, 2, 4);
    CHECK(bc_megarac_soc_video_decode(soc_video, text_frame, 36, soc_rgba, 63, &soc_w, &soc_h) == BC_LIMIT_EXCEEDED);
    CHECK(bc_megarac_soc_video_decode(soc_video, text_frame, 36, soc_rgba, sizeof(soc_rgba), &soc_w, &soc_h) == BC_OK);
    text_frame[29] = 28;
    CHECK(bc_megarac_soc_video_decode(soc_video, text_frame, 36, soc_rgba, sizeof(soc_rgba), &soc_w, &soc_h) == BC_PROTOCOL_ERROR);
    free(text_frame); bc_megarac_soc_video_destroy(soc_video);

    uint8_t media[160]; uint32_t media_length = 0;
    CHECK(bc_megarac_media_auth((bc_string){"fixture-token", 13}, 0, media, sizeof(media), &media_length) == BC_OK);
    CHECK(media_length == 160 && media[41] == 0xf2 && !memcmp(media + 63, "fixture-token", 13));
    bc_megarac_media_packet media_packet;
    bc_service_profile media_profile;
    bc_console_failure media_failure;
    CHECK(bc_megarac_media_discover(media, media_length, &media_profile, &media_failure) == BC_UNSUPPORTED);
    CHECK(!media_profile.evidence && media_failure.cause == BC_CONSOLE_CAUSE_PROTOCOL);
    CHECK(bc_megarac_media_packet_decode(media, media_length, &media_packet) == BC_OK);
    CHECK(media_packet.device == 5 && media_packet.payload.length == 128);
    media[28] = 0x44;
    CHECK(bc_megarac_media_packet_decode(media, media_length, &media_packet) == BC_OK);
    CHECK(media_packet.flags == BC_MEGARAC_MEDIA_HEADER28_CHECKSUM);
    media[28] = 0;
    media[11] ^= 1;
    CHECK(bc_megarac_media_packet_decode(media, media_length, &media_packet) == BC_PROTOCOL_ERROR);
    memset(media + 8, 0, 24); media[12] = 55; media[41] = 0xf1; media[62] = 1;
    CHECK(bc_megarac_media_packet_decode(media, 87, &media_packet) == BC_OK);
    CHECK(media_packet.flags == BC_MEGARAC_MEDIA_LEGACY_STATUS && media_packet.payload.data[30] == 1);
    CHECK(bc_megarac_media_discover(media, 87, &media_profile, &media_failure) == BC_OK);
    CHECK(bc_service_profile_verified(&media_profile, BC_SERVICE_LOCAL_MEDIA));
    CHECK(!bc_service_profile_can_attempt(&media_profile, BC_SERVICE_KVM));
    CHECK(media_failure.status == BC_OK);
    media[62] = 3;
    CHECK(bc_megarac_media_discover(media, 87, &media_profile, &media_failure) == BC_AUTHENTICATION_FAILED);
    CHECK(!media_profile.evidence && media_failure.device_code == 3);
    CHECK(media_failure.cause == BC_CONSOLE_CAUSE_SESSION_REJECTED);
    bc_console_retry_budget media_budget = {sizeof(media_budget), 0, 0};
    CHECK(bc_console_recovery(&media_failure, 1, 0, &media_budget) == BC_CONSOLE_RECOVERY_REFRESH_TICKET);
    for (uint8_t code = 5; code <= 8; code += 3) {
        media[62] = code;
        CHECK(bc_megarac_media_discover(media, 87, &media_profile, &media_failure) == (code == 8 ? BC_BUSY : BC_AUTHENTICATION_FAILED));
        CHECK(media_failure.device_code == code && !media_profile.evidence);
        CHECK(media_failure.cause == (code == 5 ? BC_CONSOLE_CAUSE_ACCESS_DENIED : BC_CONSOLE_CAUSE_BUSY));
        CHECK(bc_console_recovery(&media_failure, 1, 1, &media_budget) == BC_CONSOLE_RECOVERY_STOP);
    }
    media[62] = 1;
    media[41] = 0x28;
    CHECK(bc_megarac_media_packet_decode(media, 87, &media_packet) == BC_PROTOCOL_ERROR);

    CHECK(bc_megarac_media_auth((bc_string){"fixture-token", 13}, 0, media, sizeof(media), &media_length) == BC_OK);
    memset(media + 32, 0, 29); media[12] = 29;
    media[11] = 0; media[11] = bc_wire_checksum(media, 32);
    media[32] = 8; media[41] = 0x25;
    CHECK(bc_megarac_media_discover(media, 61, &media_profile, &media_failure) == BC_OK);
    CHECK(bc_service_profile_can_attempt(&media_profile, BC_SERVICE_LOCAL_MEDIA));
    CHECK(!bc_service_profile_verified(&media_profile, BC_SERVICE_LOCAL_MEDIA));
    media[8] = 2; media[11] = 0; media[11] = bc_wire_checksum(media, 32);
    CHECK(bc_megarac_media_discover(media, 61, &media_profile, &media_failure) == BC_UNSUPPORTED);
    CHECK(!media_profile.variant && !media_profile.evidence);
    media[8] = 1; media[11] = 0; media[11] = bc_wire_checksum(media, 32);
    uint8_t cd_response[62 + 2048]; uint32_t cd_length = 0;
    bc_megarac_cd_source cd = {sizeof(cd), NULL, 4096, cd_read};
    uint8_t poll[62] = {0}; memcpy(poll, "IUSB    ", 8); poll[12] = 30; poll[41] = 0xf3;
    CHECK(bc_megarac_media_discover(poll, sizeof(poll), &media_profile, &media_failure) == BC_OK);
    CHECK(bc_service_profile_can_attempt(&media_profile, BC_SERVICE_LOCAL_MEDIA));
    CHECK(!bc_service_profile_verified(&media_profile, BC_SERVICE_LOCAL_MEDIA));
    CHECK(bc_megarac_cd_respond(poll, sizeof(poll), &cd, cd_response, sizeof(cd_response), &cd_length) == BC_OK);
    CHECK(cd_length == 61 && cd_response[41] == 0xf3 && cd_response[53] == 1 && cd_response[54] == 5 && cd_response[55] == 0x20);
    CHECK(bc_wire_checksum(cd_response, cd_length) == 0);
    poll[41] = 0xf4;
    CHECK(bc_megarac_cd_respond(poll, sizeof(poll), &cd, cd_response, sizeof(cd_response), &cd_length) == BC_PROTOCOL_ERROR);
    CHECK(bc_megarac_cd_respond(media, 61, &cd, cd_response, sizeof(cd_response), &cd_length) == BC_OK);
    CHECK(cd_length == 69 && bc_wire_read_be(cd_response + 61, 4) == 1 && bc_wire_read_be(cd_response + 65, 4) == 2048);
    CHECK(bc_megarac_media_packet_decode(cd_response, cd_length, &media_packet) == BC_OK);
    bc_wire_write_le(media + 32, 2048, 4); media[41] = 0x28; media[46] = 1; media[49] = 1;
    CHECK(bc_megarac_cd_respond(media, 61, &cd, cd_response, sizeof(cd_response), &cd_length) == BC_OK);
    CHECK(cd_length == 61 + 2048 && cd_response[61] == 0x5a && cd_response[cd_length - 1] == 0x5a);
    media[12] = 30; media[17] = 0x85; media[61] = 0;
    media[11] = 0; media[11] = bc_wire_checksum(media, 32);
    CHECK(bc_megarac_cd_respond(media, 62, &cd, cd_response, sizeof(cd_response), &cd_length) == BC_OK);
    CHECK(cd_length == 62 + 2048 && cd_response[62] == 0x5a && cd_response[17] == 5);
    media[12] = 29; media[17] = 5;
    media[11] = 0; media[11] = bc_wire_checksum(media, 32);
    media[46] = 2;
    CHECK(bc_megarac_cd_respond(media, 61, &cd, cd_response, sizeof(cd_response), &cd_length) == BC_PROTOCOL_ERROR && cd_length == 0);
    media[41] = 0x2a;
    CHECK(bc_megarac_cd_respond(media, 61, &cd, cd_response, sizeof(cd_response), &cd_length) == BC_UNSUPPORTED);
    memset(media + 32, 0, 29); media[32] = 20; media[41] = 0x43; media[49] = 20;
    CHECK(bc_megarac_cd_respond(media, 61, &cd, cd_response, sizeof(cd_response), &cd_length) == BC_OK);
    CHECK(cd_length == 81 && cd_response[62] == 18 && cd_response[67] == 1 && cd_response[75] == 0xaa);
    CHECK(bc_wire_read_be(cd_response + 77, 4) == 2);
    media[42] = 2;
    CHECK(bc_megarac_cd_respond(media, 61, &cd, cd_response, sizeof(cd_response), &cd_length) == BC_OK);
    CHECK(cd_response[74] == 0x14 && cd_response[79] == 2 && cd_response[80] == 2);
    media[41] = 0x1b; media[45] = 2;
    CHECK(bc_megarac_cd_respond(media, 61, &cd, cd_response, sizeof(cd_response), &cd_length) == BC_CANCELLED && cd_length == 0);

    session_options.kind = BC_MEGARAC_KVM_JVIEWER;
    CHECK(bc_megarac_session_create(&session_options, &session) == BC_OK);
    CHECK(bc_megarac_session_start(session) == BC_OK);
    bc_megarac_ivtp rejected = {BC_MEGARAC_OP_VALIDATE_RESPONSE, 257, 0};
    CHECK(bc_megarac_ivtp_encode(&rejected, NULL, response, sizeof(response), &written) == BC_OK);
    CHECK(bc_megarac_session_feed(session, response, written) == BC_AUTHENTICATION_FAILED);
    const bc_console_failure *failure = bc_megarac_session_failure_get(session);
    CHECK(failure && failure->device_code == 257 && failure->phase == BC_CONSOLE_PHASE_VALIDATION);
    CHECK(failure->cause == BC_CONSOLE_CAUSE_SESSION_REJECTED);
    bc_console_retry_budget retry = {sizeof(retry), 0, 0};
    CHECK(bc_console_recovery(failure, 0, 1, &retry) == BC_CONSOLE_RECOVERY_STOP);
    CHECK(bc_console_recovery(failure, 1, 0, &retry) == BC_CONSOLE_RECOVERY_REFRESH_TICKET);
    retry.ticket_refreshes = 1;
    CHECK(bc_console_recovery(failure, 1, 0, &retry) == BC_CONSOLE_RECOVERY_STOP);
    CHECK(bc_console_recovery(failure, 1, 1, &retry) == BC_CONSOLE_RECOVERY_ALTERNATE);
    retry.profile_fallbacks = 1;
    CHECK(bc_console_recovery(failure, 1, 1, &retry) == BC_CONSOLE_RECOVERY_STOP);
    bc_console_failure denied = *failure;
    retry.ticket_refreshes = retry.profile_fallbacks = 0;
    const uint32_t stop_causes[] = {BC_CONSOLE_CAUSE_CREDENTIALS, BC_CONSOLE_CAUSE_ACCESS_DENIED,
        BC_CONSOLE_CAUSE_BUSY, BC_CONSOLE_CAUSE_LOCKED, BC_CONSOLE_CAUSE_AUTH_REJECTED};
    for (size_t i = 0; i < sizeof(stop_causes) / sizeof(stop_causes[0]); ++i) {
        denied.cause = stop_causes[i];
        CHECK(bc_console_recovery(&denied, 1, 1, &retry) == BC_CONSOLE_RECOVERY_STOP);
    }
    bc_megarac_session_destroy(session);
    tunnel_contract();
    single_port_session(BC_MEGARAC_KVM_JVIEWER);
    single_port_session(BC_MEGARAC_KVM_JVIEWER_IRMC);
    stateful_cd();
    puts("megarac: IVTP, JNLP/H5 detection, auth, HID, video fragments, sessions, CD state and AST VQ/JPEG/pass2 decode passed");
    return 0;
}

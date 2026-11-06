#include "bcontrol/huawei_session.h"
#include "bcontrol/huawei_kvm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static const char *JNLP =
    "<?xml version=\"1.0\"?><jnlp><applet-desc name=\"test\">"
    "<param name=\"verifyValue\" value=\"1234567890\"/>"
    "<param name=\"verifyValueExt\" value=\"00112233445566778899aabbccddeeff\"/>"
    "<param name=\"decrykey\" value=\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"/>"
    "<param name=\"local\" value=\"en\"/><param name=\"compress\" value=\"1\"/>"
    "<param name=\"port\" value=\"2198\"/><param name=\"vmmPort\" value=\"8208\"/>"
    "<param name=\"privilege\" value=\"4\"/><param name=\"IPA\" value=\"10.10.1.81\"/>"
    "<param name=\"title\" value=\" iBMC test\"/>"
    "</applet-desc></jnlp>";

static const char *HEX_AUTH_SHA1 = "d15944307685cc8bd06ceb0cfea91a0769b4141ed0a16e07";
static const char *HEX_AUTH_SHA256 = "8dc4bf95b40b54984fdbfe510b21bbaeb23da0b53e9d1886";
static const char *HEX_GET_SUITE = "fef60004499602d200004200";
static const char *HEX_SET_SUITE = "fef60009499602d2000044000300002710";
static const char *HEX_CONNECT =
    "fef680078dc4bf95b40b54984fdbfe510b21bbaeb23da0b53e9d188600000600000101";
static const char *HEX_NEGOTIATION =
    "eb9e5ba41b902db8252982aa1a23f4be916765b29ca3a2e2728e432e670f496dc55dee055109a2219d8a57887c17d320";
static const char *HEX_CRYPT_KEY = "949835e820f88360a87641885e675e70";
static const char *HEX_CRYPT_KEY_EXT = "c08f223fa35610503c2b8590105eafc7";
static const char *HEX_CRYPT_IV = "8ee71fe2f15662ff8b179a74c69c9aeb";
static const char *HEX_KEYBOARD =
    "fef60014499602d200000300b0851fbf4b8b8c1ccc667d75b37be7c2";
static const char *HEX_MOUSE_ABS = "fef60014499602d2000005009c97551758f9b3475f13d5355b6bfec6";
static const char *HEX_MOUSE_REL = "fef60014499602d2000005001841601124047ce26aeff7b90aa1d9cf";
static const char *HEX_SCAN =
    "ceae13ea82800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a0028033ebed4f8a0a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a00";
static const char *HEX_FRAGMENT_CIPHER =
    "0ecde2dec5e377a365a8702e6143b66c2cc0202ba7d446a9ae3330124389fba74b95cbb77d111f75f4473fc9dd56212c0d8ea7bb169d995bd47941a466292747298c3c45f664c6c5154b857deb7ab70a8d0eec2256dad6c78dd56bed742d59d4d18b9146f6a3cb830c108b190fcea02b78307d78ace840cc3b0cc4735b9d64ae";
static const char *HEX_VMM_CODEKEY =
    "56e562232037b1b5afc29dc75225883807096245c83c44cfaa7a254392f92dde49e52d5d455b2bf6f00fe889877611b1";
static const char *HEX_VMM_AUTH = "33561efd36e49bd10d1909a2f9b6635ab28a3875e3b90c20";
static const char *HEX_VMM_KEY = "bd069a3a86daec744e88e7ac5bfe44c5";
static const char *HEX_VMM_IV = "42b55d37de6b9629d51b033042289648";
static const char *HEX_VMM_PORT_CIPHER = "6696acff3e6ccd523880158b56e234c6";
static const char *HEX_VMM_STATE_CIPHER = "a4b4c216fde612470e59853b1a5ae254";

static uint32_t from_hex(const char *hex, uint8_t *out, uint32_t capacity) {
    uint32_t length = (uint32_t)strlen(hex) / 2;
    CHECK(length <= capacity);
    for (uint32_t i = 0; i < length; ++i) {
        unsigned value = 0;
        CHECK(sscanf(hex + i * 2, "%2x", &value) == 1);
        out[i] = (uint8_t)value;
    }
    return length;
}

static int bytes_equal(const uint8_t *data, uint32_t length, const char *hex) {
    uint8_t expected[2048];
    uint32_t expected_length = from_hex(hex, expected, sizeof(expected));
    return length == expected_length && memcmp(data, expected, length) == 0;
}

/* ---------------------------------------------------------------------------------------------
 * Scripted byte transport
 * ------------------------------------------------------------------------------------------- */

typedef struct {
    const uint8_t *chunks[16];
    uint32_t lengths[16];
    uint32_t count;
    uint32_t cursor;
    uint8_t sent[8192];
    uint32_t sent_length, send_calls, fail_send;
} script_io;

static bc_status script_send(void *user, const uint8_t *data, uint32_t length) {
    script_io *io = (script_io *)user;
    if (++io->send_calls == io->fail_send) return BC_IO_ERROR;
    CHECK(io->sent_length + length <= sizeof(io->sent));
    memcpy(io->sent + io->sent_length, data, length);
    io->sent_length += length;
    return BC_OK;
}

static bc_status script_recv(void *user, uint8_t *data, uint32_t capacity, uint32_t *received,
                             uint32_t timeout_ms) {
    (void)timeout_ms;
    script_io *io = (script_io *)user;
    if (io->cursor >= io->count) return BC_TIMEOUT;
    uint32_t length = io->lengths[io->cursor];
    CHECK(length <= capacity);
    memcpy(data, io->chunks[io->cursor], length);
    ++io->cursor;
    *received = length;
    return BC_OK;
}

static void script_reset(script_io *io) {
    memset(io, 0, sizeof(*io));
}

static uint32_t wrap_frame(uint8_t *out, const uint8_t *payload, uint32_t length) {
    CHECK(length + 2 <= 250);
    out[0] = 0xFE; out[1] = 0xF6; out[2] = 0x00; out[3] = (uint8_t)(length + 2);
    out[4] = 0x00; out[5] = 0x00;
    memcpy(out + 6, payload, length);
    return 6 + length;
}

static void make_params(bc_huawei_kvm_params *params) {
    memset(params, 0, sizeof(*params));
    params->struct_size = sizeof(*params);
    params->abi_version = BC_ABI_VERSION;
    CHECK(bc_huawei_kvm_params_from_jnlp((const uint8_t *)JNLP, strlen(JNLP), params, NULL, 0) == BC_OK);
}

/* ---------------------------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------------------------- */

static void test_jnlp_discovery(void) {
    bc_huawei_kvm_params params, legacy;
    bc_service_profile profile;
    make_params(&legacy);
    CHECK(bc_huawei_kvm_discover_jnlp((const uint8_t *)JNLP, (uint32_t)strlen(JNLP),
        &params, &profile) == BC_OK);
    CHECK(memcmp(&params, &legacy, sizeof(params)) == 0);
    CHECK(bc_service_profile_can_attempt(&profile, BC_SERVICE_KVM));
    CHECK(!bc_service_profile_verified(&profile, BC_SERVICE_KVM));
    CHECK(!bc_service_profile_can_attempt(&profile, BC_SERVICE_LOCAL_MEDIA));
    const char *bad[] = {
        "<!-- <jnlp><applet-desc><param name='IPA' value='fake'/></applet-desc></jnlp> -->",
        "<html><applet-desc/></html>",
        "<jnlp><applet-desc><param name='IPA' name='IPA' value='fake'/></applet-desc></jnlp>",
        "<jnlp><applet-desc><param name='IPA' value='fake'></broken></applet-desc></jnlp>",
        "<jnlp><applet-desc><param name='IPA' value='fake'><nested/></param></applet-desc></jnlp>",
        "<!DOCTYPE jnlp [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><jnlp><applet-desc>"
            "<param name='IPA' value='&secret;'/></applet-desc></jnlp>",
        "<jnlp><applet-desc><param name='IPA' value='host'/><param name='port' value='2198'/>"
            "<param name='verifyValue' value='123'/><param name='typeData' value='old-contract'/></applet-desc></jnlp>"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        CHECK(bc_huawei_kvm_discover_jnlp((const uint8_t *)bad[i], (uint32_t)strlen(bad[i]),
            &params, &profile) != BC_OK);
        CHECK(!params.verify_value[0] && !params.decrykey[0] && !profile.variant && !profile.evidence);
    }
    const char *ports[] = {"2198", "0", "65536", "2198junk", "-1", "42949672962198"};
    const char *extra[] = {"", "<param name='port' value='2198'/>",
        "<param name='decrykey' value='bad'/>", "<param name='verifyValueExt' value='abc'/>",
        "<param name='vmmPort' value='65536'/>", "<param name='compress' value='1junk'/>",
        "<param name='privilege' value='-1'/>", "<param name='verifyValueExt' value=''/>",
        "<param name='verifyValueExt' value='00112233445566778899aabbccddeefg'/>"};
    for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]) + sizeof(extra) / sizeof(extra[0]) - 1; ++i) {
        size_t port_count = sizeof(ports) / sizeof(ports[0]);
        const char *port = i < port_count ? ports[i] : ports[0];
        size_t extra_index = i < port_count ? 0 : i - port_count + 1;
        char xml[1200];
        snprintf(xml, sizeof(xml), "<jnlp><information><title>MEGARAC Dell Huawei</title></information>"
            "<applet-desc><param value='bmc.example' name='IPA'/><param name='port' value='%s'/>"
            "<param name='verifyValue' value='1234567890'/>"
            "<param name='decrykey' value='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'/>"
            "<!-- <param name='verifyValue' value='fake'/> -->"
            "<param name='title' value='A&amp;B'/>%s</applet-desc></jnlp>", port, extra[extra_index]);
        bc_status status = bc_huawei_kvm_discover_jnlp((const uint8_t *)xml, (uint32_t)strlen(xml), &params, &profile);
        CHECK(status == (i == 0 || extra_index == 7 ? BC_OK : BC_PROTOCOL_ERROR));
        if (status == BC_OK) CHECK(!strcmp(params.title, "A&B"));
        else CHECK(!params.host[0] && !profile.evidence);
    }
    CHECK(bc_huawei_kvm_discover_jnlp((const uint8_t *)JNLP, 65537, &params, &profile) == BC_LIMIT_EXCEEDED);
    CHECK(!params.decrykey[0] && !profile.evidence);
}

static void test_jnlp(void) {
    bc_huawei_kvm_params params;
    char error[128] = {0};
    memset(&params, 0, sizeof(params));
    params.struct_size = sizeof(params);
    params.abi_version = BC_ABI_VERSION;
    CHECK(bc_huawei_kvm_params_from_jnlp((const uint8_t *)JNLP, strlen(JNLP), &params, error, sizeof(error)) == BC_OK);
    CHECK(strcmp(params.host, "10.10.1.81") == 0);
    CHECK(params.port == 2198 && params.vmm_port == 8208 && params.privilege == 4);
    CHECK(strcmp(params.verify_value, "1234567890") == 0);
    CHECK(strcmp(params.verify_value_ext, "00112233445566778899aabbccddeeff") == 0);
    CHECK(strcmp(params.title, " iBMC test") == 0);
    const char *broken = "<jnlp><applet-desc><param name=\"IPA\" value=\"1.2.3.4\"/></applet-desc></jnlp>";
    memset(&params, 0, sizeof(params));
    params.struct_size = sizeof(params);
    params.abi_version = BC_ABI_VERSION;
    CHECK(bc_huawei_kvm_params_from_jnlp((const uint8_t *)broken, strlen(broken), &params, error, sizeof(error)) ==
          BC_PROTOCOL_ERROR);
    CHECK(error[0] != 0);
}

static void test_packets(void) {
    bc_huawei_kvm_params params;
    make_params(&params);
    uint8_t buffer[128];
    uint32_t written = 0;
    CHECK(bc_huawei_kvm_get_suite_packet(&params, buffer, sizeof(buffer), &written) == BC_OK);
    CHECK(bytes_equal(buffer, written, HEX_GET_SUITE));
    CHECK(bc_huawei_kvm_set_suite_packet(&params, 3, 10000, buffer, sizeof(buffer), &written) == BC_OK);
    CHECK(bytes_equal(buffer, written, HEX_SET_SUITE));
    uint8_t auth[BC_HUAWEI_AUTH_MAX];
    CHECK(bc_huawei_kvm_auth_code(&params, 3, 10000, auth) == BC_OK);
    CHECK(bytes_equal(auth, sizeof(auth), HEX_AUTH_SHA256));
    CHECK(bc_huawei_kvm_connect_packet(&params, auth, NULL, 0, buffer, sizeof(buffer), &written) == BC_OK);
    CHECK(bytes_equal(buffer, written, HEX_CONNECT));
    CHECK(bc_huawei_kvm_auth_code(&params, 2, 5000, auth) == BC_OK);
    CHECK(bytes_equal(auth, sizeof(auth), HEX_AUTH_SHA1));
}

static void test_content_keys_and_input(void) {
    bc_huawei_kvm_params params;
    make_params(&params);
    uint8_t negotiation[48];
    CHECK(from_hex(HEX_NEGOTIATION, negotiation, sizeof(negotiation)) == 48);
    bc_huawei_kvm_keys keys;
    memset(&keys, 0, sizeof(keys));
    CHECK(bc_huawei_kvm_content_keys(negotiation, sizeof(negotiation), &params, 3, 10000, &keys) == BC_OK);
    CHECK(bytes_equal(keys.key, 16, HEX_CRYPT_KEY));
    CHECK(bytes_equal(keys.key_ext, 16, HEX_CRYPT_KEY_EXT));
    CHECK(bytes_equal(keys.iv, 16, HEX_CRYPT_IV));
    uint8_t buffer[128];
    uint32_t written = 0;
    const uint8_t report[8] = {0x02, 0, 0x04, 0, 0, 0, 0, 0};
    CHECK(bc_huawei_kvm_input_packet(&params, &keys, 0x03, report, sizeof(report), buffer, sizeof(buffer), &written) ==
          BC_OK);
    CHECK(bytes_equal(buffer, written, HEX_KEYBOARD));
    const uint8_t mouse_absolute[6] = {1, (uint8_t)(1000 >> 8), 0xE8, (uint8_t)(2000 >> 8), 0xD0, 0};
    CHECK(bc_huawei_kvm_input_packet(&params, &keys, 0x05, mouse_absolute, sizeof(mouse_absolute), buffer,
                                     sizeof(buffer), &written) == BC_OK);
    CHECK(bytes_equal(buffer, written, HEX_MOUSE_ABS));
    const uint8_t mouse_relative[4] = {1, (uint8_t)(int8_t)-10, 20, 0};
    CHECK(bc_huawei_kvm_input_packet(&params, &keys, 0x05, mouse_relative, sizeof(mouse_relative), buffer,
                                     sizeof(buffer), &written) == BC_OK);
    CHECK(bytes_equal(buffer, written, HEX_MOUSE_REL));
}

static void test_video(void) {
    uint8_t blocks[256];
    uint32_t scan_length = from_hex(HEX_SCAN, blocks + 3, sizeof(blocks) - 3);
    blocks[0] = 0x40;
    blocks[1] = (uint8_t)(scan_length >> 8);
    blocks[2] = (uint8_t)scan_length;
    uint32_t blocks_length = 3 + scan_length;
    uint8_t wide[256];
    memcpy(wide, blocks, blocks_length);
    wide[blocks_length] = 0xC0; /* copy previous block to the right tile */
    uint8_t frame[128 * 128 * 4];
    CHECK(bc_huawei_kvm_video_render(wide, blocks_length + 1, 128, 64, 5, frame, sizeof(frame)) == BC_OK);
    const uint8_t *top_left = frame + (0 * 128 + 4) * 4;
    const uint8_t *bottom_left = frame + (60 * 128 + 4) * 4;
    const uint8_t *top_right = frame + (0 * 128 + 100) * 4;
    const uint8_t *bottom_right = frame + (60 * 128 + 100) * 4;
    CHECK(top_left[0] > 150 && top_left[0] > top_left[2]);
    CHECK(bottom_left[2] > 150 && bottom_left[2] > bottom_left[0]);
    CHECK(top_right[0] > 150 && top_right[0] > top_right[2]);
    CHECK(bottom_right[2] > 150 && bottom_right[2] > bottom_right[0]);
    /* Copy-above (type 5) path: 64x128 = two tiles stacked vertically. */
    uint8_t tall[256];
    memcpy(tall, blocks, blocks_length);
    tall[blocks_length] = 0xA0; /* copy above */
    uint8_t tall_frame[64 * 128 * 4];
    CHECK(bc_huawei_kvm_video_render(tall, blocks_length + 1, 64, 128, 5, tall_frame, sizeof(tall_frame)) == BC_OK);
    const uint8_t *row_top = tall_frame + (4 * 64 + 4) * 4;
    const uint8_t *row_bottom = tall_frame + (100 * 64 + 4) * 4;
    CHECK(row_top[0] > 150 && row_top[0] > row_top[2]);
    CHECK(row_bottom[2] > 150 && row_bottom[2] > row_bottom[0]);
    /* Tile-only entry point. */
    uint8_t tile[64 * 64 * 4];
    CHECK(bc_huawei_kvm_video_tile(blocks + 3, scan_length, 5, tile, sizeof(tile)) == BC_OK);
    CHECK(tile[0] > 150 && tile[0] > tile[2]);
    CHECK(bc_huawei_kvm_video_tile(blocks + 3, scan_length, 5, tile, 16) == BC_LIMIT_EXCEEDED);
    CHECK(bc_huawei_kvm_video_tile(blocks + 3, scan_length, 1, tile, sizeof(tile)) == BC_OK);
    CHECK(tile[0] == 255 && tile[1] == 0 && tile[2] == 0);
    CHECK(bc_huawei_kvm_video_tile(blocks + 3, scan_length, 10, tile, sizeof(tile)) == BC_OK);
    CHECK(tile[0] > tile[2] && tile[0] - tile[2] < 20);

    uint8_t last_block[30 * 20 - 1 + sizeof(blocks)];
    uint32_t skip = 30 * 20 - 1;
    memset(last_block, 0x80, skip);
    memcpy(last_block + skip, blocks, blocks_length);
    uint32_t large_bytes = 1920u * 1280u * 4u;
    uint8_t *large = malloc(large_bytes);
    CHECK(large);
    CHECK(bc_huawei_kvm_video_render(last_block, skip + blocks_length, 1920, 1280, 10, large, large_bytes) == BC_OK);
    CHECK(large[0] == 0 && !memcmp(large + large_bytes - 4, tile + sizeof(tile) - 4, 4));
    free(large);
}

static void test_handshake_gates(void) {
    uint8_t key_payload[50] = {0x40, 0}, key_frame[64];
    CHECK(from_hex(HEX_NEGOTIATION, key_payload + 2, 48) == 48);
    uint32_t key_length = wrap_frame(key_frame, key_payload, sizeof(key_payload));
    const uint8_t offers[][8] = {
        {0x43, 0, 1, 99, 0, 0, 0x27, 0x10},
        {0x43, 0, 0},
        {0x43, 0, 2, 3, 0, 0, 0x27, 0x10},
        {0x43, 0, 1, 3, 0, 0, 0, 0},
        {0x43, 0},
        {0x43, 0, 1, 3, 0, 0, 0x27, 0x10},
        {0x08, 0, 7},
        {0x43, 0, 1, 2, 0, 0, 0x13, 0x88}
    };
    const uint32_t sizes[] = {8, 3, 8, 8, 2, 8, 3, 8};
    const bc_status expected[] = {BC_UNSUPPORTED, BC_UNSUPPORTED, BC_PROTOCOL_ERROR,
        BC_UNSUPPORTED, BC_PROTOCOL_ERROR, BC_IO_ERROR, BC_PROTOCOL_ERROR, BC_OK};
    for (uint32_t i = 0; i < 12; ++i) {
        bc_huawei_kvm_params params; make_params(&params);
        script_io io; script_reset(&io);
        uint8_t frame[128];
        uint32_t length;
        if (i < 8) length = wrap_frame(frame, offers[i], sizes[i]);
        else if (i == 8) { memcpy(frame, key_frame, key_length); length = key_length; }
        else if (i == 11) {
            uint8_t unsupported[] = {0x43, 0, 1, 1, 0, 0, 0x27, 0x10};
            length = wrap_frame(frame, unsupported, sizeof(unsupported));
        }
        else length = wrap_frame(frame, offers[i == 9 ? 0 : 5], 8);
        if (i == 5) io.fail_send = 2;
        if (i == 7 || i == 9) { memcpy(frame + length, key_frame, key_length); length += key_length; }
        if (i == 10) length += wrap_frame(frame + length, offers[5], 8);
        io.chunks[0] = frame; io.lengths[0] = length; io.count = 1;
        bc_huawei_io transport = {&io, script_send, script_recv};
        uint8_t framebuffer[4]; bc_huawei_kvm_options options = {0};
        options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
        options.handshake_timeout_ms = 200; options.frame_buffer = framebuffer;
        options.frame_capacity = sizeof(framebuffer);
        bc_huawei_kvm_session *session = NULL;
        CHECK(bc_huawei_kvm_session_create(&params, &transport, &options, &session) == BC_OK);
        CHECK(!bc_huawei_kvm_session_failure_get(session));
        bc_status status = i < 8 ? expected[i] : i == 9 || i == 11 ? BC_UNSUPPORTED : BC_PROTOCOL_ERROR;
        CHECK(bc_huawei_kvm_session_start(session) == status);
        const bc_console_failure *detail = bc_huawei_kvm_session_failure_get(session);
        if (status == BC_OK) {
            CHECK(!detail && io.send_calls == 3);
            CHECK(io.sent[24] == 2 && bc_service_profile_verified(bc_huawei_kvm_session_profile_get(session), BC_SERVICE_KVM));
        } else {
            CHECK(detail && detail->status == status);
            CHECK(detail->service == BC_SERVICE_KVM && detail->family == BC_SERVICE_FAMILY_HUAWEI);
            CHECK(!bc_service_profile_verified(bc_huawei_kvm_session_profile_get(session), BC_SERVICE_KVM));
            CHECK(io.sent_length == (i == 10 ? 64 : 12));
            CHECK(detail->cause == (i == 6 ? BC_CONSOLE_CAUSE_SESSION_REJECTED :
                i == 5 ? BC_CONSOLE_CAUSE_UNKNOWN : BC_CONSOLE_CAUSE_PROTOCOL));
            CHECK(detail->phase == (i == 5 ? BC_CONSOLE_PHASE_TRANSPORT : BC_CONSOLE_PHASE_VALIDATION));
            if (i == 6) {
                CHECK(detail->device_code == 7);
                bc_console_retry_budget budget = {sizeof(budget), 0, 0};
                CHECK(bc_console_recovery(detail, 1, 0, &budget) == BC_CONSOLE_RECOVERY_REFRESH_TICKET);
            }
        }
        bc_huawei_kvm_session_destroy(session);
    }
    /* The known direct-auth legacy path still works without a suite response. */
    bc_huawei_kvm_params params; make_params(&params); params.verify_value_ext[0] = 0;
    script_io io; script_reset(&io); io.chunks[0] = key_frame; io.lengths[0] = key_length; io.count = 1;
    bc_huawei_io transport = {&io, script_send, script_recv};
    uint8_t framebuffer[4]; bc_huawei_kvm_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.frame_buffer = framebuffer; options.frame_capacity = sizeof(framebuffer);
    bc_huawei_kvm_session *session = NULL;
    CHECK(bc_huawei_kvm_session_create(&params, &transport, &options, &session) == BC_OK);
    CHECK(bc_huawei_kvm_session_start(session) == BC_OK && io.sent_length == 35 && io.send_calls == 1);
    CHECK(bc_service_profile_verified(bc_huawei_kvm_session_profile_get(session), BC_SERVICE_KVM));
    bc_huawei_kvm_session_destroy(session);
}

typedef struct { uint8_t blocks[256]; uint32_t length, width, height, quantization; } captured_video;
static bc_status capture_video(void *user, const uint8_t *blocks, uint32_t length,
    uint32_t width, uint32_t height, uint32_t quantization, uint32_t sequence, uint32_t flags) {
    captured_video *video = user;
    CHECK(length <= sizeof(video->blocks) && sequence == 1 && flags == BC_HUAWEI_FRAME_KEY);
    memcpy(video->blocks, blocks, length);
    video->length = length; video->width = width; video->height = height; video->quantization = quantization;
    return BC_OK;
}
static void test_kvm_session(int deferred) {
    bc_huawei_kvm_params params;
    make_params(&params);
    uint8_t suite_payload[8] = {0x43, 0, 1, 3, 0, 0, 0x27, 0x10};
    uint8_t suite_frame[64];
    uint32_t suite_length = wrap_frame(suite_frame, suite_payload, sizeof(suite_payload));
    uint8_t key_payload[50];
    key_payload[0] = 0x40; key_payload[1] = 0;
    CHECK(from_hex(HEX_NEGOTIATION, key_payload + 2, sizeof(key_payload) - 2) == 48);
    uint8_t key_frame[64];
    uint32_t key_length = wrap_frame(key_frame, key_payload, sizeof(key_payload));
    /* 64x64 synthetic image: one JPEG record, one fragment. */
    uint8_t scan[256];
    uint32_t scan_length = from_hex(HEX_SCAN, scan, sizeof(scan));
    uint8_t header_payload[19] = {0x02, 0, 0, 0, 1, 0, 0, 0, 0, 0, 64, 0, 64, 0, 0, 0, 0, 0, 0x85};
    uint32_t image_length = 3 + scan_length;
    header_payload[5] = (uint8_t)(image_length >> 24);
    header_payload[6] = (uint8_t)(image_length >> 16);
    header_payload[7] = (uint8_t)(image_length >> 8);
    header_payload[8] = (uint8_t)image_length;
    uint8_t header_frame[64];
    uint32_t header_length = wrap_frame(header_frame, header_payload, sizeof(header_payload));
    uint8_t fragment_payload[6 + 128];
    fragment_payload[0] = 0x02; fragment_payload[1] = 0;
    fragment_payload[2] = 0x00; fragment_payload[3] = 0x01;
    fragment_payload[4] = 0x01;
    fragment_payload[5] = (uint8_t)image_length;
    CHECK(from_hex(HEX_FRAGMENT_CIPHER, fragment_payload + 6, sizeof(fragment_payload) - 6) == 128);
    uint8_t fragment_frame[160];
    uint32_t fragment_length = wrap_frame(fragment_frame, fragment_payload, sizeof(fragment_payload));

    script_io io;
    script_reset(&io);
    io.chunks[0] = suite_frame; io.lengths[0] = suite_length;
    io.chunks[1] = key_frame; io.lengths[1] = key_length;
    io.chunks[2] = header_frame; io.lengths[2] = header_length;
    io.chunks[3] = fragment_frame; io.lengths[3] = fragment_length;
    io.count = 4;
    bc_huawei_io transport = {&io, script_send, script_recv};
    uint8_t framebuffer[64 * 64 * 4];
    uint8_t frames_storage_a[64], frames_storage_b[64];
    bc_huawei_kvm_options options;
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = BC_ABI_VERSION;
    options.handshake_timeout_ms = 2000;
    options.heartbeat_interval_ms = 5000;
    options.frame_buffer = framebuffer;
    options.frame_capacity = sizeof(framebuffer);
    bc_huawei_kvm_session *session = NULL;
    CHECK(bc_huawei_kvm_session_create(&params, &transport, &options, &session) == BC_OK);
    captured_video captured = {0};
    if (deferred) CHECK(bc_huawei_kvm_session_set_video_sink(session, capture_video, &captured) == BC_OK);
    CHECK(!bc_service_profile_verified(bc_huawei_kvm_session_profile_get(session), BC_SERVICE_KVM));
    CHECK(bc_huawei_kvm_session_start(session) == BC_OK);
    CHECK(bc_service_profile_verified(bc_huawei_kvm_session_profile_get(session), BC_SERVICE_KVM));
    CHECK(!bc_service_profile_can_attempt(bc_huawei_kvm_session_profile_get(session), BC_SERVICE_LOCAL_MEDIA));
    uint32_t state = 0;
    CHECK(bc_huawei_kvm_session_state(session, &state) == BC_OK && state == BC_HUAWEI_KVM_STATE_STREAMING);
    CHECK(io.sent_length == 12 + 17 + 35);
    CHECK(bytes_equal(io.sent, 12, HEX_GET_SUITE));
    CHECK(bytes_equal(io.sent + 12, 17, HEX_SET_SUITE));
    CHECK(bytes_equal(io.sent + 29, 35, HEX_CONNECT));
    CHECK(bc_huawei_kvm_session_poll(session, 10) == BC_OK);
    bc_huawei_kvm_frame frame;
    CHECK(bc_huawei_kvm_session_frame(session, &frame) == BC_BUSY);
    CHECK(bc_huawei_kvm_session_poll(session, 10) == BC_OK);
    if (deferred) {
        CHECK(bc_huawei_kvm_session_frame(session, &frame) == BC_BUSY);
        CHECK(bc_huawei_kvm_session_set_video_sink(session, NULL, NULL) == BC_BUSY);
        CHECK(captured.length == image_length);
        uint32_t sent = io.sent_length;
        CHECK(bc_huawei_kvm_session_key(session, 'a', 1) == BC_OK && io.sent_length > sent);
        CHECK(bc_huawei_kvm_session_key(session, 'a', 0) == BC_OK);
        bc_huawei_video_decoder *decoder = NULL;
        CHECK(bc_huawei_video_decoder_create(framebuffer, sizeof(framebuffer), &decoder) == BC_OK);
        CHECK(bc_huawei_video_decoder_draw(decoder, captured.blocks, captured.length,
            captured.width, captured.height, captured.quantization) == BC_OK);
        uint8_t original[sizeof(framebuffer)]; memcpy(original, framebuffer, sizeof(original));
        const uint8_t unchanged = 0x80;
        CHECK(bc_huawei_video_decoder_draw(decoder, &unchanged, 1, 64, 64, 5) == BC_OK);
        CHECK(!memcmp(original, framebuffer, sizeof(original)));
        bc_huawei_video_decoder_destroy(decoder);
        memset(&frame, 0, sizeof(frame));
        frame.width = 64; frame.height = 64; frame.stride = 256; frame.pixels = framebuffer;
    } else {
    CHECK(bc_huawei_kvm_session_frame(session, &frame) == BC_OK);
    }
    CHECK(frame.width == 64 && frame.height == 64 && frame.stride == 256);
    CHECK(frame.pixels[0] > 150 && frame.pixels[0] > frame.pixels[2]);
    CHECK(frame.pixels[(63 * 64 + 4) * 4 + 2] > 150);
    CHECK(bc_huawei_kvm_session_ack_frame(session) == BC_OK);
    CHECK(bc_huawei_kvm_session_frame(session, &frame) == BC_BUSY);
    bc_huawei_kvm_stats stats;
    memset(&stats, 0, sizeof(stats));
    stats.struct_size = sizeof(stats);
    stats.abi_version = BC_ABI_VERSION;
    CHECK(bc_huawei_kvm_session_stats(session, &stats) == BC_OK && stats.decoded_frames == (deferred ? 0u : 1u));

    /* VMM credential negotiation carried over the KVM channel. */
    script_reset(&io);
    uint8_t vmm_payload[80];
    uint8_t vmm_frame_buffer[96];
    vmm_payload[0] = 0x32; vmm_payload[1] = 0;
    CHECK(from_hex(HEX_VMM_CODEKEY, vmm_payload + 2, sizeof(vmm_payload) - 2) == 48);
    io.chunks[0] = vmm_frame_buffer;
    io.lengths[0] = wrap_frame(vmm_frame_buffer, vmm_payload, 50);
    uint8_t port_payload[18] = {0x36, 0};
    CHECK(from_hex(HEX_VMM_PORT_CIPHER, port_payload + 2, 16) == 16);
    uint8_t state_payload[18] = {0x48, 0};
    CHECK(from_hex(HEX_VMM_STATE_CIPHER, state_payload + 2, 16) == 16);
    io.chunks[1] = frames_storage_a;
    io.lengths[1] = wrap_frame(frames_storage_a, state_payload, sizeof(state_payload));
    io.chunks[2] = frames_storage_b;
    io.lengths[2] = wrap_frame(frames_storage_b, port_payload, sizeof(port_payload));
    io.count = 3;
    bc_kvm_frame media_surface = {0}; media_surface.struct_size = sizeof(media_surface);
    bc_console_session *media_console = NULL;
    CHECK(bc_huawei_console_wrap(session, &media_surface, &media_console) == BC_OK);
    CHECK(bc_console_session_controls(media_console) & BC_CONSOLE_CONTROL_MEDIA_ENABLE);
    CHECK(bc_console_session_control(media_console, BC_CONSOLE_CONTROL_MEDIA_DISABLE) == BC_UNSUPPORTED);
    CHECK(bc_console_session_control(media_console, BC_CONSOLE_CONTROL_MEDIA_ENABLE) == BC_OK);
    bc_media_offer *offer = NULL;
    CHECK(bc_console_session_media_offer(media_console, &offer) == BC_BUSY && !offer);
    bc_console_session_destroy(media_console);
    CHECK(bytes_equal(io.sent, 12, "fef60004499602d200003100"));
    CHECK(bc_huawei_kvm_session_poll(session, 10) == BC_OK);
    CHECK(bytes_equal(io.sent + 12, 12, "fef60004499602d200004700"));
    CHECK(bc_huawei_kvm_session_poll(session, 10) == BC_OK);
    CHECK(bytes_equal(io.sent + 24, 12, "fef60004499602d200003500"));
    bc_huawei_vmm_info vmm_info;
    memset(&vmm_info, 0, sizeof(vmm_info));
    CHECK(bc_huawei_kvm_session_poll(session, 10) == BC_OK);
    CHECK(bc_huawei_kvm_session_vmm_info(session, &vmm_info) == BC_OK);
    CHECK(vmm_info.state == BC_HUAWEI_VMM_STATE_ENABLED && vmm_info.port == 8208);
    CHECK(bc_huawei_console_wrap(session, &media_surface, &media_console) == BC_OK);
    CHECK(bc_console_session_media_offer(media_console, &offer) == BC_OK);
    bc_console_session_destroy(media_console);
    bc_media_offer_info offer_info = {0}; offer_info.struct_size = sizeof(offer_info);
    CHECK(bc_media_offer_info_get(offer, &offer_info) == BC_OK);
    CHECK(offer_info.flags == BC_MEDIA_OFFER_READY && offer_info.port == 8208);
    bc_media_offer_destroy(offer);
    CHECK(bytes_equal(vmm_info.auth, 24, HEX_VMM_AUTH));
    CHECK(bytes_equal(vmm_info.key, 16, HEX_VMM_KEY));
    CHECK(bytes_equal(vmm_info.iv, 16, HEX_VMM_IV));

    /* Pointer coordinates are framebuffer pixels; the session scales them to 0...3000. */
    uint8_t negotiation_key[48];
    CHECK(from_hex(HEX_NEGOTIATION, negotiation_key, sizeof(negotiation_key)) == 48);
    bc_huawei_kvm_keys keys;
    memset(&keys, 0, sizeof(keys));
    CHECK(bc_huawei_kvm_content_keys(negotiation_key, sizeof(negotiation_key), &params, 3, 10000, &keys) == BC_OK);
    uint32_t sent_before_pointer = io.sent_length;
    CHECK(bc_huawei_kvm_session_pointer(session, 32, 32, 0) == BC_OK);
    const uint8_t expected_mouse_report[6] = {0, 0x05, 0xDC, 0x05, 0xDC, 0};
    uint8_t expected_mouse[64];
    uint32_t expected_mouse_length = 0;
    CHECK(bc_huawei_kvm_input_packet(&params, &keys, 0x05, expected_mouse_report, sizeof(expected_mouse_report),
                                     expected_mouse, sizeof(expected_mouse), &expected_mouse_length) == BC_OK);
    CHECK(io.sent_length == sent_before_pointer + expected_mouse_length);
    CHECK(memcmp(io.sent + sent_before_pointer, expected_mouse, expected_mouse_length) == 0);
    /* Raw device coordinates bypass scaling. */
    CHECK(bc_huawei_kvm_session_pointer_device(session, 3000, 3000, 0) == BC_OK);

    /* Duplicate keyboard reports must be suppressed: one press, repeated key-down events and a
     * repeated release each reach the wire at most once, while state changes still do. */
    uint32_t before_key = io.sent_length;
    CHECK(bc_huawei_kvm_session_key_usage(session, 0x04, 0, 1) == BC_OK);
    uint32_t after_press = io.sent_length;
    CHECK(after_press > before_key);
    for (int repeat = 0; repeat < 5; ++repeat) {
        CHECK(bc_huawei_kvm_session_key_usage(session, 0x04, 0, 1) == BC_OK);
        CHECK(io.sent_length == after_press);
    }
    CHECK(bc_huawei_kvm_session_key_usage(session, 0x04, 0, 0) == BC_OK);
    uint32_t after_release = io.sent_length;
    CHECK(after_release > after_press);
    CHECK(bc_huawei_kvm_session_key_usage(session, 0x04, 0, 0) == BC_OK);
    CHECK(io.sent_length == after_release);
    /* Rollover and modifier transitions must still be transmitted. */
    CHECK(bc_huawei_kvm_session_key_usage(session, 0x04, 0, 1) == BC_OK);
    uint32_t rollover_start = io.sent_length;
    CHECK(bc_huawei_kvm_session_key_usage(session, 0x05, 0, 1) == BC_OK);
    CHECK(io.sent_length > rollover_start);
    uint32_t shift_start = io.sent_length;
    CHECK(bc_huawei_kvm_session_key_usage(session, 0xE1, 0, 1) == BC_OK); /* Left Shift */
    CHECK(io.sent_length > shift_start);
    CHECK(bc_huawei_kvm_session_key(session, 'A', 1) == BC_OK); /* implicit shift */
    CHECK(bc_huawei_kvm_session_key(session, 'A', 0) == BC_OK);
    CHECK(bc_huawei_kvm_session_key_usage(session, 0xE1, 0, 0) == BC_OK);
    CHECK(bc_huawei_kvm_session_key_usage(session, 0x05, 0, 0) == BC_OK);
    CHECK(bc_huawei_kvm_session_key_usage(session, 0x04, 0, 0) == BC_OK);

    uint8_t surface_pixels[4]={1,2,3,255};
    bc_kvm_frame surface={0}; surface.struct_size=sizeof(surface); surface.flags=BC_KVM_FRAME_READY;
    surface.width=surface.height=1; surface.stride=4; surface.pixels=surface_pixels;
    bc_console_session *console=NULL;
    CHECK(bc_huawei_console_wrap(session,&surface,&console)==BC_OK);
    CHECK(bc_console_session_input_capabilities(console)==0);
    bc_console_statistics unified_stats = {0}; unified_stats.struct_size = sizeof(unified_stats);
    CHECK(bc_console_session_statistics_get(console, &unified_stats) == BC_OK);
    CHECK(unified_stats.received_bytes > 0 && unified_stats.image_packets > 0);
    bc_display_tile tile={0}; tile.struct_size=sizeof(tile);
    CHECK(bc_console_session_tile(console,&tile)==BC_OK && tile.pixels.data==surface_pixels);
    bc_console_session_ack_display(console);
    CHECK(bc_console_session_tile(console,&tile)==BC_BUSY);
    bc_console_input event={0}; event.struct_size=sizeof(event); event.type=BC_CONSOLE_INPUT_POINTER;
    event.x=event.y=64; event.width=event.height=128;
    sent_before_pointer=io.sent_length;
    CHECK(bc_console_session_input(console,&event)==BC_OK);
    CHECK(io.sent_length==sent_before_pointer+expected_mouse_length);
    CHECK(!memcmp(io.sent+sent_before_pointer,expected_mouse,expected_mouse_length));
    event.type=BC_CONSOLE_INPUT_SCROLL; event.wheel=1;
    sent_before_pointer=io.sent_length;
    CHECK(bc_console_session_input(console,&event)==BC_UNSUPPORTED && io.sent_length==sent_before_pointer);
    bc_console_session_destroy(console);

    /* Press a key and a mouse button, then destroy: the session must emit all-zero releases so no
     * stuck key or button remains after disconnect. */
    CHECK(bc_huawei_kvm_session_key_usage(session, 0x28, 0, 1) == BC_OK);
    CHECK(bc_huawei_kvm_session_pointer(session, 0, 0, 1) == BC_OK);
    uint8_t zero_report[8] = {0};
    uint8_t expected_zero_key[64], expected_zero_mouse[64];
    uint32_t zero_key_length = 0, mouse_length = 0;
    CHECK(bc_huawei_kvm_input_packet(&params, &keys, 0x03, zero_report, sizeof(zero_report), expected_zero_key,
                                     sizeof(expected_zero_key), &zero_key_length) == BC_OK);
    const uint8_t zero_mouse_report[6] = {0, 0, 0, 0, 0, 0};
    CHECK(bc_huawei_kvm_input_packet(&params, &keys, 0x05, zero_mouse_report, sizeof(zero_mouse_report),
                                     expected_zero_mouse, sizeof(expected_zero_mouse), &mouse_length) == BC_OK);
    uint32_t before_destroy = io.sent_length;
    bc_huawei_kvm_session_destroy(session);
    CHECK(io.sent_length == before_destroy + zero_key_length + mouse_length);
    CHECK(memcmp(io.sent + before_destroy, expected_zero_key, zero_key_length) == 0);
    CHECK(memcmp(io.sent + before_destroy + zero_key_length, expected_zero_mouse, mouse_length) == 0);
}

static void test_keysym(void) {
    uint8_t modifiers = 0;
    CHECK(bc_huawei_kvm_keysym_to_usage('a', &modifiers) == 0x04 && modifiers == 0);
    CHECK(bc_huawei_kvm_keysym_to_usage('A', &modifiers) == 0x04 && modifiers == 0x02);
    CHECK(bc_huawei_kvm_keysym_to_usage(0xFF0D, &modifiers) == 0x28);
    CHECK(bc_huawei_kvm_keysym_to_usage(0xFF09, &modifiers) == 0x2B);
    CHECK(bc_huawei_kvm_keysym_to_usage(0xFF51, &modifiers) == 0x50);
    CHECK(bc_huawei_kvm_keysym_to_usage(0x1234, &modifiers) == 0);
}

static void test_pointer_scale(void) {
    CHECK(bc_huawei_kvm_pointer_scale(0, 1024) == 0);
    CHECK(bc_huawei_kvm_pointer_scale(512, 1024) == 1500);
    CHECK(bc_huawei_kvm_pointer_scale(1023, 1024) == 2997);
    CHECK(bc_huawei_kvm_pointer_scale(700, 768) == 2734);
    CHECK(bc_huawei_kvm_pointer_scale(3000, 0) == 3000);
    CHECK(bc_huawei_kvm_pointer_scale(99999, 0) == 3000);
}

/* ---------------------------------------------------------------------------------------------
 * Virtual media
 * ------------------------------------------------------------------------------------------- */

static uint8_t iso_data[4096];

static bc_status iso_size(void *userdata, uint64_t *bytes) {
    (void)userdata;
    *bytes = sizeof(iso_data);
    return BC_OK;
}

static bc_status iso_read(void *userdata, uint64_t offset, uint32_t length, uint8_t *out) {
    (void)userdata;
    if (offset > sizeof(iso_data) || length > sizeof(iso_data) - offset) return BC_IO_ERROR;
    memcpy(out, iso_data + offset, length);
    return BC_OK;
}

static uint32_t vmm_frame(uint8_t *out, uint8_t command, uint8_t usb_id, const uint8_t *body, uint32_t length) {
    memset(out, 0, 12);
    out[0] = command;
    out[3] = usb_id;
    out[4] = (uint8_t)(length >> 24); out[5] = (uint8_t)(length >> 16);
    out[6] = (uint8_t)(length >> 8); out[7] = (uint8_t)length;
    if (length) memcpy(out + 12, body, length);
    return 12 + length;
}


static void test_media(void) {
    for (uint32_t i = 0; i < sizeof(iso_data); ++i) iso_data[i] = (uint8_t)(i * 7 + 3);
    bc_huawei_kvm_params params;
    make_params(&params);
    bc_huawei_vmm_info info;
    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    info.state = BC_HUAWEI_VMM_STATE_ENABLED;
    info.port = 8208;
    CHECK(from_hex(HEX_VMM_AUTH, info.auth, sizeof(info.auth)) == 24);
    CHECK(from_hex(HEX_VMM_KEY, info.key, sizeof(info.key)) == 16);
    CHECK(from_hex(HEX_VMM_IV, info.iv, sizeof(info.iv)) == 16);
    uint8_t ack_auth[12] = {0}, ack_create[12] = {0};
    ack_auth[2] = 0x00;
    ack_create[2] = 0x10;
    uint8_t inquiry_cdb[16] = {0x12, 0, 0, 0, 36};
    uint8_t capacity_cdb[16] = {0x25, 0, 0, 0, 0, 0, 0, 0, 8};
    uint8_t read_cdb[16] = {0x28, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t write_cdb[16] = {0x2A, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t frames[5][64];
    uint32_t lengths[5];
    lengths[0] = 12; memcpy(frames[0], ack_auth, 12);
    lengths[1] = 12; memcpy(frames[1], ack_create, 12);
    lengths[2] = vmm_frame(frames[2], 4, 1, inquiry_cdb, sizeof(inquiry_cdb));
    lengths[3] = vmm_frame(frames[3], 4, 1, capacity_cdb, sizeof(capacity_cdb));
    lengths[4] = vmm_frame(frames[4], 4, 1, read_cdb, sizeof(read_cdb));
    script_io io;
    script_reset(&io);
    for (uint32_t i = 0; i < 5; ++i) { io.chunks[i] = frames[i]; io.lengths[i] = lengths[i]; }
    io.count = 5;
    bc_huawei_io transport = {&io, script_send, script_recv};
    bc_huawei_vmm_source source;
    memset(&source, 0, sizeof(source));
    source.struct_size = sizeof(source);
    source.userdata = NULL;
    source.size = sizeof(iso_data);
    source.read = iso_read;
    (void)iso_size;
    bc_huawei_media_options options;
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = BC_ABI_VERSION;
    options.info = &info;
    options.source = &source;
    options.timeout_ms = 1000;
    bc_huawei_media *media = NULL;
    CHECK(bc_huawei_media_create(&options, &transport, &media) == BC_OK);
    bc_media_session *common_media = NULL;
    CHECK(bc_huawei_media_wrap(media, &common_media) == BC_OK);
    CHECK(!bc_service_profile_verified(bc_huawei_media_profile_get(media), BC_SERVICE_LOCAL_MEDIA));
    CHECK(!bc_huawei_media_removal_unconfirmed(media));
    CHECK(bc_huawei_media_connect(media) == BC_OK);
    CHECK(bc_huawei_media_removal_unconfirmed(media));
    CHECK(bc_service_profile_verified(bc_huawei_media_profile_get(media), BC_SERVICE_LOCAL_MEDIA));
    CHECK(!bc_service_profile_can_attempt(bc_huawei_media_profile_get(media), BC_SERVICE_KVM));
    uint32_t state = 0;
    CHECK(bc_huawei_media_state(media, &state) == BC_OK && state == BC_HUAWEI_MEDIA_STATE_ESTABLISHED);
    uint32_t before = io.sent_length;
    CHECK(bc_media_session_poll(common_media, 10) == BC_OK);
    CHECK(io.sent[before] == 4 && io.sent[before + 1] == 0x31 && io.sent[before + 3] == 1);
    CHECK(io.sent[before + 4] == 0 && io.sent[before + 5] == 0 && io.sent[before + 6] == 0 &&
          io.sent[before + 7] == 36);
    CHECK(memcmp(io.sent + before + 12, "\x05\x80", 2) == 0);
    CHECK(io.sent[before + 48] == 0xFF);
    before = io.sent_length;
    CHECK(bc_media_session_poll(common_media, 10) == BC_OK);
    CHECK(io.sent[before + 7] == 8);
    uint32_t last_lba = ((uint32_t)io.sent[before + 12] << 24) | ((uint32_t)io.sent[before + 13] << 16) |
                        ((uint32_t)io.sent[before + 14] << 8) | io.sent[before + 15];
    uint32_t block_size = ((uint32_t)io.sent[before + 16] << 24) | ((uint32_t)io.sent[before + 17] << 16) |
                          ((uint32_t)io.sent[before + 18] << 8) | io.sent[before + 19];
    CHECK(last_lba == 1 && block_size == 2048);
    before = io.sent_length;
    CHECK(bc_media_session_poll(common_media, 10) == BC_OK);
    CHECK(io.sent[before] == 4 && io.sent[before + 1] == 0x31 && io.sent[before + 3] == 1);
    CHECK(io.sent[before + 6] == 0x08 && io.sent[before + 7] == 0x00);
    CHECK(memcmp(io.sent + before + 12, iso_data, 2048) == 0);
    /* Write commands are rejected with DATA PROTECT. */
    uint8_t write_frame[32];
    uint32_t write_length = vmm_frame(write_frame, 4, 2, write_cdb, sizeof(write_cdb));
    script_reset(&io);
    io.chunks[0] = write_frame;
    io.lengths[0] = write_length;
    io.count = 1;
    before = io.sent_length;
    CHECK(bc_media_session_poll(common_media, 10) == BC_OK);
    CHECK(io.sent[before] == 0xFF && io.sent[before + 1] == 1);
    bc_huawei_media_statistics stats;
    memset(&stats, 0, sizeof(stats));
    stats.struct_size = sizeof(stats);
    stats.abi_version = BC_ABI_VERSION;
    CHECK(bc_huawei_media_stats(media, &stats) == BC_OK);
    CHECK(stats.sense_key == 7 && stats.asc == 0x27);
    before = io.sent_length;
    CHECK(bc_media_session_control(common_media, BC_MEDIA_CONTROL_CLOSE) == BC_OK);
    CHECK(io.sent[before] == 5 && io.sent[before + 1] == 2);
    bc_media_session_info common_info = {.struct_size = sizeof(common_info)};
    CHECK(bc_media_session_info_get(common_media, &common_info) == BC_OK);
    CHECK(common_info.flags & BC_MEDIA_BYTES_READ_VALID);
    CHECK(!(common_info.flags & (BC_MEDIA_CONNECTED | BC_MEDIA_REMOVAL_CONFIRMED)));
    bc_media_session_destroy(common_media);
    bc_huawei_media_destroy(media);
    script_reset(&io);
    io.chunks[0] = frames[0]; io.lengths[0] = lengths[0];
    io.chunks[1] = frames[1]; io.lengths[1] = lengths[1]; io.count = 2;
    CHECK(bc_huawei_media_create(&options, &transport, &media) == BC_OK);
    CHECK(bc_huawei_media_connect(media) == BC_OK);
    io.fail_send = io.send_calls + 1;
    CHECK(bc_huawei_media_close(media) == BC_IO_ERROR);
    CHECK(bc_huawei_media_removal_unconfirmed(media));
    CHECK(bc_huawei_media_state(media, &state) == BC_OK && state == BC_HUAWEI_MEDIA_STATE_CLOSED);
    uint32_t calls = io.send_calls;
    CHECK(bc_huawei_media_close(media) == BC_OK && io.send_calls == calls);
    bc_huawei_media_destroy(media);

    script_reset(&io);
    io.chunks[0] = frames[0]; io.lengths[0] = lengths[0]; io.count = 1;
    io.fail_send = 2;
    CHECK(bc_huawei_media_create(&options, &transport, &media) == BC_OK);
    CHECK(bc_huawei_media_connect(media) == BC_IO_ERROR);
    CHECK(bc_huawei_media_removal_unconfirmed(media));
    CHECK(bc_huawei_media_close(media) == BC_OK);
    bc_huawei_media_destroy(media);
}

int main(void) {
    test_jnlp();
    test_jnlp_discovery();
    test_packets();
    test_content_keys_and_input();
    test_video();
    test_handshake_gates();
    test_kvm_session(0);
    test_kvm_session(1);
    test_keysym();
    test_pointer_scale();
    test_media();
    printf("huawei kvm tests passed\n");
    return 0;
}

#include "bcontrol/kvm_session.h"
#include "bcontrol/console_factory.h"
#include "bcontrol/media_factory.h"
#include "bcontrol/decode_provider.h"
#include "bcontrol/megarac_launch.h"
#include "bcontrol/console_huawei_launch.h"
#include "bcontrol/console_idrac_launch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
typedef struct { uint8_t bytes[16][8]; uint32_t lengths[16], count, fail_at; } output;
static bc_status emit(void *user, const uint8_t *bytes, uint32_t length) {
    output *out = user;
    CHECK(out->count < 16 && length <= 8);
    memcpy(out->bytes[out->count], bytes, length); out->lengths[out->count++] = length;
    return out->count == out->fail_at ? BC_IO_ERROR : BC_OK;
}
typedef struct { int ran, released; } job_state;
static bc_status run_job(void *user, const uint8_t *bytes, uint32_t length) {
    job_state *state = user;
    CHECK(length == 1 && bytes[0] == 42);
    state->ran++;
    return BC_OK;
}
static void release_job(void *user) { ((job_state *)user)->released++; }
static bc_status run_control(void *user, const uint8_t *bytes, uint32_t length) {
    CHECK(!bytes && !length);
    ((job_state *)user)->ran++;
    return BC_OK;
}
static void check_jobs(void) {
    job_state state = {0}; uint8_t source = 42; bc_decode_job *job = NULL;
    CHECK(bc_decode_job_create(&source, 1, run_job, release_job, &state, &job) == BC_OK);
    source = 0;
    CHECK(bc_decode_job_size(job) == 1 && bc_decode_job_execute(job) == BC_OK);
    CHECK(bc_decode_job_execute(job) == BC_BUSY && state.ran == 1);
    bc_decode_job_destroy(job);
    CHECK(state.released == 1);
    CHECK(bc_decode_job_create(&source, 1, run_job, release_job, &state, &job) == BC_OK);
    bc_decode_job_destroy(job);
    CHECK(state.ran == 1 && state.released == 2);
    CHECK(bc_decode_job_create(NULL, 0, run_control, release_job, &state, &job) == BC_OK);
    CHECK(bc_decode_job_execute(job) == BC_OK && state.ran == 2);
    bc_decode_job_destroy(job);
    CHECK(state.released == 3);
}
static uint8_t leds(void *user) { (void)user; return 0; }
static void check_launch_ownership(void) {
    char token[] = "fixture";
    bc_console_launch *launch = NULL;
    bc_idrac_console_launch descriptor = {0}; descriptor.struct_size = sizeof(descriptor);
    memcpy(descriptor.secondary_key, token, sizeof(token));
    CHECK(bc_console_launch_from_idrac(&descriptor, &launch) == BC_OK);
    memset(descriptor.secondary_key, 'x', sizeof(descriptor.secondary_key));
    bc_console_bootstrap *authentication = NULL;
    CHECK(bc_console_bootstrap_create(launch, &authentication) == BC_OK);
    bc_console_bootstrap_destroy(authentication);
    uint8_t reply[32]; output input = {0};
    bc_console_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.launch = launch; options.emit = emit; options.leds = leds; options.user = &input;
    options.display.struct_size = sizeof(options.display); options.display.abi_version = BC_ABI_VERSION;
    bc_console_session *session = NULL;
    CHECK(bc_console_session_create(&options, &session) == BC_OK);
    bc_console_launch_destroy(launch);
    const uint8_t challenge[] = {247,179}; uint32_t length = 0;
    CHECK(bc_console_session_feed(session, 0, challenge, sizeof(challenge)) == BC_OK);
    CHECK(bc_console_session_output(session, 0, reply, sizeof(reply), &length) == BC_OK);
    CHECK(length == 17 && reply[0] == 247 && reply[1] == 179 && !memcmp(reply+2, "fixture", 7));
    CHECK(input.count == 0);
    const uint8_t handshake[] = "RFB 003.008\n\1\1\0\0\0\0";
    const uint8_t init[24] = {7,128,4,176, 32,24,0,1, 0,255,0,255,0,255,16,8};
    const uint8_t update[] = {0,0,0,1, 7,127,4,175,0,1,0,1,0,0,0,0, 6,7,8,0};
    CHECK(bc_console_session_feed(session, 0, handshake, sizeof(handshake) - 1) == BC_OK);
    CHECK(bc_console_session_feed(session, 0, init, sizeof(init)) == BC_OK);
    CHECK(bc_console_session_feed(session, 0, update, sizeof(update)) == BC_OK);
    bc_display_tile tile = {.struct_size = sizeof(tile)};
    CHECK(bc_console_session_tile(session, &tile) == BC_OK);
    CHECK(tile.canvas_width == 1920 && tile.canvas_height == 1200);
    CHECK(!memcmp(tile.pixels.data + tile.pixels.length - 4, "\10\7\6\xff", 4));
    bc_console_session_destroy(session);
}
static bc_status reject_decode(void *user, bc_decode_job *job) { (void)user; (void)job; return BC_LIMIT_EXCEEDED; }
static void check_owned_megarac(void) {
    bc_megarac_kvm_info info = {0}; info.struct_size = sizeof(info);
    bc_megarac_session_options source = {0}; source.struct_size = sizeof(source);
    source.kind = BC_MEGARAC_KVM_JVIEWER; source.info = &info;
    char username[] = "fixture-user";
    source.username = username; source.client_ip = "192.0.2.2";
    bc_console_launch *launch = NULL;
    CHECK(bc_console_launch_from_megarac(&source, BC_MEGARAC_KEYBOARD_REPORT, &launch) == BC_OK);
    memset(username, 'x', sizeof(username)-1);
    bc_console_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.launch = launch; options.submit = reject_decode;
    bc_console_session *session = NULL;
    CHECK(bc_console_session_create(&options, &session) == BC_OK);
    bc_console_launch_destroy(launch);
    CHECK(bc_console_session_control(session, BC_CONSOLE_CONTROL_START) == BC_OK);
    uint8_t bytes[512]; uint32_t length = 0;
    CHECK(bc_console_session_output(session, 0, bytes, sizeof(bytes), &length) == BC_OK && length == 8 + BC_MEGARAC_JVIEWER_AUTH_SIZE);
    int found = 0;
    for (uint32_t i = 0; i + 12 <= length; ++i) if (!memcmp(bytes+i, "fixture-user", 12)) found = 1;
    CHECK(found);
    bc_console_session_destroy(session);
}
static bc_status receive_timeout(void *user, uint8_t *bytes, uint32_t capacity, uint32_t *received, uint32_t timeout) {
    (void)user; (void)bytes; (void)capacity; (void)timeout; *received = 0; return BC_TIMEOUT;
}
static void check_owned_huawei(void) {
    bc_huawei_kvm_params params = {0}; params.struct_size = sizeof(params); params.abi_version = BC_ABI_VERSION;
    bc_console_launch *launch = NULL;
    CHECK(bc_console_launch_from_huawei(&params, &launch) == BC_OK);
    bc_console_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.launch = launch; options.submit = reject_decode; options.emit = emit;
    bc_console_session *session = NULL;
    CHECK(bc_console_session_create(&options, &session) == BC_INVALID_ARGUMENT && !session);
    options.receive = receive_timeout;
    CHECK(bc_console_session_create(&options, &session) == BC_OK);
    bc_console_launch_destroy(launch);
    bc_console_info info = {0}; info.struct_size = sizeof(info);
    CHECK(bc_console_session_info_get(session, &info) == BC_OK && info.profile.family == BC_SERVICE_FAMILY_HUAWEI);
    CHECK(!(info.flags & BC_CONSOLE_INFO_READY));
    bc_console_session_destroy(session);
}
static bc_status media_read(void *user, uint64_t offset, uint32_t size, uint8_t *bytes) {
    (void)user; (void)offset; memset(bytes, 0, size); return BC_OK;
}
static void check_media_factory(void) {
    bc_media_offer *offer = NULL;
    CHECK(bc_media_offer_from_token(BC_CONSOLE_PROTOCOL_ILO, 0,
        (bc_string){"0123456789abcdef0123456789abcdef", 32}, &offer) == BC_OK);
    bc_media_source source = {sizeof(source), NULL, 8192, media_read};
    bc_media_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.offer = offer; options.source = &source;
    bc_media_session *session = NULL;
    CHECK(bc_media_session_create(&options, &session) == BC_OK);
    bc_media_offer_destroy(offer);
    uint8_t message[54]; uint32_t size = 0;
    CHECK(bc_media_session_output(session, NULL, 0, &size) == BC_LIMIT_EXCEEDED && size == 54);
    CHECK(bc_media_session_output(session, message, 53, &size) == BC_LIMIT_EXCEEDED && size == 54);
    CHECK(bc_media_session_output(session, message, sizeof(message), &size) == BC_OK && size == 54);
    CHECK(bc_media_session_output(session, NULL, 0, &size) == BC_BUSY && size == 0);
    uint8_t hello[53] = {0};
    CHECK(bc_media_session_feed(session, (bc_bytes){hello, sizeof(hello)}) == BC_OK);
    bc_media_session_info info = {.struct_size = sizeof(info)};
    CHECK(bc_media_session_info_get(session, &info) == BC_OK);
    CHECK((info.flags & BC_MEDIA_CONNECTED) && (info.flags & BC_MEDIA_REMOVAL_UNCONFIRMED));
    CHECK(!(info.flags & BC_MEDIA_MOUNT_CONFIRMED));
    CHECK(bc_media_session_observe_mount(session, 1) == BC_OK);
    CHECK(bc_media_session_info_get(session, &info) == BC_OK && (info.flags & BC_MEDIA_MOUNT_CONFIRMED));
    CHECK(bc_media_session_tick(session, 100) == BC_OK);
    CHECK(bc_media_session_tick(session, 2099) == BC_OK);
    CHECK(bc_media_session_output(session, NULL, 0, &size) == BC_BUSY);
    CHECK(bc_media_session_tick(session, 2100) == BC_OK);
    CHECK(bc_media_session_output(session, message, sizeof(message), &size) == BC_OK && size == 16);
    CHECK(bc_media_session_control(session, BC_MEDIA_CONTROL_EJECT) == BC_OK);
    CHECK(bc_media_session_info_get(session, &info) == BC_OK && (info.flags & BC_MEDIA_REMOVAL_UNCONFIRMED));
    CHECK(bc_media_session_observe_mount(session, 0) == BC_OK);
    CHECK(bc_media_session_info_get(session, &info) == BC_OK && (info.flags & BC_MEDIA_REMOVAL_CONFIRMED));
    CHECK(!(info.flags & (BC_MEDIA_MOUNT_CONFIRMED | BC_MEDIA_REMOVAL_UNCONFIRMED)));
    bc_media_session_destroy(session);
    offer = NULL;
    CHECK(bc_media_offer_from_token(BC_CONSOLE_PROTOCOL_ILO, 0,
        (bc_string){"0123456789abcdef0123456789abcdef", 32}, &offer) == BC_OK);
    options.offer = offer;
    CHECK(bc_media_session_create(&options, &session) == BC_OK);
    bc_media_offer_destroy(offer);
    hello[16] = 35;
    CHECK(bc_media_session_feed(session, (bc_bytes){hello, sizeof(hello)}) == BC_UNSUPPORTED);
    const bc_console_failure *failure = bc_media_session_failure_get(session);
    CHECK(failure && failure->cause == BC_CONSOLE_CAUSE_LICENSE_REQUIRED && failure->device_code == 35);
    bc_media_session_destroy(session);
}
int main(void) {
    check_media_factory();
    check_jobs();
    check_launch_ownership();
    check_owned_megarac();
    check_owned_huawei();
    uint8_t pixels[16];
    bc_kvm_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.max_width = options.max_height = 2; options.framebuffer = pixels; options.framebuffer_capacity = sizeof(pixels);
    output out = {0}; bc_console_session *session = NULL;
    bc_console_options create = {0};
    create.struct_size = sizeof(create); create.abi_version = BC_ABI_VERSION;
    create.display = options; create.emit = emit; create.user = &out;
    CHECK(bc_console_session_create(&create, &session) == BC_INVALID_ARGUMENT && !session);
    bc_console_launch *launch = NULL;
    CHECK(bc_console_launch_from_token(0, 0, (bc_string){0}, &launch) == BC_UNSUPPORTED && !launch);
    CHECK(bc_console_launch_from_token(BC_CONSOLE_PROTOCOL_RFB, 0, (bc_string){0}, &launch) == BC_OK);
    create.launch = launch;
    create.abi_version++;
    CHECK(bc_console_session_create(&create, &session) == BC_INVALID_ARGUMENT && !session);
    create.abi_version = BC_ABI_VERSION;
    CHECK(bc_console_session_create(&create, &session) == BC_OK);
    bc_console_launch_destroy(launch); create.launch = NULL;
    bc_console_statistics unsupported_stats = {0}; unsupported_stats.struct_size = sizeof(unsupported_stats);
    unsupported_stats.received_bytes = 99;
    CHECK(bc_console_session_statistics_get(session, &unsupported_stats) == BC_UNSUPPORTED && unsupported_stats.received_bytes == 0);
    const uint8_t banner[] = "RFB 003.008\n";
    uint8_t response[16]; uint32_t written=99;
    CHECK(bc_console_session_feed(session,1,banner,12)==BC_INVALID_ARGUMENT);
    uint32_t consumed=99;
    CHECK(bc_console_session_feed_some(session,0,banner,5,&consumed)==BC_OK && consumed==5);
    CHECK(bc_console_session_feed(session,0,banner+5,7)==BC_OK);
    CHECK(bc_console_session_output(session,0,response,sizeof(response),&written)==BC_OK);
    CHECK(written==12 && !memcmp(response,banner,12) && out.count==0);
    CHECK(bc_console_session_output(session,0,response,sizeof(response),&written)==BC_OK && written==0);
    CHECK(bc_console_session_name(session,NULL,0,&written)==BC_OK && written==0);
    bc_console_info info={0}; info.struct_size=sizeof(info);
    CHECK(bc_console_session_info_get(session,&info)==BC_OK);
    CHECK(info.flags==BC_CONSOLE_INFO_READY_KNOWN && info.keyboard_leds==0);
    CHECK(bc_console_session_poll(session,1)==BC_UNSUPPORTED);
    CHECK(bc_console_session_tick(session,1)==BC_UNSUPPORTED);
    CHECK(bc_console_session_controls(session)==BC_CONSOLE_CONTROL_CLOSE);
    CHECK(bc_console_session_control(session,BC_CONSOLE_CONTROL_REFRESH)==BC_UNSUPPORTED);
    CHECK(bc_console_session_control(session,0)==BC_INVALID_ARGUMENT);
    CHECK(bc_console_session_control(session,BC_CONSOLE_CONTROL_CLOSE|BC_CONSOLE_CONTROL_REFRESH)==BC_INVALID_ARGUMENT);
    CHECK(bc_console_session_display_modes(session) == BC_DISPLAY_TILE);
    CHECK(bc_console_session_input_capabilities(session) == BC_CONSOLE_INPUT_HAS_SCROLL);
    bc_display_tile tile = {0}; tile.struct_size = sizeof(tile);
    CHECK(bc_console_session_tile(session, &tile) == BC_BUSY);
    bc_display_stream_packet media = {0}; media.struct_size = sizeof(media);
    CHECK(bc_console_session_media(session, &media) == BC_UNSUPPORTED);
    bc_console_input event = {0}; event.struct_size = sizeof(event);
    event.type = BC_CONSOLE_INPUT_SCROLL; event.buttons = 2; event.width = event.height = 2; event.wheel = 1;
    CHECK(bc_console_session_input(session, &event) == BC_OK);
    CHECK(out.count == 2 && out.lengths[0] == 6 && out.bytes[0][1] == 12 && out.bytes[1][1] == 4);
    event.x = 2;
    CHECK(bc_console_session_input(session, &event) == BC_INVALID_ARGUMENT && out.count == 2);
    memset(&out, 0, sizeof(out)); out.fail_at = 2;
    uint32_t keys[3] = {0xffe3, 0xffe9, 0xffff};
    CHECK(bc_console_session_chord(session, keys, 3) == BC_IO_ERROR);
    CHECK(out.count == 4);
    CHECK(out.bytes[0][1] == 1 && out.bytes[1][1] == 1 && out.bytes[2][1] == 0 && out.bytes[3][1] == 0);
    CHECK(out.bytes[2][7] == 0xe9 && out.bytes[3][7] == 0xe3);
    CHECK(bc_console_session_control(session,BC_CONSOLE_CONTROL_CLOSE)==BC_OK);
    bc_console_session_destroy(session);
    memset(&out, 0, sizeof(out));
    CHECK(bc_kvm_input_wrap(emit, &out, &session) == BC_OK);
    CHECK(bc_console_session_info_get(session,&info)==BC_UNSUPPORTED && info.flags==0);
    CHECK(bc_console_session_controls(session)==0);
    written=99;
    CHECK(bc_console_session_name(session,response,sizeof(response),&written)==BC_UNSUPPORTED && written==0);
    CHECK(bc_console_session_control(session,BC_CONSOLE_CONTROL_CLOSE)==BC_UNSUPPORTED);
    CHECK(bc_console_session_display_modes(session) == 0);
    CHECK(bc_console_session_feed(session,0,banner,12)==BC_UNSUPPORTED);
    written=99;
    CHECK(bc_console_session_output(session,0,response,sizeof(response),&written)==BC_UNSUPPORTED && written==0);
    CHECK(bc_console_session_tile(session, &tile) == BC_UNSUPPORTED);
    bc_console_session_ack_display(session);
    event.x = 0;
    CHECK(bc_console_session_input(session, &event) == BC_OK && out.count == 2);
    bc_console_session_destroy(session);
    puts("console session: independent input, RFB mapping, reserved media and failed chord release passed");
    return 0;
}

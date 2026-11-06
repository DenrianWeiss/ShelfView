#include "bcontrol/idrac_session.h"
#include "bcontrol/idrac_kvm.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

typedef struct { uint8_t bytes[2][8], leds; uint32_t count; } session_capture;
static uint8_t snapshot(void *user) { return ((session_capture *)user)->leds; }
static bc_status capture(void *user, const uint8_t *bytes, uint32_t length) {
    session_capture *out=user; assert(out->count<2 && length<=8);
    memcpy(out->bytes[out->count++],bytes,length); return BC_OK;
}
static bc_idrac_kvm *create(uint8_t *pixels) {
    bc_kvm_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.max_width = 1; options.max_height = 1;
    options.framebuffer = pixels; options.framebuffer_capacity = 4;
    bc_idrac_kvm *client = NULL;
    assert(bc_idrac_kvm_create(&options, (bc_string){"fixture-key", 11}, &client) == BC_OK);
    return client;
}
static void handshake(bc_idrac_kvm *client) {
    const uint8_t version[] = "RFB 003.008\n";
    const uint8_t security[] = {1, 1}, result[] = {0, 0, 0, 0};
    const uint8_t init[] = {0,1,0,1,32,24,0,1,0,255,0,255,0,255,16,8,0,0,0,0,0,0,0,0};
    assert(bc_idrac_kvm_feed_message(client, version, sizeof(version) - 1) == BC_OK);
    assert(bc_idrac_kvm_feed_message(client, security, sizeof(security)) == BC_OK);
    assert(bc_idrac_kvm_feed_message(client, result, sizeof(result)) == BC_OK);
    assert(bc_idrac_kvm_feed_message(client, init, sizeof(init)) == BC_OK);
}
static void key_chord(bc_idrac_kvm *client) {
    uint8_t output[512]; uint32_t written = 0;
    assert(bc_idrac_kvm_output(client, output, sizeof(output), &written) == BC_OK);
    const uint32_t keys[] = {0xffe3, 0xffe1, 0xffe9, 0xffeb, 0xffff};
    for (unsigned i = 0; i < 5; ++i) assert(bc_idrac_kvm_key_event(client, 1, keys[i]) == BC_OK);
    for (unsigned i = 5; i > 0; --i) assert(bc_idrac_kvm_key_event(client, 0, keys[i - 1]) == BC_OK);
    assert(bc_idrac_kvm_key_event(client, 1, 'a') == BC_LIMIT_EXCEEDED);
    assert(bc_idrac_kvm_output(client, output, sizeof(output), &written) == BC_OK && written == 80);
    for (unsigned i = 0; i < 10; ++i) {
        const uint8_t *event = output + i * 8;
        uint32_t key = keys[i < 5 ? i : 9 - i];
        assert(event[0] == 246 && event[1] == (i < 5));
        assert(event[4] == (uint8_t)(key >> 24) && event[5] == (uint8_t)(key >> 16));
        assert(event[6] == (uint8_t)(key >> 8) && event[7] == (uint8_t)key);
    }
    assert(bc_idrac_kvm_key_event(client, 1, 'u') == BC_OK);
    assert(bc_idrac_kvm_output(client, output, sizeof(output), &written) == BC_OK && written == 8);
}
static bc_string string(const char *text) { return (bc_string){text, strlen(text)}; }
static void launch_location(void) {
    const char *good = "{\"Location\":\"/restgui/vconsole/index.html?VCSID=fixture\",\"description\":\"MegaRAC Huawei\"}";
    char location[200]; uint32_t written = 0;
    assert(bc_idrac_kvm_launch_location((const uint8_t *)good, (uint32_t)strlen(good),
        location, sizeof(location), &written) == BC_OK);
    assert(written == strlen(location) && !strcmp(location, "/restgui/vconsole/index.html?VCSID=fixture"));
    const char *bad[] = {"[]", "{}", "{\"Location\":1}", "{\"Location\":\"\"}",
        "{\"Location\":\"a\",\"Location\":\"b\"}", "{\"Location\":\"a\\u0000b\"}",
        "{\"Location\":\"a b\"}", "{\"Location\":\"a\"}trailing"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        assert(bc_idrac_kvm_launch_location((const uint8_t *)bad[i], (uint32_t)strlen(bad[i]),
            location, sizeof(location), &written) != BC_OK);
        assert(!written && !location[0]);
    }
    assert(bc_idrac_kvm_launch_location((const uint8_t *)good, (uint32_t)strlen(good),
        location, 2, &written) == BC_LIMIT_EXCEEDED);
    assert(!written && !location[0]);
}
static void discover_launch(void) {
    const char *fixture = "ip=bmc.example&kvmport=443&VCSID=fixture-ticket&VCSID2=fixture-secondary";
    bc_idrac_launch_uri uri = {0};
    uri.struct_size = sizeof(uri); uri.scheme = string("https"); uri.host = string("BMC.EXAMPLE");
    uri.path = string("/restgui/vconsole/index.html"); uri.query = string(fixture);
    bc_idrac_console_launch launch;
    bc_service_profile profile;
    assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 0, &launch, &profile) == BC_OK);
    assert(launch.kvm_port == 443 && !strcmp(launch.primary_key, "fixture-ticket"));
    assert(!strcmp(launch.secondary_key, "fixture-secondary"));
    assert(bc_service_profile_can_attempt(&profile, BC_SERVICE_KVM));
    assert(!bc_service_profile_verified(&profile, BC_SERVICE_KVM));
    assert(!bc_service_profile_can_attempt(&profile, BC_SERVICE_LOCAL_MEDIA));
    uri.query = string("ip=bmc.example&kvmport=443&title=Server%20Console%20(user)&ST1=&ST2=&VCSID=fixture-ticket&VCSID2=fixture-secondary");
    assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 443, &launch, &profile) == BC_OK);
    assert(!strcmp(launch.primary_key, "fixture-ticket"));
    const char *bad[] = {
        "ip=other.example&kvmport=443&VCSID=a&VCSID2=b",
        "ip=bmc.example&kvmport=0&VCSID=a&VCSID2=b",
        "ip=bmc.example&kvmport=65536&VCSID=a&VCSID2=b",
        "ip=bmc.example&kvmport=443junk&VCSID=a&VCSID2=b",
        "ip=bmc.example&kvmport=-1&VCSID=a&VCSID2=b",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b&VCS%49D=other",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b&x=a&x=b",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b&",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b&flag",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b&=value",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=%00",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=%0a",
        "ip=bmc.example&kvmport=443&VCSID=a%20b&VCSID2=c",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b%20c",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b&title=bad%09title",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b&title%20name=value",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=%",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=%GG",
        "ip=bmc.example&kvmport=443&VCSID=a&VCSID2=b#fragment"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        uri.query = string(bad[i]);
        assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 443, &launch, &profile) != BC_OK);
        assert(!launch.primary_key[0] && !launch.secondary_key[0] && !profile.variant && !profile.evidence);
    }
    uri.query = string("ip=BMC.EXAMPLE&kvmport=5900&VCSID=a%26b%3Dc%23%25+&VCSID2=key");
    assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 443, &launch, &profile) == BC_OK);
    assert(!strcmp(launch.primary_key, "a&b=c#%+") && launch.kvm_port == 5900);
    for (uint32_t flags = 1; flags <= 3; ++flags) {
        uri.flags = flags;
        assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 443, &launch, &profile) == BC_PROTOCOL_ERROR);
    }
    uri.flags = 0; uri.port = 8443;
    assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 443, &launch, &profile) == BC_PROTOCOL_ERROR);
    assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 8443, &launch, &profile) == BC_OK);
    uri.port = 0; uri.host = string("other.example");
    assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 443, &launch, &profile) == BC_PROTOCOL_ERROR);
    uri.host = string("bmc.example"); uri.scheme = string("http");
    assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 443, &launch, &profile) == BC_UNSUPPORTED);
    uri.scheme = string("https"); uri.path = string("/JavaViewer.jnlp");
    assert(bc_idrac_kvm_discover_launch(&uri, string("bmc.example"), 443, &launch, &profile) == BC_UNSUPPORTED);
    uri.path = string("/restgui/vconsole/index.html"); uri.host = string("2001:db8::1");
    uri.query = string("ip=2001%3Adb8%3A%3A1&kvmport=443&VCSID=a&VCSID2=b");
    assert(bc_idrac_kvm_discover_launch(&uri, uri.host, 443, &launch, &profile) == BC_OK);
    char query[800];
    memset(query, 'a', sizeof(query));
    int prefix = snprintf(query, sizeof(query), "ip=2001%%3Adb8%%3A%%3A1&kvmport=443&VCSID2=b&VCSID=");
    memset(query + prefix, 'a', 256); query[prefix + 256] = 0; uri.query = string(query);
    assert(bc_idrac_kvm_discover_launch(&uri, uri.host, 443, &launch, &profile) == BC_OK);
    query[prefix + 256] = 'a'; query[prefix + 257] = 0; uri.query = string(query);
    assert(bc_idrac_kvm_discover_launch(&uri, uri.host, 443, &launch, &profile) != BC_OK);
    assert(!launch.primary_key[0] && !profile.evidence);
    uri.query = (bc_string){fixture, 8193};
    assert(bc_idrac_kvm_discover_launch(&uri, uri.host, 443, &launch, &profile) == BC_LIMIT_EXCEEDED);
}

static void console_authentication(void) {
    bc_idrac_console_auth *auth = NULL;
    assert(bc_idrac_console_auth_create(string("fixture-secondary"), &auth) == BC_OK);
    uint8_t out[266]; uint32_t written = 0;
    assert(!bc_idrac_console_auth_key_get(auth).length);
    const uint8_t banner[] = "RFB 003.008\n";
    assert(bc_idrac_console_auth_feed_message(auth, banner, 12) == BC_OK);
    assert(bc_idrac_console_auth_output(auth, out, sizeof(out), &written) == BC_OK && !written);
    const uint8_t challenge[] = {247, 179};
    assert(bc_idrac_console_auth_feed_message(auth, challenge, sizeof(challenge)) == BC_OK);
    assert(bc_idrac_console_auth_output(auth, out, 2, &written) == BC_LIMIT_EXCEEDED && !written);
    assert(bc_idrac_console_auth_output(auth, out, sizeof(out), &written) == BC_OK);
    assert(written == strlen("fixture-secondary") + 10 && out[0] == 247 && out[1] == 179);
    assert(!memcmp(out + 2, "fixture-secondary", strlen("fixture-secondary")));
    for (uint32_t i = written - 8; i < written; ++i) assert(!out[i]);
    uint8_t clients[365] = {247, 172};
    memcpy(clients + 6, "123456789012345678901234ABCDEFGH", 32);
    assert(bc_idrac_console_auth_feed_message(auth, clients, sizeof(clients)) == BC_OK);
    bc_string key = bc_idrac_console_auth_key_get(auth);
    assert(key.length == 24 && !memcmp(key.data, clients + 6, 24));
    assert(bc_idrac_console_auth_close_session(auth) == BC_OK);
    assert(!bc_idrac_console_auth_key_get(auth).length);
    assert(bc_idrac_console_auth_output(auth, out, sizeof(out), &written) == BC_OK && written == 3);
    assert(out[0] == 247 && out[1] == 0 && out[2] == 249);
    assert(bc_idrac_console_auth_close_session(auth) == BC_OK);
    assert(bc_idrac_console_auth_output(auth, out, sizeof(out), &written) == BC_OK && !written);
    bc_idrac_console_auth_destroy(auth);

    for (unsigned mode = 0; mode < 5; ++mode) {
        assert(bc_idrac_console_auth_create(string("fixture"), &auth) == BC_OK);
        if (mode) {
            assert(bc_idrac_console_auth_feed_message(auth, challenge, sizeof(challenge)) == BC_OK);
            assert(bc_idrac_console_auth_output(auth, out, sizeof(out), &written) == BC_OK);
        }
        const uint8_t denied[] = {247, 169, 8}, busy[] = {247, 164};
        const uint8_t *message = mode == 3 ? denied : mode == 4 ? busy : clients;
        uint32_t size = mode == 1 ? 10 : mode == 3 ? sizeof(denied) : mode == 4 ? sizeof(busy) : sizeof(clients);
        if (mode == 2) clients[6] = 1;
        bc_status expected = mode == 3 ? BC_AUTHENTICATION_FAILED : mode == 4 ? BC_BUSY : BC_PROTOCOL_ERROR;
        assert(bc_idrac_console_auth_feed_message(auth, message, size) == expected);
        const bc_console_failure *detail = bc_idrac_console_auth_failure_get(auth);
        assert(detail && detail->service == BC_SERVICE_KVM && detail->family == BC_SERVICE_FAMILY_IDRAC);
        if (mode == 3) assert(detail->cause == BC_CONSOLE_CAUSE_SESSION_REJECTED);
        if (mode == 4) assert(detail->cause == BC_CONSOLE_CAUSE_BUSY);
        assert(!bc_idrac_console_auth_key_get(auth).length);
        assert(bc_idrac_console_auth_feed_message(auth, challenge, sizeof(challenge)) == expected);
        bc_idrac_console_auth_destroy(auth); clients[6] = '1';
    }
}
int main(void) {
    uint8_t key_packet[8], pointer_packet[6];
    const uint8_t expected_key[8] = {246, 1, 0, 3, 0x01, 0x02, 0x03, 0x04};
    const uint8_t expected_pointer[6] = {5, 4, 0x01, 0x23, 0x02, 0x34};
    assert(bc_idrac_kvm_key_encode(1, 0x01020304, 3, key_packet, sizeof(key_packet)) == BC_OK);
    assert(!memcmp(key_packet, expected_key, sizeof(key_packet)));
    assert(bc_idrac_kvm_key_encode(1, 1, 0, key_packet, 7) == BC_LIMIT_EXCEEDED);
    assert(bc_kvm_pointer_encode(4, 0x123, 0x234, 1920, 1200, pointer_packet, sizeof(pointer_packet)) == BC_OK);
    assert(!memcmp(pointer_packet, expected_pointer, sizeof(pointer_packet)));
    assert(bc_kvm_pointer_encode(0, 1920, 0, 1920, 1200, pointer_packet, sizeof(pointer_packet)) == BC_INVALID_ARGUMENT);

    console_authentication();
    const char *plugins[] = {"\"eHTML5\"", "3", "\"3\"", "\"HTML5\"", "2", "\"Java\"", "null"};
    for (size_t i = 0; i < sizeof(plugins) / sizeof(plugins[0]); ++i) {
        char json[256]; bc_service_profile hint;
        int length = snprintf(json, sizeof(json), "{\"@odata.type\":\"#DellAttributes.v1_0_0.DellAttributes\","
            "\"Attributes\":{\"VirtualConsole.1.PluginType\":%s}}", plugins[i]);
        bc_status status = bc_idrac_kvm_discover_attributes((const uint8_t *)json, (uint32_t)length, &hint);
        assert(status == (i < 3 ? BC_OK : BC_UNSUPPORTED));
        assert(!bc_service_profile_can_attempt(&hint, BC_SERVICE_KVM));
        if (i < 3) assert(hint.evidence == BC_SERVICE_EVIDENCE_HINT && hint.family == BC_SERVICE_FAMILY_IDRAC);
        else assert(!hint.evidence && !hint.variant);
    }
    const char *bad_attributes[] = {
        "{\"@odata.type\":\"#DellAttributes.v1_0_0.DellAttributes\",\"Attributes\":{}}",
        "{\"@odata.type\":\"#DellAttributes.v9_0_0.DellAttributes\",\"Attributes\":{\"VirtualConsole.1.PluginType\":3}}",
        "{\"@odata.type\":\"#DellAttributes.v1_0_0.DellAttributes\",\"Attributes\":{\"VirtualConsole.1.PluginType\":3,\"VirtualConsole.1.PluginType\":2}}",
        "{\"@odata.type\":\"#DellAttributes.v1_0_0.DellAttributes\",\"Attributes\":{},\"Attributes\":{\"VirtualConsole.1.PluginType\":3}}"
    };
    for (size_t i = 0; i < sizeof(bad_attributes) / sizeof(bad_attributes[0]); ++i) {
        bc_service_profile hint;
        assert(bc_idrac_kvm_discover_attributes((const uint8_t *)bad_attributes[i],
            (uint32_t)strlen(bad_attributes[i]), &hint) != BC_OK && !hint.evidence);
    }
    launch_location();
    discover_launch();
    uint8_t pixels[4];
    bc_idrac_kvm *generic = create(pixels);
    handshake(generic);
    key_chord(generic);
    assert(!bc_service_profile_verified(bc_idrac_kvm_profile_get(generic), BC_SERVICE_KVM));
    bc_idrac_kvm_destroy(generic);

    bc_idrac_kvm *client = create(pixels);
    const uint8_t challenge[] = {247, 179};
    assert(bc_idrac_kvm_feed_message(client, challenge, sizeof(challenge)) == BC_OK);
    assert(bc_service_profile_can_attempt(bc_idrac_kvm_profile_get(client), BC_SERVICE_KVM));
    assert(!bc_service_profile_verified(bc_idrac_kvm_profile_get(client), BC_SERVICE_KVM));
    handshake(client);
    assert(bc_service_profile_verified(bc_idrac_kvm_profile_get(client), BC_SERVICE_KVM));
    assert(!bc_service_profile_can_attempt(bc_idrac_kvm_profile_get(client), BC_SERVICE_LOCAL_MEDIA));
    session_capture captured={0}; captured.leds=2;
    bc_console_session *session=NULL;
    assert(bc_idrac_session_wrap(client,capture,snapshot,&captured,&session)==BC_OK);
    bc_console_info info={0}; info.struct_size=sizeof(info);
    assert(bc_console_session_info_get(session,&info)==BC_OK);
    assert((info.flags & BC_CONSOLE_INFO_READY) && !(info.flags & BC_CONSOLE_INFO_LEDS_VALID));
    const uint8_t leds[]={247,178,3};
    assert(bc_console_session_feed(session,0,leds,sizeof(leds))==BC_OK);
    assert(bc_console_session_info_get(session,&info)==BC_OK);
    assert((info.flags & BC_CONSOLE_INFO_LEDS_VALID) && info.keyboard_leds==3);

    bc_console_input event={0}; event.struct_size=sizeof(event); event.type=BC_CONSOLE_INPUT_KEY;
    event.keysym='a'; event.down=1;
    assert(bc_console_session_input(session,&event)==BC_OK);
    uint8_t expected[8];
    assert(bc_idrac_kvm_key_encode(1,'a',2,expected,sizeof(expected))==BC_OK);
    assert(captured.count==1 && !memcmp(expected,captured.bytes[0],8));
    captured.count=0; event.type=BC_CONSOLE_INPUT_SCROLL; event.width=event.height=1;
    event.buttons=4; event.wheel=-1;
    assert(bc_console_session_input(session,&event)==BC_OK);
    assert(captured.count==2 && captured.bytes[0][1]==18 && captured.bytes[1][1]==2);
    bc_console_session_destroy(session);
    const uint8_t denied[] = {247, 169, 8};
    assert(bc_idrac_kvm_feed_message(client, denied, sizeof(denied)) == BC_AUTHENTICATION_FAILED);
    const bc_console_failure *failure = bc_idrac_kvm_failure_get(client);
    assert(failure && failure->device_code == 8 && failure->cause == BC_CONSOLE_CAUSE_SESSION_REJECTED);
    assert(failure->service == BC_SERVICE_KVM && failure->family == BC_SERVICE_FAMILY_IDRAC);
    bc_console_retry_budget budget = {sizeof(budget), 0, 0};
    assert(bc_console_recovery(failure, 1, 0, &budget) == BC_CONSOLE_RECOVERY_REFRESH_TICKET);
    bc_idrac_kvm_destroy(client);
    return 0;
}

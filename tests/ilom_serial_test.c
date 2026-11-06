#include "../adapters/ilom/serial.c"
#include "../adapters/ilom/profile.c"
#include <assert.h>

static uint8_t incoming[128], outgoing[128];
static uint32_t available, consumed, sent, fragment;
static const bc_socks5_proxy *seen_proxy;
bc_status bc_kvm_transport_connect_proxy(const bc_kvm_transport_options *o, const bc_socks5_proxy *proxy, bc_kvm_transport **out) {
    seen_proxy=proxy; assert(!o->username.length && !o->password.length); *out = NULL; return BC_UNSUPPORTED;
}
bc_status bc_kvm_transport_recv(bc_kvm_transport *t, uint8_t *out, uint32_t capacity, uint32_t *n, uint32_t timeout) {
    (void)t; (void)timeout; *n = available - consumed;
    if (!*n) return BC_TIMEOUT;
    if (*n > capacity) *n = capacity;
    if (fragment && *n > fragment) *n = fragment;
    memcpy(out, incoming + consumed, *n); consumed += *n; return BC_OK;
}
bc_status bc_kvm_transport_send(bc_kvm_transport *t, const uint8_t *data, uint32_t length) {
    (void)t; assert(length <= sizeof(outgoing)); memcpy(outgoing, data, length); sent = length; return BC_OK;
}
void bc_kvm_transport_destroy(bc_kvm_transport *t) { (void)t; }
static void packet(uint16_t command, uint32_t length) {
    memset(incoming, 0, sizeof(incoming)); memcpy(incoming, "REDIRECT", 8);
    bc_wire_write_le(incoming + 8, 24, 2); bc_wire_write_le(incoming + 10, length, 4);
    bc_wire_write_le(incoming + 14, command, 2); available = 24 + length; consumed = 0;
}
int main(void) {
    bc_kvm_transport_options options={0};
    options.struct_size=sizeof(options); options.abi_version=BC_ABI_VERSION;
    options.url=(bc_string){"tls://bmc:5556",14};
    options.username=(bc_string){"user",4}; options.password=(bc_string){"secret",6};
    bc_string serial_url={"tcp://bmc:7579",14};
    bc_socks5_proxy proxy={sizeof(proxy),{"proxy",5},{0},{0},1080};
    bc_ilom_serial *opened=NULL;
    assert(bc_ilom_serial_open_proxy(&options,serial_url,&proxy,&opened)==BC_UNSUPPORTED);
    assert(!opened && seen_proxy==&proxy);
    assert(bc_ilom_serial_open(&options,serial_url,&opened)==BC_UNSUPPORTED && !seen_proxy);

    uint8_t device[15] = {0}; device[6] = 42; device[9] = 1; device[10] = 0x47;
    assert(bc_ilom_ipmi_capabilities(device, sizeof(device)) ==
        (BC_IPMI_CAPABILITY_NO_GRAPHICAL_CONSOLE | BC_IPMI_CAPABILITY_ILOM_SERIAL_CANDIDATE));
    device[9] = 2;
    assert(bc_ilom_ipmi_capabilities(device, sizeof(device)) == BC_IPMI_CAPABILITY_ILOM_SERIAL_CANDIDATE);
    device[6] = 43;
    assert(bc_ilom_ipmi_capabilities(device, sizeof(device)) == 0);
    assert(bc_ilom_ipmi_capabilities(device, 10) == 0);
    assert(bc_ilom_serial_fallback_allowed(BC_UNSUPPORTED, 0x81));
    assert(bc_ilom_serial_fallback_allowed(BC_UNSUPPORTED, 0xc1));
    assert(!bc_ilom_serial_fallback_allowed(BC_TIMEOUT, 0));
    assert(!bc_ilom_serial_fallback_allowed(BC_AUTHENTICATION_FAILED, 0));
    assert(!bc_ilom_serial_fallback_allowed(BC_BUSY, 0x80));
    assert(!bc_ilom_serial_fallback_allowed(BC_UNSUPPORTED, 0xd4));
    uint8_t challenge[32], digest[16];
    for (unsigned i = 0; i < 32; ++i) challenge[i] = (uint8_t)i;
    const uint8_t des[16] = {0x92,0x39,0x50,0x13,0x42,0xfb,0x40,0xfe,0x5e,0x00,0x23,0x12,0x04,0xe2,0xf5,0x8b};
    const uint8_t md5[16] = {0x80,0x18,0x90,0x3f,0xb3,0xda,0x01,0x3f,0xa8,0x84,0x33,0xd5,0x13,0x86,0x75,0x56};
    const uint8_t encrypted[8] = {0x7e,0x6a,0x68,0xb1,0x7e,0x7a,0x4e,0x95};
    assert(challenge_digest("fixture", (const uint8_t *)"\0\0", challenge, digest) == BC_OK);
    assert(!memcmp(digest, des, 16));
    assert(challenge_digest("fixture", (const uint8_t *)"$1$A17c6z5w$", challenge, digest) == BC_OK);
    assert(!memcmp(digest, md5, 16));
    bc_ilom_serial session = {0}; session.started = 1;
    BF_set_key(&session.key, sizeof(digest), digest);
    uint8_t byte = 'A', out[32]; uint32_t count, accepted;
    bc_serial_stream *stream = NULL;
    assert(bc_ilom_serial_stream(&session, &stream) == BC_OK);
    bc_serial_info info = {0}; info.struct_size = sizeof(info);
    assert(bc_serial_info_get(stream, &info) == BC_OK && !(info.capabilities & BC_SERIAL_WRITE));
    assert(bc_serial_control(stream, BC_SERIAL_CONTROL_BREAK) == BC_UNSUPPORTED);
    assert(bc_serial_write(stream, (bc_bytes){&byte, 1}, &accepted) == BC_BUSY);
    packet(22, 21); incoming[24] = 1; fragment = 3;
    assert(bc_serial_read(stream, 0, 1, out, sizeof(out), &count) == BC_OK);
    assert(bc_serial_info_get(stream, &info) == BC_OK && (info.capabilities & BC_SERIAL_WRITE));
    assert(bc_serial_write(stream, (bc_bytes){&byte, 1}, &accepted) == BC_OK);
    assert(accepted == 1);
    assert(sent == 33 && outgoing[21] == 1 && outgoing[24] == 1 && !memcmp(outgoing + 25, encrypted, 8));
    packet(19, 9); bc_wire_write_le(incoming + 24, 3, 4); memcpy(incoming + 30, "abc", 3);
    available = 13;
    assert(bc_serial_read(stream, 0, 1, out, sizeof(out), &count) == BC_TIMEOUT);
    available = 33;
    assert(bc_serial_read(stream, 0, 1, out, sizeof(out), &count) == BC_OK);
    assert(count == 3 && !memcmp(out, "abc", 3));
    packet(22, 21); incoming[24] = 2;
    assert(bc_serial_read(stream, 0, 1, out, sizeof(out), &count) == BC_OK);
    assert(!bc_ilom_serial_writable(&session) && bc_serial_write(stream, (bc_bytes){&byte, 1}, &accepted) == BC_BUSY);
    packet(6, 4); incoming[8] = 0; incoming[9] = 24; incoming[10] = 0; incoming[13] = 4;
    uint16_t cmd; uint8_t *data;
    assert(receive_packet(&session, &cmd, &data, &count, 1) == BC_OK && cmd == 6 && count == 4);
    packet(19, 0); bc_wire_write_le(incoming + 10, 65537, 4);
    assert(bc_serial_read(stream, 0, 1, out, sizeof(out), &count) == BC_LIMIT_EXCEEDED);
    assert(bc_serial_close(stream) == BC_OK);
    assert(bc_serial_info_get(stream, &info) == BC_OK && info.state == BC_SERIAL_CLOSED);
    assert(bc_serial_write(stream, (bc_bytes){&byte, 1}, &accepted) == BC_SHUTTING_DOWN && accepted == 0);
    bc_serial_destroy(stream);
    return 0;
}

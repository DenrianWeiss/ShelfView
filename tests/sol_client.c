#include "bcontrol/ipmi_platform.h"
#include "bcontrol/ipmi_sol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(int argc, char **argv) {
    CHECK(argc == 3);
    const char *mode = argv[2];
    bc_ipmi_io *io = NULL; bc_ipmi_crypto *crypto = NULL; bc_ipmi_session *session = NULL;
    CHECK(bc_ipmi_udp_create((bc_string){"127.0.0.1", 9}, (uint16_t)atoi(argv[1]), &io) == BC_OK);
    CHECK(bc_ipmi_openssl_crypto_create(&crypto) == BC_OK);
    bc_ipmi_session_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.io = io; options.crypto = crypto; options.timeout_ms = 150;
    options.username = (bc_string){"admin", 5}; options.password = (bc_string){"test-password", 13};
    CHECK(bc_ipmi_session_create(&options, &session) == BC_OK);
    CHECK(bc_ipmi_session_open(session) == BC_OK);
    bc_ipmi_sol_options settings = {0};
    settings.struct_size = sizeof(settings); settings.abi_version = BC_ABI_VERSION;
    settings.session_port = (uint16_t)atoi(argv[1]);
    settings.receive_capacity = !strcmp(mode, "burst") ? 8192 : 255;
    settings.send_capacity = 16; settings.retry_interval_ms = 40; settings.retries = 2; settings.keepalive_ms = 400;
    bc_ipmi_sol *sol = NULL; uint64_t now = 0;
    bc_status status = bc_ipmi_sol_open(session, &settings, now, &sol);
    CHECK(sol);
    bc_ipmi_sol_info info = {0}; info.struct_size = sizeof(info);
    if (!strcmp(mode, "busy")) CHECK(status == BC_BUSY);
    else if (!strcmp(mode, "port")) CHECK(status == BC_UNSUPPORTED);
    else if (!strcmp(mode, "unsupported-version")) CHECK(status == BC_UNSUPPORTED);
    else if (!strcmp(mode, "unprotected")) CHECK(status == BC_PROTOCOL_ERROR);
    else if (!strcmp(mode, "lost-activate")) CHECK(status == BC_OUTCOME_UNKNOWN);
    else {
        CHECK(status == BC_OK);
        CHECK(bc_ipmi_session_close(session) == BC_BUSY);
        bc_ipmi_sol *second = NULL;
        CHECK(bc_ipmi_sol_open(session, &settings, now, &second) == BC_BUSY);
        bc_ipmi_sol_destroy(second);
        uint32_t accepted = 0;
        if (!strcmp(mode, "transfer") || !strcmp(mode, "partial-ack") || !strcmp(mode, "first-zero-ack") || !strcmp(mode, "zero-ack") || !strcmp(mode, "bad-ack") || !strcmp(mode, "no-ack")) {
            CHECK(bc_ipmi_sol_write(sol, (bc_bytes){(const uint8_t *)"abcdef", 6}, &accepted) == BC_OK && accepted == 6);
        }
        uint8_t output[16384]; uint32_t total = 0;
        unsigned limit = !strcmp(mode, "burst") ? 700 : 160;
        for (unsigned i = 0; i < limit; ++i) {
            now += 10; status = bc_ipmi_sol_poll(sol, now, 10);
            if (status != BC_OK) break;
            if (strcmp(mode, "backpressure") || i > 12) {
                uint32_t n = 0;
                CHECK(bc_ipmi_sol_read(sol, output + total, sizeof(output) - total, &n) == BC_OK);
                total += n;
                if (!strcmp(mode, "burst") && total == 20u * 252u) break;
            }
        }
        CHECK(bc_ipmi_sol_info_get(sol, &info) == BC_OK);
        if (!strcmp(mode, "owner")) CHECK(status == BC_CANCELLED);
        else if (!strcmp(mode, "bad-ack")) CHECK(status == BC_PROTOCOL_ERROR);
        else if (!strcmp(mode, "no-ack") || !strcmp(mode, "zero-ack")) CHECK(status == BC_OUTCOME_UNKNOWN);
        else {
            CHECK(status == BC_OK);
            if (!strcmp(mode, "transfer") || !strcmp(mode, "partial-ack")) CHECK(total == 6 && !memcmp(output, "hello!", 6) && !info.send_pending);
            if (!strcmp(mode, "first-zero-ack")) CHECK(!info.send_pending);
            if (!strcmp(mode, "backpressure")) {
                CHECK(total == 400);
                for (unsigned i = 0; i < total; ++i) CHECK(output[i] == (i < 200 ? 'a' : 'b'));
            }
            if (!strcmp(mode, "burst")) {
                /* Advertised outbound size is 255 but packets carry 256 bytes of
                 * SOL payload (iBMC behaviour); all bytes must stream in order. */
                CHECK(total == 20u * 252u);
                CHECK(info.state == BC_IPMI_SOL_ACTIVE);
                for (unsigned i = 0; i < 20; ++i) {
                    for (unsigned j = 0; j < 252; ++j)
                        CHECK(output[i * 252 + j] == (uint8_t)((((i * 17 + j) % 251) + 1)));
                }
            }
        }
    }
    bc_ipmi_sol_close(sol);
    CHECK(bc_ipmi_sol_info_get(sol, &info) == BC_OK && info.cleanup_status == BC_OK);
    bc_ipmi_sol_destroy(sol);
    CHECK(bc_ipmi_session_close(session) == BC_OK);
    bc_ipmi_session_destroy(session); bc_ipmi_openssl_crypto_destroy(crypto); bc_ipmi_udp_destroy(io);
    return 0;
}

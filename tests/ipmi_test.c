#include "bcontrol/ipmi.h"
#include "bcontrol/ipmi_sensor.h"
#include "bcontrol/ipmi_sel.h"
#include "bcontrol/ipmi_fru.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static uint8_t checksum(const uint8_t *p, size_t n) {
    uint8_t sum = 0;
    while (n--) sum = (uint8_t)(sum + *p++);
    return (uint8_t)(0u - sum);
}
static size_t response_packet(uint8_t *out, const uint8_t *data, size_t length) {
    memset(out, 0, 16);
    out[0] = 0x06; out[1] = 0x00; out[2] = 0xff; out[3] = 0x07;
    out[4] = 0x06; out[5] = 0x00;
    size_t len = 16;
    out[len++] = 0x20; out[len++] = 0x07 << 2;
    out[len] = checksum(out + len - 2, 2); ++len;
    size_t message = len;
    out[len++] = 0x81; out[len++] = 0x00; out[len++] = 0x54; out[len++] = 0x00;
    memcpy(out + len, data, length); len += length;
    out[len] = checksum(out + message, len - message); ++len;
    uint16_t payload = (uint16_t)(len - 16);
    out[14] = (uint8_t)payload; out[15] = (uint8_t)(payload >> 8);
    return len;
}
static void sensor_record(uint8_t record[64], uint8_t analog_format, uint8_t linearization, int m, int b, int k1, int k2) {
    memset(record, 0, 64);
    record[2] = 0x51; record[3] = 0x01; record[4] = 59;
    uint8_t *d = record + 5;
    d[0] = 0x20; d[2] = 0x23; d[3] = 3; d[4] = 1;
    d[7] = 1; d[8] = 1;
    d[15] = (uint8_t)(analog_format << 6); d[16] = 1;
    d[18] = linearization;
    d[19] = (uint8_t)m; d[20] = (uint8_t)(((m >> 8) & 3) << 6);
    d[24] = (uint8_t)((k1 & 0x0f) | ((k2 & 0x0f) << 4));
    d[21] = (uint8_t)b; d[22] = (uint8_t)(((b >> 8) & 3) << 6);
    for (unsigned i = 31; i <= 36; ++i) d[i] = 0xFF;
    d[42] = 0xC3; memcpy(d + 43, "CPU", 3);
}
int main(void) {
    uint8_t packet[256];
    uint32_t length = 0;
    CHECK(bc_ipmi_cipher_suites_request(0x0e, 0, 0, packet, sizeof(packet), &length) == BC_OK);
    const uint8_t expected[] = {0x06, 0x00, 0xff, 0x07, 0x06, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x00,
                                0x20, 0x18, 0xc8, 0x81, 0x00, 0x54, 0x0e, 0x00, 0x80, 0x9d};
    CHECK(length == sizeof(expected) && !memcmp(packet, expected, sizeof(expected)));
    CHECK(bc_ipmi_cipher_suites_request(0x0e, 0, 0, packet, sizeof(expected) - 1, &length) == BC_LIMIT_EXCEEDED);

    const uint8_t records[] = {0x0e, 0xc0, 0x11, 0x03, 0x44, 0x81, 0xc0, 0x03, 0x01, 0x01, 0x01, 0xc1, 0x20, 0x00, 0x0a, 0x0b, 0x01, 0x02, 0x03};
    size_t size = response_packet(packet, records, sizeof(records));
    bc_ipmi_response response;
    CHECK(bc_ipmi_sessionless_decode(packet, size, &response) == BC_OK);
    CHECK(response.netfn == 0x07 && response.command == 0x54 && response.completion_code == 0 && response.data.length == sizeof(records));
    bc_ipmi_cipher_suites suites;
    CHECK(bc_ipmi_cipher_suites_parse(&response, &suites) == BC_OK);
    CHECK(suites.channel == 0x0e && suites.count == 3);
    CHECK(suites.suites[0].cipher_suite_id == 17 && suites.suites[0].auth_algorithm == 3 &&
          suites.suites[0].integrity_algorithm == 4 && suites.suites[0].confidentiality_algorithm == 1);
    CHECK(suites.suites[1].cipher_suite_id == 3 && suites.suites[1].confidentiality_algorithm == 1);
    CHECK(suites.suites[2].flags == BC_IPMI_CIPHER_SUITE_OEM && suites.suites[2].iana == 0x0b0a00);
    CHECK(bc_ipmi_standard_cipher_suite(17) && bc_ipmi_standard_cipher_suite(17)->integrity_algorithm == 4);
    CHECK(!bc_ipmi_standard_cipher_suite(18));

    bc_ipmi_suite_selection selected;
    CHECK(bc_ipmi_select_cipher_suite(&suites, BC_IPMI_SUITE3_DISALLOWED, &selected) == BC_OK && selected.cipher_suite_id == 17 && !selected.flags);
    bc_ipmi_cipher_suites fallback = {0};
    fallback.channel = 1;
    fallback.count = 1;
    fallback.suites[0] = suites.suites[1];
    CHECK(bc_ipmi_select_cipher_suite(&fallback, BC_IPMI_SUITE3_DISALLOWED, &selected) == BC_UNSUPPORTED);
    CHECK(bc_ipmi_select_cipher_suite(&fallback, BC_IPMI_SUITE3_ALLOWED, &selected) == BC_OK &&
          selected.cipher_suite_id == 3 && (selected.flags & BC_IPMI_SUITE_CONFIRMATION_REQUIRED));
    CHECK(bc_ipmi_select_cipher_suite(&fallback, BC_IPMI_SUITE3_CONFIRMED, &selected) == BC_OK && !selected.flags);
    fallback.suites[0].auth_algorithm = 2;
    CHECK(bc_ipmi_select_cipher_suite(&fallback, BC_IPMI_SUITE3_CONFIRMED, &selected) == BC_PROTOCOL_ERROR);

    packet[size - 1] ^= 0x40;
    CHECK(bc_ipmi_sessionless_decode(packet, size, &response) == BC_PROTOCOL_ERROR);
    CHECK(bc_ipmi_sessionless_decode(packet, size - 1, &response) == BC_PROTOCOL_ERROR);
    bc_ipmi_packet raw;
    CHECK(bc_ipmi_packet_decode(packet, size - 1, &raw) == BC_PROTOCOL_ERROR);
    const uint8_t bad_tag[] = {0x0e, 0xc2};
    size = response_packet(packet, bad_tag, sizeof(bad_tag));
    CHECK(bc_ipmi_sessionless_decode(packet, size, &response) == BC_OK);
    CHECK(bc_ipmi_cipher_suites_parse(&response, &suites) == BC_PROTOCOL_ERROR);

    bc_ipmi_open_session_request open = {0};
    open.message_tag = 7; open.maximum_privilege = BC_IPMI_PRIVILEGE_ADMINISTRATOR;
    open.console_session_id = 0xA0A2A3A4;
    open.auth_algorithm = 3; open.integrity_algorithm = 4; open.confidentiality_algorithm = 1;
    static const uint8_t expected_open[] = {7, 4, 0, 0, 0xa4, 0xa3, 0xa2, 0xa0, 0, 0, 0, 8, 3, 0, 0, 0,
        1, 0, 0, 8, 4, 0, 0, 0, 2, 0, 0, 8, 1, 0, 0, 0};
    CHECK(bc_ipmi_open_session_request_encode(&open, packet, sizeof(expected_open)) == BC_OK &&
          !memcmp(packet, expected_open, sizeof(expected_open)));
    memcpy(packet, expected_open, sizeof(expected_open));
    bc_ipmi_open_session_response session;
    const uint8_t session_response[] = {7, 0, 4, 0, 0xa4, 0xa3, 0xa2, 0xa0, 0x44, 0x33, 0x22, 0x11,
        0, 0, 0, 8, 3, 0, 0, 0, 1, 0, 0, 8, 4, 0, 0, 0, 2, 0, 0, 8, 1, 0, 0, 0};
    CHECK(bc_ipmi_open_session_response_decode(session_response, 32, &session) == BC_PROTOCOL_ERROR);
    CHECK(bc_ipmi_open_session_response_decode(session_response, sizeof(session_response), &session) == BC_OK);
    CHECK(session.status == 0 && session.maximum_privilege == 4 && session.console_session_id == 0xA0A2A3A4 &&
          session.bmc_session_id == 0x11223344 && session.auth_algorithm == 3 && session.integrity_algorithm == 4 &&
          session.confidentiality_algorithm == 1);
    memcpy(packet, session_response, sizeof(session_response));
    packet[12] = 5;
    CHECK(bc_ipmi_open_session_response_decode(packet, sizeof(session_response), &session) == BC_PROTOCOL_ERROR);
    memcpy(packet, session_response, sizeof(session_response));
    packet[1] = 4;
    CHECK(bc_ipmi_open_session_response_decode(packet, 8, &session) == BC_OK && session.status == 4);

    uint8_t random[16], guid[16], auth_code[32];
    for (unsigned i = 0; i < 16; ++i) { random[i] = (uint8_t)i; guid[i] = (uint8_t)(0x20 + i); }
    for (unsigned i = 0; i < 32; ++i) auth_code[i] = (uint8_t)(0x30 + i);
    bc_ipmi_rakp1 rakp1 = {0};
    rakp1.message_tag = 9; rakp1.bmc_session_id = 0x11223344; rakp1.requested_privilege = 4;
    rakp1.console_random = random; rakp1.user_name = (bc_string){"admin", 5};
    uint64_t written = 0;
    CHECK(bc_ipmi_rakp1_encode(&rakp1, packet, sizeof(packet), &written) == BC_OK && written == 33);
    CHECK(packet[0] == 9 && packet[4] == 0x44 && packet[24] == 4 && packet[27] == 5 && !memcmp(packet + 28, "admin", 5));
    rakp1.user_name = (bc_string){"0123456789abcdefg", 17};
    CHECK(bc_ipmi_rakp1_encode(&rakp1, packet, sizeof(packet), &written) == BC_INVALID_ARGUMENT);

    memset(packet, 0, 72);
    packet[0] = 1; packet[4] = 0xa4; packet[5] = 0xa3; packet[6] = 0xa2; packet[7] = 0xa0;
    memcpy(packet + 8, random, 16); memcpy(packet + 24, guid, 16); memcpy(packet + 40, auth_code, 32);
    bc_ipmi_rakp2 rakp2;
    CHECK(bc_ipmi_rakp2_decode(packet, 72, BC_IPMI_AUTH_ALG_HMAC_SHA256, &rakp2) == BC_OK);
    CHECK(rakp2.console_session_id == 0xA0A2A3A4 && rakp2.bmc_random.length == 16 && rakp2.bmc_guid.length == 16 && rakp2.auth_code.length == 32);
    CHECK(rakp2.auth_code.data[31] == auth_code[31] && bc_ipmi_auth_code_size(BC_IPMI_AUTH_ALG_HMAC_SHA1) == 20);
    CHECK(bc_ipmi_rakp2_decode(packet, 72, 9, &rakp2) == BC_UNSUPPORTED);

    bc_ipmi_rakp3 rakp3 = {0};
    rakp3.message_tag = 2; rakp3.bmc_session_id = 0x55667788; rakp3.auth_algorithm = BC_IPMI_AUTH_ALG_HMAC_SHA1;
    rakp3.auth_code = (bc_bytes){auth_code, 20};
    CHECK(bc_ipmi_rakp3_encode(&rakp3, packet, sizeof(packet), &written) == BC_OK && written == 28);
    CHECK(packet[0] == 2 && packet[4] == 0x88 && packet[8] == auth_code[0]);
    rakp3.auth_code = (bc_bytes){auth_code, 16};
    CHECK(bc_ipmi_rakp3_encode(&rakp3, packet, sizeof(packet), &written) == BC_INVALID_ARGUMENT);

    memset(packet, 0, 20);
    packet[0] = 3; packet[4] = 0xa4; packet[5] = 0xa3; packet[6] = 0xa2; packet[7] = 0xa0;
    memcpy(packet + 8, auth_code, 12);
    bc_ipmi_rakp4 rakp4;
    CHECK(bc_ipmi_rakp4_decode(packet, 20, BC_IPMI_INTEGRITY_ALG_HMAC_SHA1_96, &rakp4) == BC_OK &&
          rakp4.integrity_check_value.length == 12 && rakp4.console_session_id == 0xA0A2A3A4);
    CHECK(bc_ipmi_rakp4_decode(packet, 20, BC_IPMI_INTEGRITY_ALG_HMAC_SHA256_128, &rakp4) == BC_PROTOCOL_ERROR);
    uint8_t record[64], short_record[12] = {0x10, 0, 0x51, 0x01, 59};
    bc_ipmi_sensor_record sensor;
    sensor_record(record, 0, 0, 1, 0, 0, 0);
    record[5 + 33] = 80;
    CHECK(bc_ipmi_sdr_parse_record(record, sizeof(record), &sensor) == BC_OK);
    CHECK(sensor.sensor_number == 0x23 && sensor.sensor_type == 1 && sensor.unit_base == 1 && sensor.m == 1 && sensor.b == 0);
    CHECK(sensor.id_length == 3 && !memcmp(sensor.id, "CPU", 3));
    CHECK((sensor.threshold_mask & (1u << BC_IPMI_THRESHOLD_UPPER_NON_CRITICAL)) &&
          sensor.threshold_values[BC_IPMI_THRESHOLD_UPPER_NON_CRITICAL] == 80.0);
    record[4] = 46;
    CHECK(bc_ipmi_sdr_parse_record(record, 51, &sensor) == BC_OK);
    record[4] = 59;
    double value = 0;
    CHECK(bc_ipmi_sensor_convert(&sensor, 25, &value) == BC_OK && value == 25.0);
    sensor_record(record, 2, 0, 1, 0, 0, 0);
    CHECK(bc_ipmi_sdr_parse_record(record, sizeof(record), &sensor) == BC_OK);
    CHECK(bc_ipmi_sensor_convert(&sensor, 0xf6, &value) == BC_OK && value == -10.0);
    sensor_record(record, 0, 2, 1, 0, 0, 0);
    CHECK(bc_ipmi_sdr_parse_record(record, sizeof(record), &sensor) == BC_OK);
    CHECK(bc_ipmi_sensor_convert(&sensor, 100, &value) == BC_OK && value == 2.0);
    sensor_record(record, 0, 0, 2, 3, 0, -1);
    CHECK(bc_ipmi_sdr_parse_record(record, sizeof(record), &sensor) == BC_OK);
    CHECK(bc_ipmi_sensor_convert(&sensor, 10, &value) == BC_OK && value > 2.29 && value < 2.31);
    CHECK(bc_ipmi_sdr_parse_record(short_record, sizeof(short_record), &sensor) == BC_PROTOCOL_ERROR);
    bc_ipmi_sensor_descriptor descriptor = {0}; descriptor.struct_size = sizeof(descriptor); descriptor.abi_version = BC_ABI_VERSION;
    uint8_t compact[34] = {1, 0, 0x51, 2, 29};
    compact[5] = 0x20; compact[7] = 40; compact[9] = 0x81;
    compact[12] = 8; compact[13] = 0x6f; compact[18] = 0xff; compact[19] = 0x7f;
    compact[20] = 0x08; compact[21] = 4;
    compact[23] = 0x13; compact[24] = 0x99; compact[31] = 0xc2; compact[32] = 'P'; compact[33] = 'S';
    CHECK(bc_ipmi_sdr_sensor_parse((bc_bytes){compact, sizeof(compact)}, 1, &descriptor) == BC_OK);
    CHECK(descriptor.share_count == 3 && descriptor.share_index == 1 && descriptor.sensor.sensor_number == 41);
    CHECK(descriptor.sensor.entity_instance == 0x82 && !strcmp(descriptor.name, "PSAA"));
    CHECK(descriptor.sensor.unit_rate == 1 && descriptor.sensor.unit_base == 4);
    compact[7] = 254;
    CHECK(bc_ipmi_sdr_sensor_parse((bc_bytes){compact, sizeof(compact)}, 0, &descriptor) == BC_PROTOCOL_ERROR);
    compact[7] = 40; compact[31] = 0xd0;
    CHECK(bc_ipmi_sdr_sensor_parse((bc_bytes){compact, sizeof(compact)}, 0, &descriptor) == BC_PROTOCOL_ERROR);
    const uint8_t boot_response[7] = {1, 5, 0, 0, 0, 0, 0};
    bc_ipmi_boot_info boot;
    uint8_t boot_request[6];
    CHECK(bc_ipmi_boot_flags_parse(boot_response, sizeof(boot_response), &boot) == BC_OK);
    CHECK(bc_ipmi_boot_flags_build(&boot, BC_BOOT_CD, BC_BOOT_MODE_PRESERVE, boot_request) == BC_CONFIRMATION_REQUIRED);
    CHECK(bc_ipmi_boot_flags_build(&boot, BC_BOOT_CD, BC_BOOT_MODE_UEFI, boot_request) == BC_OK);
    CHECK(boot_request[0] == 5 && boot_request[1] == 0xa0 && boot_request[2] == 0x14);
    CHECK(bc_ipmi_boot_flags_build(&boot, BC_BOOT_USB, BC_BOOT_MODE_UEFI, boot_request) == BC_UNSUPPORTED);
    uint8_t existing_boot[7] = {1, 5, 0xe0, 0xc3, 0x81, 0x42, 0x11};
    CHECK(bc_ipmi_boot_flags_parse(existing_boot, sizeof(existing_boot), &boot) == BC_OK);
    CHECK(bc_ipmi_boot_flags_build(&boot, BC_BOOT_PXE, BC_BOOT_MODE_PRESERVE, boot_request) == BC_OK);
    CHECK(boot_request[1] == 0xa0 && boot_request[2] == 0xc7 && boot_request[3] == 0x81 && boot_request[4] == 0x42 && boot_request[5] == 0x11);
    CHECK(bc_ipmi_boot_flags_build(&boot, BC_BOOT_NONE, BC_BOOT_MODE_PRESERVE, boot_request) == BC_OK && boot_request[1] == 0x60);
    existing_boot[1] |= 0x80;
    CHECK(bc_ipmi_boot_flags_parse(existing_boot, sizeof(existing_boot), &boot) == BC_OK);
    CHECK(bc_ipmi_boot_flags_build(&boot, BC_BOOT_CD, BC_BOOT_MODE_UEFI, boot_request) == BC_BUSY);

    const uint8_t sel_info_response[14] = {0x51, 0x03, 0x00, 0xe0, 0x2e, 0x78, 0x56, 0x34, 0x12,
        0xbc, 0x9a, 0x78, 0x56, 0x42};
    bc_ipmi_sel_info sel_info = {0};
    sel_info.struct_size = sizeof(sel_info); sel_info.abi_version = BC_ABI_VERSION;
    CHECK(bc_ipmi_sel_info_parse((bc_bytes){sel_info_response, sizeof(sel_info_response)}, &sel_info) == BC_OK);
    CHECK(sel_info.version == 0x51 && sel_info.record_count == 3 && sel_info.free_space == 0x2ee0);
    CHECK(sel_info.addition_timestamp == 0x12345678 && sel_info.erase_timestamp == 0x56789abc);
    CHECK(sel_info.reserve_supported && sel_info.overflow && sel_info.operation_support == 0x42);
    CHECK(bc_ipmi_sel_info_parse((bc_bytes){sel_info_response, 13}, &sel_info) == BC_PROTOCOL_ERROR);
    const uint8_t sel_info_bad_version[14] = {0x52};
    CHECK(bc_ipmi_sel_info_parse((bc_bytes){sel_info_bad_version, sizeof(sel_info_bad_version)}, &sel_info) == BC_PROTOCOL_ERROR);
    sel_info.struct_size = 0;
    CHECK(bc_ipmi_sel_info_parse((bc_bytes){sel_info_response, sizeof(sel_info_response)}, &sel_info) == BC_INVALID_ARGUMENT);

    uint8_t sel_record[16] = {0x34, 0x12, 0x02, 0x78, 0x56, 0x34, 0x20, 0x04, 0x01, 0x69,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    bc_ipmi_sel_entry sel_entry = {0};
    sel_entry.struct_size = sizeof(sel_entry); sel_entry.abi_version = BC_ABI_VERSION;
    CHECK(bc_ipmi_sel_entry_parse((bc_bytes){sel_record, sizeof(sel_record)}, &sel_entry) == BC_OK);
    CHECK(sel_entry.record_id == 0x1234 && sel_entry.record_type == 0x02);
    CHECK((sel_entry.flags & BC_IPMI_SEL_ENTRY_TIMESTAMP_PRESENT) && sel_entry.timestamp == 0x345678);
    CHECK(sel_entry.raw_length == 16 && !memcmp(sel_entry.raw, sel_record, 16) && sel_entry.status == BC_OK);
    sel_record[2] = 0xc0;
    CHECK(bc_ipmi_sel_entry_parse((bc_bytes){sel_record, sizeof(sel_record)}, &sel_entry) == BC_OK);
    CHECK(!(sel_entry.flags & BC_IPMI_SEL_ENTRY_TIMESTAMP_PRESENT) && sel_entry.timestamp == 0);
    sel_record[2] = 0xe1;
    CHECK(bc_ipmi_sel_entry_parse((bc_bytes){sel_record, sizeof(sel_record)}, &sel_entry) == BC_OK);
    CHECK((sel_entry.flags & BC_IPMI_SEL_ENTRY_TIMESTAMP_PRESENT) && sel_entry.timestamp == 0x345678);
    CHECK(bc_ipmi_sel_entry_parse((bc_bytes){sel_record, 10}, &sel_entry) == BC_PROTOCOL_ERROR);
    CHECK(sel_entry.status == BC_PROTOCOL_ERROR && sel_entry.raw_length == 10 && sel_entry.record_id == 0x1234);
    uint8_t sel_oversize[17] = {0};
    CHECK(bc_ipmi_sel_entry_parse((bc_bytes){sel_oversize, sizeof(sel_oversize)}, &sel_entry) == BC_LIMIT_EXCEEDED);
    CHECK(bc_ipmi_sel_entry_parse((bc_bytes){sel_record, 2}, &sel_entry) == BC_PROTOCOL_ERROR);
    CHECK(sel_entry.raw_length == 2 && sel_entry.record_type == 0);
    sel_entry.abi_version = 0;
    CHECK(bc_ipmi_sel_entry_parse((bc_bytes){sel_record, sizeof(sel_record)}, &sel_entry) == BC_INVALID_ARGUMENT);

    char fru_text[128];
    const uint8_t packed6[] = {0x29, 0xdc, 0xa6};
    CHECK(bc_ipmi_fru_text_decode(2, (bc_bytes){packed6, sizeof(packed6)}, 0, fru_text, sizeof(fru_text)) == BC_OK);
    CHECK(!strcmp(fru_text, "IPMI"));
    const uint8_t utf16le[] = {0x2d, 0x4e, 0x87, 0x65};
    CHECK(bc_ipmi_fru_text_decode(3, (bc_bytes){utf16le, sizeof(utf16le)}, 1, fru_text, sizeof(fru_text)) == BC_OK);
    CHECK(!strcmp(fru_text, "\xe4\xb8\xad\xe6\x96\x87"));
    const uint8_t bcd[] = {0x12, 0xab};
    CHECK(bc_ipmi_fru_text_decode(1, (bc_bytes){bcd, sizeof(bcd)}, 0, fru_text, sizeof(fru_text)) == BC_OK);
    CHECK(!strcmp(fru_text, "12 -"));
    const uint8_t bcd_reserved[] = {0xde};
    CHECK(bc_ipmi_fru_text_decode(1, (bc_bytes){bcd_reserved, sizeof(bcd_reserved)}, 0, fru_text, sizeof(fru_text)) == BC_PROTOCOL_ERROR);
    CHECK(bc_ipmi_fru_text_decode(0, (bc_bytes){bcd, sizeof(bcd)}, 0, fru_text, sizeof(fru_text)) == BC_UNSUPPORTED);
    CHECK(bc_ipmi_fru_text_decode(3, (bc_bytes){utf16le, 3}, 1, fru_text, sizeof(fru_text)) == BC_PROTOCOL_ERROR);
    CHECK(bc_ipmi_fru_text_decode(3, (bc_bytes){bcd, sizeof(bcd)}, 0, fru_text, 1) == BC_LIMIT_EXCEEDED);
    const uint8_t english[] = {'N', 'E', 'C'}, latin1[] = {'C', 'a', 'f', 0xe9};
    for (uint8_t language = 0; language <= 25; language += 25) {
        CHECK(bc_ipmi_fru_text_decode(3, (bc_bytes){english, sizeof(english)}, language, fru_text, sizeof(fru_text)) == BC_OK);
        CHECK(!strcmp(fru_text, "NEC"));
        CHECK(bc_ipmi_fru_text_decode(3, (bc_bytes){latin1, sizeof(latin1)}, language, fru_text, sizeof(fru_text)) == BC_OK);
        CHECK(!strcmp(fru_text, "Caf\xc3\xa9"));
        CHECK(bc_ipmi_fru_text_decode(3, (bc_bytes){latin1, sizeof(latin1)}, language, fru_text, 5) == BC_LIMIT_EXCEEDED);
    }

    uint8_t fru_image_buf[512];
    uint32_t fru_image_length = 0;
    const char *fru_hexes[] = {
        "01000000010600f8010500c441636d65c6536572766572c54d6f64656cc3312e30c453313233"
        "c441343536c0c10000a903020c46a901687474703a2f2f626d632fc08203fac1010203",
        "01000000010600f8010500c440636d65c6536572766572c54d6f64656cc3312e30c453313233"
        "c441343536c0c10000a903020c46a901687474703a2f2f626d632fc08203fac1010203",
    };
    bc_ipmi_fru_info fru = {0};
    fru.struct_size = sizeof(fru); fru.abi_version = BC_ABI_VERSION;
    for (unsigned h = 0; h < 2; ++h) {
        fru_image_length = 0;
        for (const char *p = fru_hexes[h]; p[0] && p[1]; p += 2) {
            unsigned byte = 0;
            CHECK(sscanf(p, "%2x", &byte) == 1);
            fru_image_buf[fru_image_length++] = (uint8_t)byte;
        }
        if (h == 0) {
            CHECK(bc_ipmi_fru_image_parse((bc_bytes){fru_image_buf, fru_image_length}, &fru) == BC_OK);
            CHECK(fru.header_version == 1 && fru.status == BC_OK);
            CHECK(fru.product.present && fru.product.status == BC_OK && fru.product.language == 0);
            CHECK(!strcmp(fru.product.manufacturer.text, "Acme") && !strcmp(fru.product.name.text, "Server"));
            CHECK(!strcmp(fru.product.part_number.text, "Model") && !strcmp(fru.product.version.text, "1.0"));
            CHECK(!strcmp(fru.product.serial.text, "S123") && !strcmp(fru.product.asset_tag.text, "A456"));
            CHECK(fru.product.file_id.status == BC_OK && fru.product.file_id.text[0] == 0 && fru.product.custom_count == 0);
            CHECK(!fru.chassis.present && !fru.board.present);
            CHECK(fru.multi_status == BC_UNSUPPORTED && fru.multi_length == 25 && fru.multi_raw[0] == 0x03);
        } else {
            CHECK(bc_ipmi_fru_image_parse((bc_bytes){fru_image_buf, fru_image_length}, &fru) == BC_PROTOCOL_ERROR);
            CHECK(fru.product.present && fru.product.status == BC_PROTOCOL_ERROR);
        }
    }
    const uint8_t fru_empty_header[] = {1, 0, 0, 0, 0, 0, 0, 0xff};
    CHECK(bc_ipmi_fru_image_parse((bc_bytes){fru_empty_header, sizeof(fru_empty_header)}, &fru) == BC_OK);
    CHECK(!fru.chassis.present && !fru.board.present && !fru.product.present && fru.multi_length == 0);
    uint8_t fru_bad_version[8] = {2, 0, 0, 0, 0, 0, 0, 0};
    fru_bad_version[7] = checksum(fru_bad_version, 7);
    CHECK(bc_ipmi_fru_image_parse((bc_bytes){fru_bad_version, sizeof(fru_bad_version)}, &fru) == BC_PROTOCOL_ERROR);
    fru_bad_version[0] = 1; fru_bad_version[2] = 1;
    fru_bad_version[7] = checksum(fru_bad_version, 7);
    CHECK(bc_ipmi_fru_image_parse((bc_bytes){fru_bad_version, sizeof(fru_bad_version)}, &fru) == BC_PROTOCOL_ERROR);
    CHECK(fru.chassis.present && fru.chassis.status == BC_PROTOCOL_ERROR);
    CHECK(bc_ipmi_fru_image_parse((bc_bytes){fru_empty_header, 4}, &fru) == BC_PROTOCOL_ERROR);
    CHECK(bc_ipmi_fru_image_parse((bc_bytes){fru_empty_header, sizeof(fru_empty_header)}, &(bc_ipmi_fru_info){0}) == BC_INVALID_ARGUMENT);

    puts("ipmi: sessionless framing, cipher suites, Open Session, RAKP, SDR, SEL and FRU decoding passed");
    return 0;
}

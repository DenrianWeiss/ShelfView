#include "huawei_kvm_internal.h"
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------------------------
 * SHA-1 / SHA-256 / HMAC / PBKDF2 (FIPS 180-4, RFC 2104, RFC 2898)
 * ------------------------------------------------------------------------------------------- */

static uint32_t rotl32(uint32_t value, uint32_t bits) { return (value << bits) | (value >> (32 - bits)); }
static uint32_t rotr32(uint32_t value, uint32_t bits) { return (value >> bits) | (value << (32 - bits)); }
static uint32_t read_be32(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
}
static void write_be32(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24); data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8); data[3] = (uint8_t)value;
}

static void sha1_compress(uint32_t state[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = read_be32(block + i * 4);
    for (int i = 16; i < 80; ++i) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
        uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void huawei_sha1(const uint8_t *data, size_t length, uint8_t out[20]) {
    uint32_t state[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    size_t total = length;
    while (length >= 64) { sha1_compress(state, data); data += 64; length -= 64; }
    uint8_t tail[128];
    memset(tail, 0, sizeof(tail));
    memcpy(tail, data, length);
    tail[length] = 0x80;
    size_t padded = length < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)total * 8;
    for (int i = 0; i < 8; ++i) tail[padded - 1 - i] = (uint8_t)(bits >> (i * 8));
    sha1_compress(state, tail);
    if (padded == 128) sha1_compress(state, tail + 64);
    for (int i = 0; i < 5; ++i) write_be32(out + i * 4, state[i]);
}

static const uint32_t sha256_k[64] = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
    0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu, 0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
    0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
    0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
    0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
    0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u, 0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u};

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = read_be32(block + i * 4);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void huawei_sha256(const uint8_t *data, size_t length, uint8_t out[32]) {
    uint32_t state[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                         0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
    size_t total = length;
    while (length >= 64) { sha256_compress(state, data); data += 64; length -= 64; }
    uint8_t tail[128];
    memset(tail, 0, sizeof(tail));
    memcpy(tail, data, length);
    tail[length] = 0x80;
    size_t padded = length < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)total * 8;
    for (int i = 0; i < 8; ++i) tail[padded - 1 - i] = (uint8_t)(bits >> (i * 8));
    sha256_compress(state, tail);
    if (padded == 128) sha256_compress(state, tail + 64);
    for (int i = 0; i < 8; ++i) write_be32(out + i * 4, state[i]);
}

void huawei_hmac(const uint8_t *key, size_t key_length, const uint8_t *data, size_t length, int sha256,
                 uint8_t out[32], uint32_t *out_length) {
    uint8_t block[64], inner[64], outer[64], digest[32];
    uint32_t digest_length = sha256 ? 32u : 20u;
    memset(block, 0, sizeof(block));
    if (key_length > sizeof(block)) {
        if (sha256) huawei_sha256(key, key_length, digest); else huawei_sha1(key, key_length, digest);
        memcpy(block, digest, digest_length);
    } else if (key_length) {
        memcpy(block, key, key_length);
    }
    for (int i = 0; i < 64; ++i) { inner[i] = block[i] ^ 0x36; outer[i] = block[i] ^ 0x5C; }
    size_t capacity = length > digest_length ? length : digest_length;
    if (capacity > SIZE_MAX - 64) { *out_length = 0; return; }
    uint8_t *combined = (uint8_t *)malloc(64 + capacity);
    if (!combined) { *out_length = 0; return; }
    memcpy(combined, inner, 64);
    if (length) memcpy(combined + 64, data, length);
    if (sha256) huawei_sha256(combined, 64 + length, digest); else huawei_sha1(combined, 64 + length, digest);
    memcpy(combined, outer, 64);
    memcpy(combined + 64, digest, digest_length);
    if (sha256) huawei_sha256(combined, 64 + digest_length, digest); else huawei_sha1(combined, 64 + digest_length, digest);
    free(combined);
    memcpy(out, digest, digest_length);
    *out_length = digest_length;
}

void huawei_swap_groups(uint8_t *data, size_t length) {
    if (length % 4) return;
    for (size_t i = 0; i < length; i += 4) {
        uint8_t a = data[i], b = data[i + 1];
        data[i] = data[i + 3]; data[i + 3] = a;
        data[i + 1] = data[i + 2]; data[i + 2] = b;
    }
}

bc_status huawei_pbkdf2(const uint8_t *password, size_t password_length, const uint8_t *salt, size_t salt_length,
                        uint32_t iterations, int sha256, uint8_t *out, uint32_t length) {
    if (!out || !length || !iterations || (!salt && salt_length)) return BC_INVALID_ARGUMENT;
    uint32_t digest_length = sha256 ? 32u : 20u;
    uint32_t blocks = (length + digest_length - 1) / digest_length;
    uint32_t produced = 0;
    for (uint32_t block = 1; block <= blocks; ++block) {
        uint8_t first[20 + 4];
        memcpy(first, salt, salt_length);
        first[salt_length + 0] = (uint8_t)(block >> 24);
        first[salt_length + 1] = (uint8_t)(block >> 16);
        first[salt_length + 2] = (uint8_t)(block >> 8);
        first[salt_length + 3] = (uint8_t)block;
        uint8_t u[32], accumulated[32];
        uint32_t produced_length = 0;
        huawei_hmac(password, password_length, first, salt_length + 4, sha256, u, &produced_length);
        if (produced_length != digest_length) return BC_NO_MEMORY;
        memcpy(accumulated, u, digest_length);
        for (uint32_t round = 1; round < iterations; ++round) {
            huawei_hmac(password, password_length, u, digest_length, sha256, u, &produced_length);
            for (uint32_t i = 0; i < digest_length; ++i) accumulated[i] ^= u[i];
        }
        uint32_t take = length - produced < digest_length ? length - produced : digest_length;
        memcpy(out + produced, accumulated, take);
        produced += take;
    }
    return BC_OK;
}

int huawei_hex_decode(const char *text, uint8_t *out, uint32_t capacity) {
    if (!text || !out) return 0;
    size_t length = strlen(text);
    if (length % 2 || length / 2 > capacity) return 0;
    for (size_t i = 0; i < length / 2; ++i) {
        int high, low;
        char a = text[i * 2], b = text[i * 2 + 1];
        if (a >= '0' && a <= '9') high = a - '0';
        else if (a >= 'a' && a <= 'f') high = a - 'a' + 10;
        else if (a >= 'A' && a <= 'F') high = a - 'A' + 10;
        else return 0;
        if (b >= '0' && b <= '9') low = b - '0';
        else if (b >= 'a' && b <= 'f') low = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') low = b - 'A' + 10;
        else return 0;
        out[i] = (uint8_t)((high << 4) | low);
    }
    return (int)(length / 2);
}

uint32_t huawei_latin1_to_utf8(const uint8_t *input, uint32_t length, uint8_t *out, uint32_t capacity) {
    uint32_t at = 0;
    for (uint32_t i = 0; i < length; ++i) {
        uint8_t byte = input[i];
        if (byte < 0x80) {
            if (at + 1 > capacity) return 0;
            out[at++] = byte;
        } else {
            if (at + 2 > capacity) return 0;
            out[at++] = (uint8_t)(0xC0 | (byte >> 6));
            out[at++] = (uint8_t)(0x80 | (byte & 0x3F));
        }
    }
    return at;
}

/* ---------------------------------------------------------------------------------------------
 * AES-128 (FIPS 197), CBC mode without padding.
 * ------------------------------------------------------------------------------------------- */

static const uint8_t aes_sbox[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16};

static const uint8_t aes_inverse_sbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D};

static const uint8_t aes_rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

static uint8_t aes_xtime(uint8_t value) {
    return (uint8_t)((value << 1) ^ ((value & 0x80) ? 0x1B : 0x00));
}
static uint8_t aes_multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = aes_xtime(a);
        b >>= 1;
    }
    return result;
}

static void aes_round_keys(const uint8_t key[16], uint8_t round_keys[176]) {
    uint8_t *w = round_keys;
    memcpy(w, key, 16);
    for (int i = 4; i < 44; ++i) {
        uint8_t temp[4];
        memcpy(temp, w + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            uint8_t first = temp[0];
            temp[0] = aes_sbox[temp[1]] ^ aes_rcon[i / 4 - 1];
            temp[1] = aes_sbox[temp[2]];
            temp[2] = aes_sbox[temp[3]];
            temp[3] = aes_sbox[first];
        }
        for (int j = 0; j < 4; ++j) w[i * 4 + j] = w[(i - 4) * 4 + j] ^ temp[j];
    }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t *round_key) {
    for (int i = 0; i < 16; ++i) state[i] ^= round_key[i];
}
static void aes_sub_bytes(uint8_t state[16], const uint8_t *box) {
    for (int i = 0; i < 16; ++i) state[i] = box[state[i]];
}
static void aes_shift_rows(uint8_t state[16]) {
    uint8_t copy[16];
    memcpy(copy, state, 16);
    for (int row = 1; row < 4; ++row)
        for (int column = 0; column < 4; ++column)
            state[row + 4 * column] = copy[row + 4 * ((column + row) % 4)];
}
static void aes_inverse_shift_rows(uint8_t state[16]) {
    uint8_t copy[16];
    memcpy(copy, state, 16);
    for (int row = 1; row < 4; ++row)
        for (int column = 0; column < 4; ++column)
            state[row + 4 * column] = copy[row + 4 * ((column + 4 - row) % 4)];
}
static void aes_mix_columns(uint8_t state[16]) {
    for (int column = 0; column < 4; ++column) {
        uint8_t *s = state + column * 4;
        uint8_t a = s[0], b = s[1], c = s[2], d = s[3];
        s[0] = aes_multiply(a, 2) ^ aes_multiply(b, 3) ^ c ^ d;
        s[1] = a ^ aes_multiply(b, 2) ^ aes_multiply(c, 3) ^ d;
        s[2] = a ^ b ^ aes_multiply(c, 2) ^ aes_multiply(d, 3);
        s[3] = aes_multiply(a, 3) ^ b ^ c ^ aes_multiply(d, 2);
    }
}
static void aes_inverse_mix_columns(uint8_t state[16]) {
    for (int column = 0; column < 4; ++column) {
        uint8_t *s = state + column * 4;
        uint8_t a = s[0], b = s[1], c = s[2], d = s[3];
        s[0] = aes_multiply(a, 14) ^ aes_multiply(b, 11) ^ aes_multiply(c, 13) ^ aes_multiply(d, 9);
        s[1] = aes_multiply(a, 9) ^ aes_multiply(b, 14) ^ aes_multiply(c, 11) ^ aes_multiply(d, 13);
        s[2] = aes_multiply(a, 13) ^ aes_multiply(b, 9) ^ aes_multiply(c, 14) ^ aes_multiply(d, 11);
        s[3] = aes_multiply(a, 11) ^ aes_multiply(b, 13) ^ aes_multiply(c, 9) ^ aes_multiply(d, 14);
    }
}
static void aes_encrypt_block(const uint8_t round_keys[176], const uint8_t input[16], uint8_t output[16]) {
    uint8_t state[16];
    memcpy(state, input, 16);
    aes_add_round_key(state, round_keys);
    for (int round = 1; round <= 10; ++round) {
        aes_sub_bytes(state, aes_sbox);
        aes_shift_rows(state);
        if (round != 10) aes_mix_columns(state);
        aes_add_round_key(state, round_keys + round * 16);
    }
    memcpy(output, state, 16);
}
static void aes_decrypt_block(const uint8_t round_keys[176], const uint8_t input[16], uint8_t output[16]) {
    uint8_t state[16];
    memcpy(state, input, 16);
    aes_add_round_key(state, round_keys + 160);
    for (int round = 9; round >= 0; --round) {
        aes_inverse_shift_rows(state);
        aes_sub_bytes(state, aes_inverse_sbox);
        aes_add_round_key(state, round_keys + round * 16);
        if (round != 0) aes_inverse_mix_columns(state);
    }
    memcpy(output, state, 16);
}

bc_status huawei_aes_cbc(const uint8_t *key, const uint8_t *iv, const uint8_t *input, uint32_t length,
                         uint8_t *out, int encrypt) {
    if (!key || !iv || (!input && length) || !out || length % HUAWEI_AES_BLOCK) return BC_INVALID_ARGUMENT;
    uint8_t round_keys[176], previous[16], block[16];
    aes_round_keys(key, round_keys);
    memcpy(previous, iv, 16);
    for (uint32_t offset = 0; offset < length; offset += HUAWEI_AES_BLOCK) {
        if (encrypt) {
            for (int i = 0; i < 16; ++i) block[i] = input[offset + i] ^ previous[i];
            aes_encrypt_block(round_keys, block, out + offset);
            memcpy(previous, out + offset, 16);
        } else {
            aes_decrypt_block(round_keys, input + offset, block);
            for (int i = 0; i < 16; ++i) out[offset + i] = block[i] ^ previous[i];
            memcpy(previous, input + offset, 16);
        }
    }
    return BC_OK;
}

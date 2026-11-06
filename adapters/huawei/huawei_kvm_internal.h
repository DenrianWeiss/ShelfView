#ifndef BCONTROL_HUAWEI_KVM_INTERNAL_H
#define BCONTROL_HUAWEI_KVM_INTERNAL_H
#include "bcontrol/huawei_kvm.h"
#include <stddef.h>
#include <stdint.h>

#define HUAWEI_FRAME_MAGIC0 0xFEu
#define HUAWEI_FRAME_MAGIC1 0xF6u
#define HUAWEI_MAX_PACKET 250u
#define HUAWEI_SHA1_SIZE 20u
#define HUAWEI_SHA256_SIZE 32u
#define HUAWEI_AES_BLOCK 16u

/* Portable crypto (self-contained; no platform libraries). */
void huawei_sha1(const uint8_t *data, size_t length, uint8_t out[20]);
void huawei_sha256(const uint8_t *data, size_t length, uint8_t out[32]);
void huawei_hmac(const uint8_t *key, size_t key_length, const uint8_t *data, size_t length, int sha256,
                 uint8_t out[32], uint32_t *out_length);
bc_status huawei_pbkdf2(const uint8_t *password, size_t password_length, const uint8_t *salt, size_t salt_length,
                        uint32_t iterations, int sha256, uint8_t *out, uint32_t length);
void huawei_swap_groups(uint8_t *data, size_t length);
int huawei_hex_decode(const char *text, uint8_t *out, uint32_t capacity);
/* Raw UTF-8 encoding of a JS-style byte string (each byte becomes a code point). */
uint32_t huawei_latin1_to_utf8(const uint8_t *input, uint32_t length, uint8_t *out, uint32_t capacity);
bc_status huawei_aes_cbc(const uint8_t *key, const uint8_t *iv, const uint8_t *input, uint32_t length,
                         uint8_t *out, int encrypt);

/* Streaming parser for server packets (0xFE 0xF6 0x00 length, two reserved bytes, payload). */
typedef struct {
    uint8_t buffer[8192];
    uint32_t length;
} huawei_reader;

void huawei_reader_reset(huawei_reader *reader);
/* Appends bytes and returns the number of complete payloads copied through `callback`. */
typedef int (*huawei_payload_callback)(void *user, const uint8_t *payload, uint32_t length);
uint32_t huawei_reader_feed(huawei_reader *reader, const uint8_t *data, uint32_t length,
                            huawei_payload_callback callback, void *user);

/* Video: JPEG tile decode plus tiled frame composition (all inside the caller frame buffer). */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t columns;
    uint32_t rows;
    uint32_t quantization;
    uint8_t *frame;
    uint32_t frame_capacity;
} huawei_renderer;

void huawei_renderer_reset(huawei_renderer *renderer, uint8_t *frame, uint32_t capacity);
bc_status huawei_renderer_draw(huawei_renderer *renderer, const uint8_t *blocks, uint32_t length,
                               uint32_t width, uint32_t height, uint32_t quantization);
bc_status huawei_jpeg_decode_tile(const uint8_t *scan, uint32_t length, uint32_t quantization,
                                  uint8_t out[BC_HUAWEI_TILE * BC_HUAWEI_TILE * 4]);

/* Image fragment assembly. */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t byte_length;
    uint32_t quantization;
    uint32_t key_frame;
    uint32_t sequence;
    uint8_t *blocks;
    uint32_t blocks_capacity;
    uint32_t received;
    uint32_t expected;
    uint32_t active;
    uint8_t received_map[512];
} huawei_image_assembler;

void huawei_assembler_reset(huawei_image_assembler *assembler);
bc_status huawei_assembler_begin(huawei_image_assembler *assembler, uint32_t width, uint32_t height,
                                 uint32_t byte_length, uint32_t quantization, uint32_t key_frame,
                                 uint32_t sequence);
bc_status huawei_assembler_fragment(huawei_image_assembler *assembler, uint32_t sequence, uint32_t offset,
                                    const uint8_t *chunk, uint32_t length);
/* Returns 1 when the frame is complete and the blocks/header describe it. */
int huawei_assembler_complete(const huawei_image_assembler *assembler);

#endif

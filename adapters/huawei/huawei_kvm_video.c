#include "huawei_kvm_internal.h"
#include "huawei_kvm_tables.h"
#include <stdlib.h>
#include <string.h>

struct bc_huawei_video_decoder { huawei_renderer renderer; };
bc_status bc_huawei_video_decoder_create(uint8_t *frame, uint32_t capacity, bc_huawei_video_decoder **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!frame || !capacity) return BC_INVALID_ARGUMENT;
    bc_huawei_video_decoder *decoder = calloc(1, sizeof(*decoder));
    if (!decoder) return BC_NO_MEMORY;
    huawei_renderer_reset(&decoder->renderer, frame, capacity);
    *out = decoder; return BC_OK;
}
bc_status bc_huawei_video_decoder_draw(bc_huawei_video_decoder *decoder, const uint8_t *blocks,
    uint32_t length, uint32_t width, uint32_t height, uint32_t quantization) {
    if (!decoder || (!blocks && length)) return BC_INVALID_ARGUMENT;
    return huawei_renderer_draw(&decoder->renderer, blocks, length, width, height, quantization);
}
void bc_huawei_video_decoder_destroy(bc_huawei_video_decoder *decoder) { free(decoder); }

/* ---------------------------------------------------------------------------------------------
 * Baseline JPEG decode of one 64x64 tile. The device sends only the entropy-coded scan; the
 * quantization tables are selected by the frame quality byte and the standard Annex K Huffman
 * tables are used for every tile.
 * ------------------------------------------------------------------------------------------- */

#define JPEG_SCAN_LIMIT (4u * 1024u * 1024u)

typedef struct {
    const uint8_t *data;
    uint32_t length;
    uint32_t position;
    uint32_t bits;
    uint32_t bit_count;
    int error;
} jpeg_bits;

typedef struct {
    const uint8_t *counts;
    const int16_t *values;
    uint32_t first_code[17];
    int32_t first_index[17];
} jpeg_huffman;

static void huffman_build(jpeg_huffman *table, const uint8_t counts[17], const int16_t *values) {
    memset(table, 0, sizeof(*table));
    table->counts = counts;
    table->values = values;
    uint32_t code = 0;
    int32_t index = 0;
    for (int length = 1; length <= 16; ++length) {
        table->first_code[length] = code;
        table->first_index[length] = index;
        code = (code + counts[length]) << 1;
        index += counts[length];
    }
}

static int jpeg_bit(jpeg_bits *bits) {
    if (!bits->bit_count) {
        if (bits->position >= bits->length) { bits->error = 1; return 0; }
        uint32_t byte = bits->data[bits->position++];
        if (byte == 0xFF) {
            while (bits->position < bits->length && bits->data[bits->position] == 0xFF) ++bits->position;
            if (bits->position >= bits->length) { bits->error = 1; return 0; }
            uint32_t next = bits->data[bits->position++];
            if (next != 0x00) { bits->error = 1; return 0; } /* marker terminates the scan */
        }
        bits->bits = byte;
        bits->bit_count = 8;
    }
    --bits->bit_count;
    return (int)((bits->bits >> bits->bit_count) & 1u);
}

static int jpeg_symbol(jpeg_bits *bits, const jpeg_huffman *table) {
    uint32_t code = 0;
    for (int length = 1; length <= 16; ++length) {
        int bit = jpeg_bit(bits);
        if (bits->error) return -1;
        code = (code << 1) | (uint32_t)bit;
        uint32_t count = table->counts[length];
        if (count && code >= table->first_code[length] && code < table->first_code[length] + count) {
            int32_t index = table->first_index[length] + (int32_t)(code - table->first_code[length]);
            return table->values[index];
        }
    }
    return -1;
}

static int32_t jpeg_value(jpeg_bits *bits, uint32_t size) {
    if (size == 0 || size > 16) { bits->error = 1; return 0; }
    uint32_t value = 0;
    for (uint32_t i = 0; i < size; ++i) {
        int bit = jpeg_bit(bits);
        if (bits->error) return 0;
        value = (value << 1) | (uint32_t)bit;
    }
    if (!(value & (1u << (size - 1)))) value += 1u - (1u << size);
    return (int32_t)value;
}

static int32_t shift16(int64_t value) { return value >= 0 ? (int32_t)(value >> 16) : -(int32_t)(((-value) + 65535) >> 16); }
#define AAN_MUL(a, b) ((int32_t)(((int64_t)(a) * (b)) >> 8))

static void idct_block(const int32_t coefficients[64], const int64_t quant[64], int32_t out[64]) {
    int32_t workspace[64];
    for (int column = 0; column < 8; ++column) {
        int c = column;
        if ((coefficients[c + 8] | coefficients[c + 16] | coefficients[c + 24] | coefficients[c + 32] |
             coefficients[c + 40] | coefficients[c + 48] | coefficients[c + 56]) == 0) {
            int32_t dc = shift16((int64_t)coefficients[c] * quant[column]);
            for (int row = 0; row < 8; ++row) workspace[row * 8 + column] = dc;
            continue;
        }
        int32_t t0 = shift16((int64_t)coefficients[c] * quant[column]);
        int32_t t1 = shift16((int64_t)coefficients[c + 16] * quant[column + 16]);
        int32_t t2 = shift16((int64_t)coefficients[c + 32] * quant[column + 32]);
        int32_t t3 = shift16((int64_t)coefficients[c + 48] * quant[column + 48]);
        int32_t tmp10 = t0 + t2, tmp11 = t0 - t2, tmp13 = t1 + t3;
        int32_t tmp12 = AAN_MUL(t1 - t3, 362) - tmp13;
        int32_t a0 = tmp10 + tmp13, a3 = tmp10 - tmp13, a1 = tmp11 + tmp12, a2 = tmp11 - tmp12;
        int32_t s0 = shift16((int64_t)coefficients[c + 8] * quant[column + 8]);
        int32_t s1 = shift16((int64_t)coefficients[c + 24] * quant[column + 24]);
        int32_t s2 = shift16((int64_t)coefficients[c + 40] * quant[column + 40]);
        int32_t s3 = shift16((int64_t)coefficients[c + 56] * quant[column + 56]);
        int32_t z13 = s2 + s1, z10 = s2 - s1, z11 = s0 + s3, z12 = s0 - s3;
        int32_t u7 = z11 + z13, u11 = AAN_MUL(z11 - z13, 362), z5 = AAN_MUL(z10 + z12, 473);
        int32_t u10 = AAN_MUL(z12, 277) - z5, u12 = AAN_MUL(z10, -669) + z5 - u7;
        int32_t v6 = u11 - u12, v5 = u10 + v6;
        workspace[column] = a0 + u7; workspace[56 + column] = a0 - u7;
        workspace[8 + column] = a1 + u12; workspace[48 + column] = a1 - u12;
        workspace[16 + column] = a2 + v6; workspace[40 + column] = a2 - v6;
        workspace[32 + column] = a3 + v5; workspace[24 + column] = a3 - v5;
    }
    for (int row = 0; row < 8; ++row) {
        const int32_t *w = workspace + row * 8;
        int32_t tmp10 = w[0] + w[4], tmp11 = w[0] - w[4];
        int32_t tmp13 = w[2] + w[6], tmp12 = AAN_MUL(w[2] - w[6], 362) - tmp13;
        int32_t a0 = tmp10 + tmp13, a3 = tmp10 - tmp13, a1 = tmp11 + tmp12, a2 = tmp11 - tmp12;
        int32_t z13 = w[5] + w[3], z10 = w[5] - w[3];
        int32_t z11 = w[1] + w[7], z12 = w[1] - w[7];
        int32_t u7 = z11 + z13, u11 = AAN_MUL(z11 - z13, 362), z5 = AAN_MUL(z10 + z12, 473);
        int32_t u10 = AAN_MUL(z12, 277) - z5, u12 = AAN_MUL(z10, -669) + z5 - u7;
        int32_t v6 = u11 - u12, v5 = u10 + v6;
        out[row * 8] = (a0 + u7) >> 3; out[row * 8 + 7] = (a0 - u7) >> 3;
        out[row * 8 + 1] = (a1 + u12) >> 3; out[row * 8 + 6] = (a1 - u12) >> 3;
        out[row * 8 + 2] = (a2 + v6) >> 3; out[row * 8 + 5] = (a2 - v6) >> 3;
        out[row * 8 + 4] = (a3 + v5) >> 3; out[row * 8 + 3] = (a3 - v5) >> 3;
    }
}
#undef AAN_MUL

static int decode_block(jpeg_bits *bits, const jpeg_huffman *dc, const jpeg_huffman *ac, int32_t *predictor,
                        const int64_t quant[64], int32_t coefficients[64], int32_t samples[64]) {
    memset(coefficients, 0, 64 * sizeof(int32_t));
    int size = jpeg_symbol(bits, dc);
    if (size < 0 || size > 15) return 0;
    if (size) {
        int32_t delta = jpeg_value(bits, (uint32_t)size);
        if (bits->error) return 0;
        *predictor += delta;
    }
    coefficients[0] = *predictor;
    int index = 1;
    while (index < 64) {
        int symbol = jpeg_symbol(bits, ac);
        if (symbol < 0) return 0;
        int run = symbol >> 4, length = symbol & 15;
        if (length == 0) {
            if (run == 15) { index += 16; continue; }
            break;
        }
        index += run;
        if (index >= 64) return 0;
        int32_t value = jpeg_value(bits, (uint32_t)length);
        if (bits->error) return 0;
        coefficients[huawei_dezigzag[index]] = value;
        ++index;
    }
    idct_block(coefficients, quant, samples);
    return 1;
}

static void build_quant(const uint8_t *zigzag_table, int64_t quant[64]) {
    static const double aan[8] = {1.0, 1.3870399, 1.306563, 1.1758755, 1.0, 0.78569496, 0.5411961, 0.27589938};
    for (int natural = 0; natural < 64; ++natural) {
        int row = natural / 8, column = natural % 8;
        uint32_t value = zigzag_table[huawei_zigzag[natural]];
        if (value == 0) value = 1;
        quant[natural] = (int64_t)((double)value * aan[row] * aan[column]) * 65536;
    }
}

static void store_pixel(uint8_t *out, uint32_t x, uint32_t y, int32_t luma, int32_t cb, int32_t cr) {
    int32_t c = luma + 128 - 16, d = cb, e = cr;
    int32_t red = (298 * c + 409 * e + 128) >> 8;
    int32_t green = (298 * c - 100 * d - 208 * e + 128) >> 8;
    int32_t blue = (298 * c + 516 * d + 128) >> 8;
    uint8_t *pixel = out + (y * BC_HUAWEI_TILE + x) * 4;
    pixel[0] = (uint8_t)(red < 0 ? 0 : red > 255 ? 255 : red);
    pixel[1] = (uint8_t)(green < 0 ? 0 : green > 255 ? 255 : green);
    pixel[2] = (uint8_t)(blue < 0 ? 0 : blue > 255 ? 255 : blue);
    pixel[3] = 255;
}

bc_status huawei_jpeg_decode_tile(const uint8_t *scan, uint32_t length, uint32_t quantization,
                                  uint8_t out[BC_HUAWEI_TILE * BC_HUAWEI_TILE * 4]) {
    if (!scan || !out || length == 0 || length > JPEG_SCAN_LIMIT) return BC_INVALID_ARGUMENT;
    uint32_t level = quantization;
    if (level < 1) level = 1;
    if (level > 10) level = 10;
    int64_t quant[3][64];
    for (int table = 0; table < 3; ++table) build_quant(huawei_quant_tables[level - 1][table], quant[table]);
    jpeg_huffman dc[2], ac[2];
    huffman_build(&dc[0], huawei_dc_luma_counts, huawei_dc_luma_values);
    huffman_build(&dc[1], huawei_dc_chroma_counts, huawei_dc_chroma_values);
    huffman_build(&ac[0], huawei_ac_luma_counts, huawei_ac_luma_values);
    huffman_build(&ac[1], huawei_ac_chroma_counts, huawei_ac_chroma_values);
    jpeg_bits bits = {scan, length, 0, 0, 0, 0};
    int32_t predictor[3] = {0, 0, 0};
    int32_t coefficients[64], samples[3][64];
    for (int block_y = 0; block_y < 8; ++block_y) {
        for (int block_x = 0; block_x < 8; ++block_x) {
            for (int component = 0; component < 3; ++component) {
                int luma = component == 0;
                if (!decode_block(&bits, &dc[luma ? 0 : 1], &ac[luma ? 0 : 1], &predictor[component],
                                  quant[component], coefficients, samples[component])) {
                    return BC_PROTOCOL_ERROR;
                }
            }
            for (int row = 0; row < 8; ++row) {
                for (int column = 0; column < 8; ++column) {
                    int at = row * 8 + column;
                    store_pixel(out, (uint32_t)(block_x * 8 + column), (uint32_t)(block_y * 8 + row),
                                samples[0][at], samples[1][at], samples[2][at]);
                }
            }
        }
    }
    return BC_OK;
}

/* ---------------------------------------------------------------------------------------------
 * Frame composition with block-copy records.
 * ------------------------------------------------------------------------------------------- */

void huawei_renderer_reset(huawei_renderer *renderer, uint8_t *frame, uint32_t capacity) {
    if (!renderer) return;
    memset(renderer, 0, sizeof(*renderer));
    renderer->frame = frame;
    renderer->frame_capacity = capacity;
    if (frame && capacity) memset(frame, 0, capacity);
}

static void copy_block(huawei_renderer *renderer, uint32_t target, int vertical) {
    uint32_t x = (target % renderer->columns) * BC_HUAWEI_TILE;
    uint32_t y = (target / renderer->columns) * BC_HUAWEI_TILE;
    uint32_t width = renderer->width - x;
    uint32_t height = renderer->height - y;
    if ((int32_t)width > (int32_t)BC_HUAWEI_TILE) width = BC_HUAWEI_TILE;
    if ((int32_t)height > (int32_t)BC_HUAWEI_TILE) height = BC_HUAWEI_TILE;
    if (vertical) {
        uint32_t source_y = y - BC_HUAWEI_TILE;
        for (uint32_t row = 0; row < height; ++row) {
            memmove(renderer->frame + (size_t)(y + row) * renderer->width * 4 + x * 4,
                    renderer->frame + (size_t)(source_y + row) * renderer->width * 4 + x * 4, width * 4);
        }
    } else {
        for (uint32_t row = 0; row < height; ++row) {
            memmove(renderer->frame + (size_t)(y + row) * renderer->width * 4 + x * 4,
                    renderer->frame + (size_t)(y + row) * renderer->width * 4 + (x - BC_HUAWEI_TILE) * 4,
                    width * 4);
        }
    }
}

bc_status huawei_renderer_draw(huawei_renderer *renderer, const uint8_t *blocks, uint32_t length,
                               uint32_t width, uint32_t height, uint32_t quantization) {
    if (!renderer || !renderer->frame) return BC_INVALID_ARGUMENT;
    if (!width || !height || width > BC_HUAWEI_MAX_DIMENSION || height > BC_HUAWEI_MAX_DIMENSION)
        return BC_LIMIT_EXCEEDED;
    uint64_t needed = (uint64_t)width * height * 4;
    if (needed > renderer->frame_capacity) return BC_LIMIT_EXCEEDED;
    uint32_t columns = (width + BC_HUAWEI_TILE - 1) / BC_HUAWEI_TILE;
    uint32_t rows = (height + BC_HUAWEI_TILE - 1) / BC_HUAWEI_TILE;
    if (width != renderer->width || height != renderer->height) {
        renderer->width = width;
        renderer->height = height;
        renderer->columns = columns;
        renderer->rows = rows;
        memset(renderer->frame, 0, (size_t)needed);
    }
    renderer->quantization = quantization;
    uint8_t tile[BC_HUAWEI_TILE * BC_HUAWEI_TILE * 4];
    uint32_t tile_count = columns * rows;
    uint32_t offset = 0, tile_index = 0;
    while (offset < length && tile_index < tile_count) {
        uint32_t type = (blocks[offset] & 0xE0u) >> 5;
        if (type == 2 || type == 3) {
            if (offset + 3 > length) return BC_PROTOCOL_ERROR;
            uint32_t scan_length = ((uint32_t)blocks[offset + 1] << 8) | blocks[offset + 2];
            if (offset + 3 + scan_length > length) return BC_PROTOCOL_ERROR;
            bc_status status = huawei_jpeg_decode_tile(blocks + offset + 3, scan_length, quantization, tile);
            uint32_t x = (tile_index % columns) * BC_HUAWEI_TILE;
            uint32_t y = (tile_index / columns) * BC_HUAWEI_TILE;
            uint32_t copy_width = width - x, copy_height = height - y;
            if (copy_width > BC_HUAWEI_TILE) copy_width = BC_HUAWEI_TILE;
            if (copy_height > BC_HUAWEI_TILE) copy_height = BC_HUAWEI_TILE;
            if (status == BC_OK) {
                for (uint32_t row = 0; row < copy_height; ++row)
                    memcpy(renderer->frame + (size_t)(y + row) * width * 4 + x * 4,
                           tile + row * BC_HUAWEI_TILE * 4, copy_width * 4);
            }
            offset += 3 + scan_length;
            ++tile_index;
        } else if (type == 5) {
            if (tile_index >= columns) copy_block(renderer, tile_index, 1);
            ++offset;
            ++tile_index;
        } else if (type == 6) {
            if (tile_index > 0) copy_block(renderer, tile_index, 0);
            ++offset;
            ++tile_index;
        } else if (type == 4) {
            ++offset;
            ++tile_index;
        } else {
            ++offset;
        }
    }
    return BC_OK;
}

/* ---------------------------------------------------------------------------------------------
 * Image fragment assembly.
 * ------------------------------------------------------------------------------------------- */

#define HUAWEI_MAX_FRAME_BYTES (2u * 1024u * 1024u)

void huawei_assembler_reset(huawei_image_assembler *assembler) {
    if (!assembler) return;
    free(assembler->blocks);
    memset(assembler, 0, sizeof(*assembler));
}

bc_status huawei_assembler_begin(huawei_image_assembler *assembler, uint32_t width, uint32_t height,
                                 uint32_t byte_length, uint32_t quantization, uint32_t key_frame,
                                 uint32_t sequence) {
    if (!assembler) return BC_INVALID_ARGUMENT;
    if (!byte_length) { assembler->active = 0; return BC_OK; }
    if (byte_length > HUAWEI_MAX_FRAME_BYTES) return BC_LIMIT_EXCEEDED;
    if (assembler->blocks_capacity < byte_length) {
        uint8_t *blocks = (uint8_t *)realloc(assembler->blocks, byte_length);
        if (!blocks) return BC_NO_MEMORY;
        assembler->blocks = blocks;
        assembler->blocks_capacity = byte_length;
    }
    assembler->width = width;
    assembler->height = height;
    assembler->byte_length = byte_length;
    assembler->quantization = quantization;
    assembler->key_frame = key_frame;
    assembler->sequence = sequence;
    assembler->received = 0;
    assembler->expected = (byte_length + BC_HUAWEI_FRAGMENT - 1) / BC_HUAWEI_FRAGMENT;
    assembler->active = 1;
    memset(assembler->received_map, 0, sizeof(assembler->received_map));
    memset(assembler->blocks, 0, byte_length);
    return BC_OK;
}

bc_status huawei_assembler_fragment(huawei_image_assembler *assembler, uint32_t sequence, uint32_t offset,
                                    const uint8_t *chunk, uint32_t length) {
    if (!assembler || !assembler->active || !chunk) return BC_INVALID_ARGUMENT;
    if (sequence != assembler->sequence || offset < 1 || offset > assembler->expected) return BC_PROTOCOL_ERROR;
    uint32_t destination = (offset - 1) * BC_HUAWEI_FRAGMENT;
    if (destination >= assembler->byte_length) return BC_PROTOCOL_ERROR;
    uint32_t take = assembler->byte_length - destination;
    if (take > BC_HUAWEI_FRAGMENT) take = BC_HUAWEI_FRAGMENT;
    if (take > length) take = length;
    if (!take) return BC_PROTOCOL_ERROR;
    memcpy(assembler->blocks + destination, chunk, take);
    uint32_t bit = offset - 1;
    if (bit / 8 >= sizeof(assembler->received_map)) return BC_LIMIT_EXCEEDED;
    if (!(assembler->received_map[bit / 8] & (1u << (bit % 8)))) {
        assembler->received_map[bit / 8] |= (uint8_t)(1u << (bit % 8));
        ++assembler->received;
    }
    return BC_OK;
}

int huawei_assembler_complete(const huawei_image_assembler *assembler) {
    return assembler && assembler->active && assembler->received == assembler->expected;
}

bc_status bc_huawei_kvm_video_tile(const uint8_t *scan, uint32_t length, uint32_t quantization,
                                   uint8_t *rgba, uint32_t capacity) {
    if (!rgba || capacity < BC_HUAWEI_TILE * BC_HUAWEI_TILE * 4) return BC_LIMIT_EXCEEDED;
    return huawei_jpeg_decode_tile(scan, length, quantization, rgba);
}

bc_status bc_huawei_kvm_video_render(const uint8_t *blocks, uint32_t length, uint32_t width, uint32_t height,
                                     uint32_t quantization, uint8_t *frame, uint32_t capacity) {
    huawei_renderer renderer;
    huawei_renderer_reset(&renderer, frame, capacity);
    return huawei_renderer_draw(&renderer, blocks, length, width, height, quantization);
}

/* ---------------------------------------------------------------------------------------------
 * Server packet stream reader: 0xFE 0xF6 0x00 length, two reserved bytes, payload.
 * ------------------------------------------------------------------------------------------- */

void huawei_reader_reset(huawei_reader *reader) {
    if (reader) reader->length = 0;
}

uint32_t huawei_reader_feed(huawei_reader *reader, const uint8_t *data, uint32_t length,
                            huawei_payload_callback callback, void *user) {
    if (!reader || !data) return 0;
    uint32_t produced = 0;
    uint32_t position = 0;
    while (position < length) {
        uint32_t room = (uint32_t)sizeof(reader->buffer) - reader->length;
        if (!room) {
            memmove(reader->buffer, reader->buffer + 1, reader->length - 1);
            --reader->length;
            room = 1;
        }
        uint32_t take = length - position < room ? length - position : room;
        memcpy(reader->buffer + reader->length, data + position, take);
        reader->length += take;
        position += take;
        uint32_t index = 0;
        while (index + 4 <= reader->length) {
            if (reader->buffer[index] == HUAWEI_FRAME_MAGIC0 && reader->buffer[index + 1] == HUAWEI_FRAME_MAGIC1 &&
                reader->buffer[index + 2] == 0x00) {
                uint32_t frame_length = reader->buffer[index + 3];
                if (frame_length >= 3 && frame_length <= HUAWEI_MAX_PACKET) {
                    if (index + 4 + frame_length > reader->length) break;
                    uint32_t payload_length = frame_length - 2;
                    if (payload_length && callback) callback(user, reader->buffer + index + 6, payload_length);
                    ++produced;
                    index += 4 + frame_length;
                    continue;
                }
            }
            ++index;
        }
        if (index) {
            memmove(reader->buffer, reader->buffer + index, reader->length - index);
            reader->length -= index;
        }
    }
    return produced;
}

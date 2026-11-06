#include "video.h"
#include "bcontrol/wire.h"
#include "tables.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define AST_JOURNAL 8u
typedef struct {
    uint8_t counts[17];
    int16_t values[256];
    int value_count;
    uint32_t first_code[17];
    int16_t first_index[17];
} huffman;

struct bc_ast_video {
    uint32_t width, height, real_width, real_height;
    int mode420,strict,truncated;
    uint32_t bit_limit;
    uint32_t txb, tyb;
    uint8_t color[4][3];
    int index[4];
    uint8_t bitmap_bits;
    uint32_t *words;
    uint32_t word_count, bit_pos;
    int16_t dc_y, dc_cb, dc_cr;
    int64_t qt[4][64];
    int32_t *prev_yuv;
    uint32_t prev_pixels;
    int32_t coeff[384];
    int32_t workspace[64];
    int32_t yuv[384];
    huffman dc[2], ac[2];
    uint8_t *output;
    int32_t calc_y[256], calc_cr_r[256], calc_cb_b[256], calc_cr_g[256], calc_cb_g[256];
    uint8_t range[1408];
};
typedef struct bc_ast_video ast_video;

static int32_t shift16(int32_t value) { return value >= 0 ? value >> 16 : -(((-value) + 65535) >> 16); }
static int64_t shift64_16(int64_t value) { return value >= 0 ? value >> 16 : -(((-value) + 65535) >> 16); }
static int32_t fixed(double value) { return (int32_t)(value * 65536.0 + 0.5); }
static void init_tables(ast_video *video) {
    const int32_t cr_r = fixed(1.597656), cb_b = fixed(2.015625), cr_g = fixed(-0.8125), cb_g = fixed(-0.390625), y_scale = fixed(1.164);
    int chroma = -128;
    for (int i = 0; i < 256; ++i) {
        video->calc_cr_r[i] = shift16(cr_r * chroma + 32768);
        video->calc_cb_b[i] = shift16(cb_b * chroma + 32768);
        video->calc_cr_g[i] = shift16(cr_g * chroma + 32768);
        video->calc_cb_g[i] = shift16(cb_g * chroma + 32768);
        ++chroma;
    }
    int luma = -16;
    for (int i = 0; i < 256; ++i) {
        video->calc_y[i] = shift16(y_scale * luma + 32768);
        ++luma;
    }
    memset(video->range, 0, sizeof(video->range));
    for (int i = 0; i < 256; ++i) video->range[256 + i] = (uint8_t)i;
    for (int i = 512; i < 895; ++i) video->range[i] = 0xFF;
    for (int i = 896; i < 1279; ++i) video->range[i] = 0;
    for (int i = 1280; i < 1408; ++i) video->range[i] = (uint8_t)i;
}
static void build_huffman(huffman *table, const uint8_t counts[17], const int16_t *values, int value_count) {
    memset(table, 0, sizeof(*table));
    memcpy(table->counts, counts, sizeof(table->counts));
    memcpy(table->values, values, (size_t)value_count * sizeof(int16_t));
    table->value_count = value_count;
    uint32_t code = 0;
    int index = 0;
    for (int length = 1; length <= 16; ++length) {
        table->first_code[length] = code;
        table->first_index[length] = (int16_t)index;
        code = (code + counts[length]) << 1;
        index += counts[length];
    }
}
static int huffman_symbol(ast_video *video, const huffman *table) {
    uint32_t code = 0;
    for (int length = 1; length <= 16; ++length) {
        uint32_t bit = video->bit_pos / 32 < video->word_count ?
            (video->words[video->bit_pos / 32] >> (31 - (video->bit_pos % 32))) & 1 : 0;
        if(video->strict && video->bit_pos>=video->bit_limit)video->truncated=1;
        ++video->bit_pos;
        code = (code << 1) | bit;
        uint32_t count = table->counts[length];
        if (count && code >= table->first_code[length] && code < table->first_code[length] + count) {
            int index = table->first_index[length] + (int)(code - table->first_code[length]);
            return index < table->value_count ? table->values[index] : -1;
        }
    }
    return -1;
}
static int16_t get_bits_signed(ast_video *video, int count) {
    if (count <= 0 || count > 16) return 0;
    int32_t value = 0;
    for (int i = 0; i < count; ++i) {
        uint32_t bit = video->bit_pos / 32 < video->word_count ?
            (video->words[video->bit_pos / 32] >> (31 - (video->bit_pos % 32))) & 1 : 0;
        if(video->strict && video->bit_pos>=video->bit_limit)video->truncated=1;
        ++video->bit_pos;
        value = (value << 1) | (int32_t)bit;
    }
    if (!(value & (1 << (count - 1)))) value += 1 - (1 << count);
    return (int16_t)value;
}
static void put_pixel(ast_video *video, uint32_t x, uint32_t y, int32_t luma, int32_t cb, int32_t cr) {
    if (x >= video->real_width || y >= video->real_height) return;
    int32_t blue = video->calc_y[luma & 0xFF] + video->calc_cb_b[cb & 0xFF];
    int32_t green = video->calc_y[luma & 0xFF] + video->calc_cb_g[cb & 0xFF] + video->calc_cr_g[cr & 0xFF];
    int32_t red = video->calc_y[luma & 0xFF] + video->calc_cr_r[cr & 0xFF];
    uint8_t *pixel = video->output + ((size_t)y * video->real_width + x) * 4;
    pixel[0] = red >= 0 ? video->range[red + 256] : 0;
    pixel[1] = green >= 0 ? video->range[green + 256] : 0;
    pixel[2] = blue >= 0 ? video->range[blue + 256] : 0;
    pixel[3] = 255;
}
static void remember(ast_video *video, uint32_t x, uint32_t y, int32_t luma, int32_t cb, int32_t cr) {
    if (!video->prev_yuv || x >= video->real_width || y >= video->real_height) return;
    size_t index = ((size_t)y * video->real_width + x) * 3;
    video->prev_yuv[index] = luma + 1; /* Zero denotes a pixel without a reference. */
    video->prev_yuv[index + 1] = cb;
    video->prev_yuv[index + 2] = cr;
}
static void convert_tile(ast_video *video) {
    if (video->mode420 == 0) {
        for (uint32_t row = 0; row < 8; ++row)
            for (uint32_t column = 0; column < 8; ++column) {
                uint32_t index = row * 8 + column;
                int32_t luma = video->yuv[index], cb = video->yuv[64 + index], cr = video->yuv[128 + index];
                put_pixel(video, video->txb * 8 + column, video->tyb * 8 + row, luma, cb, cr);
                remember(video, video->txb * 8 + column, video->tyb * 8 + row, luma, cb, cr);
            }
        return;
    }
    uint32_t counts[4] = {0, 0, 0, 0};
    for (uint32_t row = 0; row < 16; ++row) {
        uint32_t block_row = (row >> 3) * 2;
        uint32_t y_row = (row >> 1) << 3;
        for (uint32_t column = 0; column < 16; ++column) {
            uint32_t block = block_row + (column >> 3);
            uint32_t position = counts[block]++;
            uint32_t chroma = y_row + (column >> 1);
            int32_t luma = video->yuv[block * 64 + position], cb = video->yuv[256 + chroma], cr = video->yuv[320 + chroma];
            put_pixel(video, video->txb * 16 + column, video->tyb * 16 + row, luma, cb, cr);
            remember(video, video->txb * 16 + column, video->tyb * 16 + row, luma, cb, cr);
        }
    }
}
static void convert_pass2(ast_video *video) {
    if (video->mode420 != 0 || !video->prev_yuv) return;
    for (uint32_t row = 0; row < 8; ++row)
        for (uint32_t column = 0; column < 8; ++column) {
            uint32_t index = row * 8 + column;
            uint32_t x = video->txb * 8 + column, y = video->tyb * 8 + row;
            if (x >= video->real_width || y >= video->real_height) continue;
            size_t at = ((size_t)y * video->real_width + x) * 3;
            if (!video->prev_yuv[at]) continue;
            int32_t luma = video->prev_yuv[at] - 1 + video->yuv[index] - 128;
            int32_t cb = video->prev_yuv[at + 1] + video->yuv[64 + index] - 128;
            int32_t cr = video->prev_yuv[at + 2] + video->yuv[128 + index] - 128;
            luma = luma < 0 ? 0 : luma > 255 ? 255 : luma;
            cb = cb < 0 ? 0 : cb > 255 ? 255 : cb;
            cr = cr < 0 ? 0 : cr > 255 ? 255 : cr;
            put_pixel(video, x, y, luma, cb, cr);
        }
}
static void move_block(ast_video *video) {
    ++video->txb;
    if (video->mode420 == 0) {
        if (video->txb >= video->width / 8) { ++video->tyb; if (video->tyb >= video->height / 8) video->tyb = 0; video->txb = 0; }
    } else {
        if (video->txb >= video->width / 16) { ++video->tyb; if (video->tyb >= video->height / 16) video->tyb = 0; video->txb = 0; }
    }
}
static void load_quant(ast_video *video, int index, const uint8_t *source,int legacy) {
    static const double aan[8] = {1.0, 1.3870399, 1.306563, 1.1758755, 1.0, 0.78569496, 0.5411961, 0.27589938};
    static const double precise[8]={1.0,1.387039845,1.306562965,1.175875602,1.0,0.785694958,0.541196100,0.275899379};
    const double *scale=legacy?aan:precise;
    uint8_t clamped[64];
    for (int i = 0; i < 64; ++i) {
        int value = legacy?(int)(int8_t)source[i]:(int)source[i];
        clamped[i] = value <= 0 ? 1 : value > 255 ? 255 : (uint8_t)value;
    }
    for (int row = 0; row < 8; ++row)
        for (int column = 0; column < 8; ++column)
            video->qt[index][row * 8 + column] = legacy?(int64_t)((double)clamped[row * 8 + column] * aan[row] * aan[column])*65536:(int64_t)((double)clamped[row * 8 + column]*scale[row]*scale[column]*65536);
}
static int32_t dequant(ast_video *video,int32_t value,int64_t quant){
    int64_t product=(int64_t)value*quant;
    if(!video->strict)return (int32_t)shift64_16(product);
    return (int32_t)(product>=0?product/256:-((-product+255)/256));
}
static void idct(ast_video *video, int offset, int table) {
    int64_t *qt = video->qt[table];
    int32_t *c = video->coeff, *ws = video->workspace;
#define MUL(a, b) ((int32_t)(((int64_t)(a) * (b)) >> 8))
    int column = 0;
    for (; column < 8; ++column) {
        int32_t i4 = offset + column;
        if ((c[i4 + 8] | c[i4 + 16] | c[i4 + 24] | c[i4 + 32] | c[i4 + 40] | c[i4 + 48] | c[i4 + 56]) == 0) {
            int32_t dc = (int32_t)shift64_16((int64_t)c[i4]*qt[column]);
            for (int j = 0; j < 8; ++j) ws[j * 8 + column] = dc;
            continue;
        }
        int t0 = dequant(video,c[i4],qt[column]);
        int t1 = dequant(video,c[i4 + 16],qt[column + 16]);
        int t2 = dequant(video,c[i4 + 32],qt[column + 32]);
        int t3 = dequant(video,c[i4 + 48],qt[column + 48]);
        int32_t tmp10 = t0 + t2, tmp11 = t0 - t2, tmp13 = t1 + t3;
        int32_t tmp12 = MUL(t1 - t3, 362) - tmp13;
        int32_t a0 = tmp10 + tmp13, a3 = tmp10 - tmp13, a1 = tmp11 + tmp12, a2 = tmp11 - tmp12;
        int s0 = dequant(video,c[i4 + 8],qt[column + 8]);
        int s1 = dequant(video,c[i4 + 24],qt[column + 24]);
        int s2 = dequant(video,c[i4 + 40],qt[column + 40]);
        int s3 = dequant(video,c[i4 + 56],qt[column + 56]);
        int32_t z13 = s2 + s1, z10 = s2 - s1, z11 = s0 + s3, z12 = s0 - s3;
        int32_t u7 = z11 + z13, u11 = MUL(z11 - z13, 362), z5 = MUL(z10 + z12, 473);
        int32_t u10 = MUL(z12, 277) - z5, u12 = MUL(z10, -669) + z5 - u7;
        int32_t v6 = u11 - u12, v5 = u10 + v6;
        ws[column] = a0 + u7; ws[56 + column] = a0 - u7;
        ws[8 + column] = a1 + u12; ws[48 + column] = a1 - u12;
        ws[16 + column] = a2 + v6; ws[40 + column] = a2 - v6;
        ws[32 + column] = a3 + v5; ws[24 + column] = a3 - v5;
        if(video->strict)for(int j=0;j<8;++j){int32_t v=ws[j*8+column];ws[j*8+column]=v>=0?v/256:-((-v+255)/256);}
    }
    for (int row = 0; row < 8; ++row) {
        int w = row * 8, base = offset + row * 8;
        int32_t tmp10 = ws[w] + ws[w + 4], tmp11 = ws[w] - ws[w + 4];
        int32_t tmp13 = ws[w + 2] + ws[w + 6], tmp12 = MUL(ws[w + 2] - ws[w + 6], 362) - tmp13;
        int32_t a0 = tmp10 + tmp13, a3 = tmp10 - tmp13, a1 = tmp11 + tmp12, a2 = tmp11 - tmp12;
        int32_t z13 = ws[w + 5] + ws[w + 3], z10 = ws[w + 5] - ws[w + 3];
        int32_t z11 = ws[w + 1] + ws[w + 7], z12 = ws[w + 1] - ws[w + 7];
        int32_t u7 = z11 + z13, u11 = MUL(z11 - z13, 362), z5 = MUL(z10 + z12, 473);
        int32_t u10 = MUL(z12, 277) - z5, u12 = MUL(z10, -669) + z5 - u7;
        int32_t v6 = u11 - u12, v5 = u10 + v6;
        video->yuv[base] = video->range[128 + (((a0 + u7) >> 3) & 1023) + 256];
        video->yuv[base + 7] = video->range[128 + (((a0 - u7) >> 3) & 1023) + 256];
        video->yuv[base + 1] = video->range[128 + (((a1 + u12) >> 3) & 1023) + 256];
        video->yuv[base + 6] = video->range[128 + (((a1 - u12) >> 3) & 1023) + 256];
        video->yuv[base + 2] = video->range[128 + (((a2 + v6) >> 3) & 1023) + 256];
        video->yuv[base + 5] = video->range[128 + (((a2 - v6) >> 3) & 1023) + 256];
        video->yuv[base + 4] = video->range[128 + (((a3 + v5) >> 3) & 1023) + 256];
        video->yuv[base + 3] = video->range[128 + (((a3 - v5) >> 3) & 1023) + 256];
    }
#undef MUL
}
static bc_status decode_unit(ast_video *video, int offset, int component, int luma_table, int chroma_table) {
    memset(video->coeff + offset, 0, 64 * sizeof(int32_t));
    int luma = component == 0;
    int category = huffman_symbol(video, &video->dc[luma ? 0 : 1]);
    if (category < 0 || category > (video->strict?11:15)) return BC_PROTOCOL_ERROR;
    int16_t *predictor = component == 0 ? &video->dc_y : component == 1 ? &video->dc_cb : &video->dc_cr;
    if (category == 0) video->coeff[offset] = *predictor;
    else {
        int16_t delta = get_bits_signed(video, category);
        video->coeff[offset] = (int16_t)(*predictor + delta);
        *predictor = (int16_t)video->coeff[offset];
    }
    if(video->strict && (video->coeff[offset]<-2048 || video->coeff[offset]>2047))return BC_PROTOCOL_ERROR;
    int index = 1;
    while (index < 64) {
        int symbol = huffman_symbol(video, &video->ac[luma ? 0 : 1]);
        if (symbol < 0) return BC_PROTOCOL_ERROR;
        int run = symbol >> 4, size = symbol & 15;
        if(video->strict && size>10)return BC_PROTOCOL_ERROR;
        if (size == 0) {
            if (run == 15) { index += 16; continue; }
            break;
        }
        index += run;
        if (index >= 64) return BC_PROTOCOL_ERROR;
        video->coeff[offset + ast_dezigzag[index]] = get_bits_signed(video, size);
        ++index;
    }
    idct(video, offset, luma ? luma_table : chroma_table);
    return BC_OK;
}
static bc_status decode_jpeg(ast_video *video, int luma_table, int chroma_table) {
    if (video->mode420 == 0) {
        bc_status status = decode_unit(video, 0, 0, luma_table, chroma_table);
        if (status == BC_OK) status = decode_unit(video, 64, 1, luma_table, chroma_table);
        if (status == BC_OK) status = decode_unit(video, 128, 2, luma_table, chroma_table);
        if (status != BC_OK) return status;
    } else {
        for (int i = 0; i < 4; ++i) {
            bc_status status = decode_unit(video, i * 64, 0, luma_table, chroma_table);
            if (status != BC_OK) return status;
        }
        bc_status status = decode_unit(video, 256, 1, luma_table, chroma_table);
        if (status == BC_OK) status = decode_unit(video, 320, 2, luma_table, chroma_table);
        if (status != BC_OK) return status;
    }
    return BC_OK;
}
static uint32_t read_bit(ast_video *video) {
    uint32_t bit = video->bit_pos / 32 < video->word_count ?
        (video->words[video->bit_pos / 32] >> (31 - (video->bit_pos % 32))) & 1u : 0;
    if(video->strict && video->bit_pos>=video->bit_limit)video->truncated=1;
    ++video->bit_pos;
    return bit;
}
static uint32_t read_bits(ast_video *video, uint32_t count) {
    uint32_t value = 0;
    for (uint32_t i = 0; i < count; ++i) value = (value << 1) | read_bit(video);
    return value;
}
static void read_vq_header(ast_video *video, uint32_t bits, uint32_t count) {
    video->bitmap_bits = (uint8_t)bits;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t update = read_bit(video);
        video->index[i] = (int)read_bits(video, 2);
        if (update) {
            uint32_t color = read_bits(video, 24);
            video->color[video->index[i]][0] = (uint8_t)((color >> 16) & 0xFF);
            video->color[video->index[i]][1] = (uint8_t)((color >> 8) & 0xFF);
            video->color[video->index[i]][2] = (uint8_t)(color & 0xFF);
        }
    }
}
static void vq_tile(ast_video *video) {
    uint32_t at = 0;
    for (uint32_t i = 0; i < 64; ++i) {
        int selection = video->bitmap_bits ? (int)read_bits(video, video->bitmap_bits) : 0;
        const uint8_t *color = video->color[video->index[selection & 3] & 3];
        video->yuv[at] = color[0]; video->yuv[64 + at] = color[1]; video->yuv[128 + at] = color[2]; ++at;
    }
    convert_tile(video);
}
static bc_status decode_blocks(ast_video *video, uint32_t compressed) {
    for (;;) {
        uint32_t code = read_bits(video, 4);
        if(video->truncated)return BC_PROTOCOL_ERROR;
        if(video->strict && (code==2 || code==4 || code==10 || code==12 || (video->mode420 && (code==5 || code==6 || code==7 || code>=13))))return BC_UNSUPPORTED;
        switch (code) {
        case 0: {
            bc_status status = decode_jpeg(video, 0, 1); if (status != BC_OK) return status; convert_tile(video); move_block(video); break;
        }
        case 8: {
            video->txb = read_bits(video, 8); video->tyb = read_bits(video, 8);
            if(video->strict && (video->txb>=video->width/(video->mode420?16:8) || video->tyb>=video->height/(video->mode420?16:8)))return BC_PROTOCOL_ERROR;
            bc_status status = decode_jpeg(video, 0, 1); if (status != BC_OK) return status; convert_tile(video); move_block(video); break;
        }
        case 2: {
            bc_status status = decode_jpeg(video, 2, 3); if (status != BC_OK) return status;
            convert_pass2(video); move_block(video); break;
        }
        case 10: {
            video->txb = read_bits(video, 8); video->tyb = read_bits(video, 8);
            if(video->strict && (video->txb>=video->width/(video->mode420?16:8) || video->tyb>=video->height/(video->mode420?16:8)))return BC_PROTOCOL_ERROR;
            bc_status status = decode_jpeg(video, 2, 3); if (status != BC_OK) return status;
            convert_pass2(video); move_block(video); break;
        }
        case 4: {
            bc_status status = decode_jpeg(video, 2, 3); if (status != BC_OK) return status; convert_tile(video); move_block(video); break;
        }
        case 12: {
            video->txb = read_bits(video, 8); video->tyb = read_bits(video, 8);
            if(video->strict && (video->txb>=video->width/(video->mode420?16:8) || video->tyb>=video->height/(video->mode420?16:8)))return BC_PROTOCOL_ERROR;
            bc_status status = decode_jpeg(video, 2, 3); if (status != BC_OK) return status; convert_tile(video); move_block(video); break;
        }
        case 5: read_vq_header(video, 0, 1); vq_tile(video); move_block(video); break;
        case 6: read_vq_header(video, 1, 2); vq_tile(video); move_block(video); break;
        case 7: read_vq_header(video, 2, 4); vq_tile(video); move_block(video); break;
        case 13: video->txb = read_bits(video, 8); video->tyb = read_bits(video, 8);
            if(video->strict && (video->txb>=video->width/(video->mode420?16:8) || video->tyb>=video->height/(video->mode420?16:8)))return BC_PROTOCOL_ERROR;
            read_vq_header(video, 0, 1); vq_tile(video); move_block(video); break;
        case 14: video->txb = read_bits(video, 8); video->tyb = read_bits(video, 8);
            if(video->strict && (video->txb>=video->width/(video->mode420?16:8) || video->tyb>=video->height/(video->mode420?16:8)))return BC_PROTOCOL_ERROR;
            read_vq_header(video, 1, 2); vq_tile(video); move_block(video); break;
        case 15: video->txb = read_bits(video, 8); video->tyb = read_bits(video, 8);
            if(video->strict && (video->txb>=video->width/(video->mode420?16:8) || video->tyb>=video->height/(video->mode420?16:8)))return BC_PROTOCOL_ERROR;
            read_vq_header(video, 2, 4); vq_tile(video); move_block(video); break;
        case 9: return video->truncated?BC_PROTOCOL_ERROR:BC_OK;
        default: return BC_UNSUPPORTED;
        }
        if(video->strict){if(video->truncated || video->bit_pos>=video->bit_limit)return BC_PROTOCOL_ERROR;}
        else if (2 + video->bit_pos / 32 >= compressed / 4) return BC_OK;
    }
}
bc_status bc_ast_video_create(bc_ast_video **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    ast_video *video = calloc(1, sizeof(*video));
    if (!video) return BC_NO_MEMORY;
    video->color[0][0] = 0; video->color[0][1] = 0x80; video->color[0][2] = 0x80;
    video->color[1][0] = 0xFF; video->color[1][1] = 0x80; video->color[1][2] = 0x80;
    video->color[2][0] = 0x80; video->color[2][1] = 0x80; video->color[2][2] = 0x80;
    video->color[3][0] = 0xC0; video->color[3][1] = 0x80; video->color[3][2] = 0x80;
    build_huffman(&video->dc[0], ast_dc_y_counts, ast_dc_y_values, 12);
    build_huffman(&video->dc[1], ast_dc_c_counts, ast_dc_c_values, 12);
    build_huffman(&video->ac[0], ast_ac_y_counts, ast_ac_y_values, 162);
    build_huffman(&video->ac[1], ast_ac_c_counts, ast_ac_c_values, 162);
    init_tables(video);
    *out = (bc_ast_video *)video;
    return BC_OK;
}
bc_status bc_ast_video_decode(bc_ast_video *video,const bc_ast_parameters *params,const uint8_t *payload,uint32_t length,
    uint8_t *rgba,uint32_t capacity) {
    if(!video || !params || !rgba || !payload)return BC_INVALID_ARGUMENT;
    uint32_t dest_width=params->width,dest_height=params->height,compressed=length;
    if(!dest_width || !dest_height || dest_width>4096 || dest_height>4096 || length<4 || length>16u*1024u*1024u)return BC_PROTOCOL_ERROR;
    if((uint64_t)dest_width*dest_height*4>capacity)return BC_LIMIT_EXCEEDED;
    size_t pixels = (size_t)dest_width * dest_height;
    if (pixels != video->prev_pixels) {
        int32_t *fresh = calloc(pixels * 3, sizeof(int32_t));
        if (!fresh) return BC_NO_MEMORY;
        free(video->prev_yuv);
        video->prev_yuv = fresh; video->prev_pixels = (uint32_t)pixels;
    } else if (dest_width != video->real_width || dest_height != video->real_height) {
        memset(video->prev_yuv, 0, pixels * 3 * sizeof(*video->prev_yuv));
    }
    video->mode420=params->mode420;
    video->strict=params->strict;
    video->bit_limit=length*8;video->truncated=0;
    video->real_width=dest_width;video->real_height=dest_height;
    video->width=(dest_width+(video->mode420?15:7)) & ~(video->mode420?15u:7u);
    video->height=(dest_height+(video->mode420?15:7)) & ~(video->mode420?15u:7u);
    video->output=rgba;memset(video->yuv,0,sizeof(video->yuv));
    video->bit_pos=0;video->txb=video->tyb=0;video->dc_y=video->dc_cb=video->dc_cr=0;
    for(int i=0;i<4;++i){video->index[i]=i;load_quant(video,i,params->quant[i],params->legacy_quant);}
    if(params->strict)for(int i=0;i<256;++i){
        video->calc_cr_g[i]=shift16(0x688000-i*0xd000);
        video->calc_cr_r[i]=shift16(-13369344+i*0x19900);
        video->calc_cb_g[i]=shift16(0x328000-i*0x6400);
        video->calc_cb_b[i]=shift16(-16875520+i*0x20400);
        video->calc_y[i]=shift16(-1187776+i*0x129fc);
    }
    uint32_t words = (compressed + 3) / 4;
    free(video->words);
    video->words = calloc(words + AST_JOURNAL, sizeof(uint32_t));
    if (!video->words) return BC_NO_MEMORY;
    for (uint32_t i = 0; i < words; ++i) {
        uint32_t at = i * 4, value = 0;
        for (uint32_t j = 0; j < 4 && at + j < length && i * 4 + j < compressed; ++j) value |= (uint32_t)payload[at + j] << (8 * j);
        video->words[i] = value;
    }
    video->word_count = words + AST_JOURNAL;
    if (params->rc4) {
        static const uint8_t key[16] = {'f','e','d','c','b','a','9','8','7','6','5','4','3','2','1','0'};
        uint8_t expanded[256]; for (int i = 0; i < 256; ++i) expanded[i] = key[i % 16];
        uint8_t m[256]; for (int i = 0; i < 256; ++i) m[i] = (uint8_t)i;
        unsigned j = 0;
        for (unsigned i = 0; i < 256; ++i) {
            uint8_t value = m[i];
            j = (j + value + (uint8_t)(int8_t)expanded[i]) & 0xFF;
            m[i] = m[j]; m[j] = value;
        }
        uint32_t x = 0, y = 0;
        for (uint32_t i = 0; i < words; ++i) {
            x = (x + 1) & 0xFF; uint8_t a = m[x];
            y = (y + a) & 0xFF; uint8_t b = m[y];
            m[x] = b; m[y] = a;
            video->words[i] ^= m[(a + b) & 0xFF];
        }
    }
    bc_status status=decode_blocks(video,compressed);
    return video->truncated?BC_PROTOCOL_ERROR:status;
}
void bc_ast_video_destroy(bc_ast_video *handle) {
    if (!handle) return;
    ast_video *video = (ast_video *)handle;
    free(video->words);
    free(video->prev_yuv);
    free(video);
}

#ifndef BC_ILO_VIDEO_INTERNAL_H
#define BC_ILO_VIDEO_INTERNAL_H
#include "bcontrol/kvm.h"
typedef struct {
    uint32_t pending;
    uint8_t count;
} bc_ilo_bits;
typedef struct {
    uint16_t colors[17];
    uint8_t count;
} bc_ilo_palette;
/* Wire bytes arrive least-significant bit first; each field is assembled MSB first. */
bc_status bc_ilo_bits_append(bc_ilo_bits *, uint8_t);
int bc_ilo_bits_take(bc_ilo_bits *, uint8_t count, uint16_t *);
void bc_ilo_palette_insert(bc_ilo_palette *, uint16_t color);
bc_status bc_ilo_palette_get(bc_ilo_palette *, uint8_t index, uint16_t *);
void bc_ilo_palette_prune(bc_ilo_palette *);
uint8_t bc_ilo_palette_bits(const bc_ilo_palette *);
bc_status bc_ilo_blit(bc_kvm_frame *, const uint16_t *tile, uint32_t x, uint32_t y,
    uint32_t height, uint8_t bits_per_color);
typedef struct bc_ilo_video bc_ilo_video;
bc_status bc_ilo_video_create(uint32_t max_width, uint32_t max_height, bc_ilo_video **);
bc_status bc_ilo_video_feed(bc_ilo_video *, const uint8_t *, uint32_t);
const bc_kvm_frame *bc_ilo_video_frame(const bc_ilo_video *);
int bc_ilo_video_take_ack(bc_ilo_video *);
void bc_ilo_video_ack_frame(bc_ilo_video *);
void bc_ilo_video_destroy(bc_ilo_video *);
#endif

#include "bcontrol/kvm.h"
#include "bcontrol/display.h"
#include <emscripten/emscripten.h>
#include <stdlib.h>

typedef struct {
    bc_kvm *decoder;
    bc_display_tile tile;
} web_decoder;

EMSCRIPTEN_KEEPALIVE void bc_web_decoder_destroy(web_decoder *s) {
    if (!s) return;
    bc_kvm_destroy(s->decoder);
    free(s);
}

EMSCRIPTEN_KEEPALIVE web_decoder *bc_web_decoder_create(void) {
    web_decoder *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    bc_kvm_options options = {.struct_size = sizeof(options), .abi_version = BC_ABI_VERSION};
    if (bc_kvm_create(&options, &s->decoder) != BC_OK) {
        bc_web_decoder_destroy(s); return NULL;
    }
    s->tile.struct_size = sizeof(s->tile);
    return s;
}

EMSCRIPTEN_KEEPALIVE bc_status bc_web_decoder_feed(web_decoder *s, const uint8_t *bytes, uint32_t length) {
    return s ? bc_kvm_feed(s->decoder, bytes, length) : BC_INVALID_ARGUMENT;
}
EMSCRIPTEN_KEEPALIVE int bc_web_decoder_ready(web_decoder *s) {
    return s && bc_kvm_handshake_complete(s->decoder);
}
/* Parser-generated negotiation and update requests; never keyboard/mouse input. */
EMSCRIPTEN_KEEPALIVE bc_status bc_web_decoder_output(web_decoder *s, uint8_t *bytes, uint32_t capacity, uint32_t *written) {
    return s ? bc_kvm_output(s->decoder, bytes, capacity, written) : BC_INVALID_ARGUMENT;
}
EMSCRIPTEN_KEEPALIVE bc_status bc_web_decoder_tile(web_decoder *s) {
    return s ? bc_display_tile_from_frame(bc_kvm_frame_get(s->decoder), &s->tile) : BC_INVALID_ARGUMENT;
}
EMSCRIPTEN_KEEPALIVE uint32_t bc_web_decoder_width(web_decoder *s) { return s ? bc_kvm_frame_get(s->decoder)->width : 0; }
EMSCRIPTEN_KEEPALIVE uint32_t bc_web_decoder_height(web_decoder *s) { return s ? bc_kvm_frame_get(s->decoder)->height : 0; }
EMSCRIPTEN_KEEPALIVE uint32_t bc_web_decoder_stride(web_decoder *s) { return s ? bc_kvm_frame_get(s->decoder)->stride : 0; }
EMSCRIPTEN_KEEPALIVE const uint8_t *bc_web_decoder_pixels(web_decoder *s) { return s ? s->tile.pixels.data : NULL; }
EMSCRIPTEN_KEEPALIVE void bc_web_decoder_ack(web_decoder *s) { if (s) bc_kvm_ack_frame(s->decoder); }
EMSCRIPTEN_KEEPALIVE const char *bc_web_decoder_name(web_decoder *s) {
    const bc_kvm_frame *frame = s ? bc_kvm_frame_get(s->decoder) : NULL;
    return frame ? frame->name.data : NULL;
}
EMSCRIPTEN_KEEPALIVE uint32_t bc_web_decoder_name_length(web_decoder *s) {
    const bc_kvm_frame *frame = s ? bc_kvm_frame_get(s->decoder) : NULL;
    return frame ? frame->name.length : 0;
}

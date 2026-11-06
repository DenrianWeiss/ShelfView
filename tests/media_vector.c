#include "bcontrol/bcontrol.h"
#include <stdio.h>
int main(void) {
    bc_media_header header = {BC_MEDIA_READ, 7, 0, UINT64_C(9007199254740993), 1, 4, 0};
    uint8_t frame[44]; uint32_t length; bc_media_header decoded;
    if (bc_media_read_encode(&header, 6, 128, 1024, frame) != BC_OK ||
        bc_media_read_decode(frame, 44, 128, 1024, &decoded, &length) != BC_OK || length != 6 ||
        decoded.request_id != header.request_id) return 1;
    for (unsigned i = 0; i < sizeof(frame); ++i) printf("%02x", frame[i]);
    putchar('\n'); return 0;
}

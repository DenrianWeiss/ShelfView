#include "bcontrol/kvm.h"
#include "bcontrol/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jpeglib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static void drain(bc_kvm *k) { uint8_t bytes[128]; uint32_t size; CHECK(bc_kvm_output(k, bytes, sizeof(bytes), &size) == BC_OK); }
int main(void) {
    struct jpeg_compress_struct jpeg; struct jpeg_error_mgr error;
    jpeg.err = jpeg_std_error(&error); jpeg_create_compress(&jpeg);
    unsigned char *encoded = NULL; unsigned long length = 0;
    jpeg_mem_dest(&jpeg, &encoded, &length);
    jpeg.image_width = jpeg.image_height = 2; jpeg.input_components = 3; jpeg.in_color_space = JCS_RGB;
    jpeg_set_defaults(&jpeg); jpeg_set_quality(&jpeg, 100, TRUE); jpeg_start_compress(&jpeg, TRUE);
    uint8_t red[6] = {255,0,0,255,0,0};
    while (jpeg.next_scanline < 2) { JSAMPROW row = red; CHECK(jpeg_write_scanlines(&jpeg, &row, 1) == 1); }
    jpeg_finish_compress(&jpeg); jpeg_destroy_compress(&jpeg);
    bc_kvm *k = NULL; bc_kvm_options options = {.struct_size=sizeof(options), .abi_version=BC_ABI_VERSION};
    CHECK(bc_kvm_create(&options, &k) == BC_OK);
    const uint8_t hello[] = "RFB 003.008\n\1\1\0\0\0\0";
    CHECK(bc_kvm_feed(k, hello, sizeof(hello)-1) == BC_OK); drain(k);
    uint8_t init[24] = {0,2,0,2,32,24,0,255,0,255,0,255,0,255,16,8};
    CHECK(bc_kvm_feed(k, init, sizeof(init)) == BC_OK); drain(k);
    uint8_t packet[24] = {0,0,0,1,0,0,0,0,0,2,0,2,0,0,0,7,0x90};
    unsigned count = 17; unsigned long remaining = length;
    do { uint8_t byte = remaining & 127; remaining >>= 7; packet[count++] = byte | (remaining ? 128 : 0); } while (remaining);
    CHECK(bc_kvm_feed(k, packet, count) == BC_OK);
    for (unsigned long i=0; i<length; ++i) CHECK(bc_kvm_feed(k, encoded+i, 1) == BC_OK);
    const bc_kvm_frame *frame = bc_kvm_frame_get(k);
    CHECK(frame->flags & BC_KVM_FRAME_READY);
    for (unsigned i=0; i<4; ++i) CHECK(frame->pixels[i*4] > 250 && frame->pixels[i*4+1] < 3 && frame->pixels[i*4+2] < 3 && frame->pixels[i*4+3] == 255);
    drain(k); bc_kvm_ack_frame(k);
    packet[16]=0x80; packet[17]=0; packet[18]=255; packet[19]=0;
    CHECK(bc_kvm_feed(k, packet, 20) == BC_OK); drain(k);
    CHECK(!memcmp(bc_kvm_frame_get(k)->pixels, "\0\xff\0\xff", 4));
    packet[16]=0x90; remaining=length; count=17;
    do { uint8_t byte=remaining&127; remaining>>=7; packet[count++]=byte|(remaining?128:0); } while(remaining);
    packet[11]=1; /* JPEG dimensions must match the enclosing RFB rectangle. */
    CHECK(bc_kvm_feed(k, packet, count) == BC_OK);
    CHECK(bc_kvm_feed(k, encoded, (uint32_t)length) == BC_PROTOCOL_ERROR);
    free(encoded); bc_kvm_destroy(k);
    puts("kvm-jpeg: fragmented Tight/JPEG, fill and dimension validation passed");
    return 0;
}

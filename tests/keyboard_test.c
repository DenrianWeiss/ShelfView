#include "bcontrol/keyboard.h"
#include <assert.h>
#include <string.h>

int main(void) {
    const uint32_t keys[][2] = {
        {0xffb0,0x62},{0xffb1,0x59},{0xffb2,0x5a},{0xffb3,0x5b},{0xffb4,0x5c},
        {0xffb5,0x5d},{0xffb6,0x5e},{0xffb7,0x5f},{0xffb8,0x60},{0xffb9,0x61},
        {0xffaa,0x55},{0xffab,0x57},{0xffac,0x85},{0xffad,0x56},{0xffae,0x63},
        {0xffaf,0x54},{0xffbd,0x67},{0xff8d,0x58},{0xff0d,0x28},
        {0xff95,0x5f},{0xff96,0x5c},{0xff97,0x60},{0xff98,0x5e},{0xff99,0x5a},
        {0xff9a,0x61},{0xff9b,0x5b},{0xff9c,0x59},{0xff9d,0x5d},{0xff9e,0x62},{0xff9f,0x63}
    };
    uint32_t pressed[32]={0}; uint8_t report[8], empty[8]={0};
    for (unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);++i) {
        uint8_t modifiers=255;
        assert(bc_keyboard_keysym_to_usage(keys[i][0],&modifiers)==keys[i][1] && modifiers==0);
        assert(bc_keyboard_report(pressed,keys[i][0],1,report)==BC_OK);
        assert(report[0]==0 && report[2]==keys[i][1]);
        assert(bc_keyboard_report(pressed,keys[i][0],0,report)==BC_OK);
        assert(!memcmp(report,empty,8));
    }
    assert(bc_keyboard_report(pressed,0xffe2,1,report)==BC_OK);
    assert(bc_keyboard_report(pressed,0xffb1,1,report)==BC_OK && report[0]==0x20 && report[2]==0x59);
    assert(bc_keyboard_report(pressed,0xffe2,0,report)==BC_OK && report[0]==0 && report[2]==0x59);
    assert(bc_keyboard_report(pressed,0xffb1,0,report)==BC_OK && !memcmp(report,empty,8));
    return 0;
}

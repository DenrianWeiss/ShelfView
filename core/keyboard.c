#include <string.h>
#include "bcontrol/keyboard.h"

uint32_t bc_keyboard_keysym_to_usage(uint32_t keysym, uint8_t *modifiers) {
    if (modifiers) *modifiers = 0;
    switch (keysym) {
    case 0x08: case 0xFF08: return 0x2A;
    case 0x09: case 0xFF09: return 0x2B;
    case 0x0A: case 0xFF0D: return 0x28;
    case 0xFF8D: return 0x58;
    case 0x1B: case 0xFF1B: return 0x29;
    case 0x7F: case 0xFFFF: return 0x4C;
    case 0xFF51: return 0x50; case 0xFF52: return 0x52;
    case 0xFF53: return 0x4F; case 0xFF54: return 0x51;
    case 0xFF50: return 0x4A; case 0xFF57: return 0x4D;
    case 0xFF55: return 0x4B; case 0xFF56: return 0x4E;
    case 0xFF63: return 0x49;
    case 0xFFE1: return 0xE1; case 0xFFE2: return 0xE5;
    case 0xFFE3: return 0xE0; case 0xFFE4: return 0xE4;
    case 0xFFE9: return 0xE2; case 0xFFEA: return 0xE6;
    case 0xFFEB: return 0xE3; case 0xFFEC: return 0xE7;
    case 0xFFE5: return 0x39; case 0xFF7F: return 0x53;
    case 0xFF14: return 0x47; case 0xFF61: return 0x46;
    case 0xFF13: return 0x48; case 0xFF67: return 0x65;
    case 0xFE20: if (modifiers) *modifiers = 0x02; return 0x2B;
    default: break;
    }
    if (keysym >= 0xFFBE && keysym <= 0xFFC9) return 0x3A + (keysym - 0xFFBE);
    if (keysym >= 0x61 && keysym <= 0x7A) return 0x04 + (keysym - 0x61);
    if (keysym >= 0x41 && keysym <= 0x5A) { if (modifiers) *modifiers = 0x02; return 0x04 + (keysym - 0x41); }
    if (keysym >= 0x31 && keysym <= 0x39) return 0x1E + (keysym - 0x31);
    if (keysym == 0x30) return 0x27;
    if (keysym == 0x20) return 0x2C;
    switch (keysym) {
    case 0x2D: return 0x2D; case 0x3D: return 0x2E; case 0x5B: return 0x2F;
    case 0x5D: return 0x30; case 0x5C: return 0x31; case 0x3B: return 0x33;
    case 0x27: return 0x34; case 0x60: return 0x35; case 0x2C: return 0x36;
    case 0x2E: return 0x37; case 0x2F: return 0x38;
    case 0x21: if (modifiers) *modifiers = 0x02; return 0x1E;
    case 0x40: if (modifiers) *modifiers = 0x02; return 0x1F;
    case 0x23: if (modifiers) *modifiers = 0x02; return 0x20;
    case 0x24: if (modifiers) *modifiers = 0x02; return 0x21;
    case 0x25: if (modifiers) *modifiers = 0x02; return 0x22;
    case 0x5E: if (modifiers) *modifiers = 0x02; return 0x23;
    case 0x26: if (modifiers) *modifiers = 0x02; return 0x24;
    case 0x2A: if (modifiers) *modifiers = 0x02; return 0x25;
    case 0x28: if (modifiers) *modifiers = 0x02; return 0x26;
    case 0x29: if (modifiers) *modifiers = 0x02; return 0x27;
    case 0x5F: if (modifiers) *modifiers = 0x02; return 0x2D;
    case 0x2B: if (modifiers) *modifiers = 0x02; return 0x2E;
    case 0x7B: if (modifiers) *modifiers = 0x02; return 0x2F;
    case 0x7D: if (modifiers) *modifiers = 0x02; return 0x30;
    case 0x7C: if (modifiers) *modifiers = 0x02; return 0x31;
    case 0x3A: if (modifiers) *modifiers = 0x02; return 0x33;
    case 0x22: if (modifiers) *modifiers = 0x02; return 0x34;
    case 0x7E: if (modifiers) *modifiers = 0x02; return 0x35;
    case 0x3C: if (modifiers) *modifiers = 0x02; return 0x36;
    case 0x3E: if (modifiers) *modifiers = 0x02; return 0x37;
    case 0x3F: if (modifiers) *modifiers = 0x02; return 0x38;
    default: return 0;
    }
}


bc_status bc_keyboard_report(uint32_t pressed[32], uint32_t keysym, int down, uint8_t out[8]) {
    if (!pressed || !out || (down != 0 && down != 1)) return BC_INVALID_ARGUMENT;
    if(!keysym && down) return BC_INVALID_ARGUMENT;
    uint32_t next[32];memcpy(next,pressed,sizeof(next));
    if(!keysym) memset(next,0,sizeof(next));
    else {
        if(!bc_keyboard_keysym_to_usage(keysym,NULL)) return BC_UNSUPPORTED;
        unsigned slot=32, empty=32;
        for(unsigned i=0;i<32;++i) {
            if(next[i]==keysym) slot=i;
            if(!next[i] && empty==32) empty=i;
        }
        if(down && slot==32) {if(empty==32) return BC_LIMIT_EXCEEDED;next[empty]=keysym;}
        if(!down && slot<32) next[slot]=0;
    }
    uint8_t report[8]={0};unsigned count=0;
    for(unsigned i=0;i<32;++i) if(next[i]) {
        uint8_t modifiers=0;
        uint32_t usage=bc_keyboard_keysym_to_usage(next[i],&modifiers);
        report[0]|=modifiers;
        if(usage>=0xe0 && usage<=0xe7) report[0]|=(uint8_t)(1u<<(usage-0xe0));
        else {
            unsigned j=0;while(j<count && report[2+j]!=usage) ++j;
            if(j==count) {if(count==6) return BC_LIMIT_EXCEEDED;report[2+count++]=(uint8_t)usage;}
        }
    }
    memcpy(out,report,sizeof(report));
    memcpy(pressed,next,sizeof(next));
    return BC_OK;
}

#include "bcontrol/aten.h"
#include "bcontrol/wire.h"
#include <string.h>
typedef struct {const uint8_t *p;uint32_t size;uint64_t sections;uint32_t count;} elf;
static uint64_t le(const uint8_t *p,unsigned n){return bc_wire_read_le(p,n);}
static const uint8_t *range(const elf *e,uint64_t at,uint64_t size){return at<=e->size && size<=e->size-at?e->p+(size_t)at:NULL;}
static const uint8_t *section(const elf *e,uint32_t index){return index<e->count?range(e,e->sections+(uint64_t)index*64,64):NULL;}
static const uint8_t *address(const elf *e,uint64_t at,uint64_t size){
    for(uint32_t i=0;i<e->count;++i){const uint8_t *s=section(e,i);if(!s)return NULL;
        uint64_t start=le(s+16,8),length=le(s+32,8),offset=le(s+24,8);
        if(le(s+4,4)==1 && at>=start && at-start<=length && size<=length-(at-start)) {
            if(offset>e->size || at-start>e->size-offset)return NULL;
            return range(e,offset+at-start,size);
        }
    }return NULL;
}
static const uint8_t *symbol(const elf *e,const char *name,uint64_t *va,uint32_t *size){
    const uint8_t *found=NULL;
    for(uint32_t i=0;i<e->count;++i){const uint8_t *s=section(e,i);if(!s)return NULL;
        if(le(s+4,4)!=11)continue;
        uint64_t length=le(s+32,8);if(le(s+56,8)!=24 || length%24)return NULL;
        const uint8_t *symbols=range(e,le(s+24,8),length),*strings_section=section(e,(uint32_t)le(s+40,4));
        if(!symbols || !strings_section)return NULL;
        uint64_t strings_size=le(strings_section+32,8);
        const uint8_t *strings=range(e,le(strings_section+24,8),strings_size);if(!strings)return NULL;
        for(uint64_t j=0;j<length;j+=24){const uint8_t *entry=symbols+j;uint32_t n=(uint32_t)le(entry,4);
            size_t wanted=strlen(name);if(n>=strings_size || wanted>=strings_size-n || memcmp(strings+n,name,wanted+1))continue;
            uint64_t bytes=le(entry+16,8),location=le(entry+8,8);
            if(found || (entry[4]&15)!=2 || !le(entry+6,2) || bytes>65536)return NULL;
            found=address(e,location,bytes);if(!found)return NULL;*va=location;*size=(uint32_t)bytes;
        }
    }return found;
}
static uint64_t relative(uint64_t next,const uint8_t *disp){
    uint32_t raw=(uint32_t)le(disp,4);
    return raw&0x80000000u?next-(uint64_t)(~raw+1u):next+raw;
}
bc_status bc_aten_native_media_layout(const uint8_t *data,uint32_t length,uint32_t *out){
    if(!out)return BC_INVALID_ARGUMENT;*out=0;
    if(!data || length<64)return BC_INVALID_ARGUMENT;
    if(length>16u*1024u*1024u)return BC_LIMIT_EXCEEDED;
    /* This is an inspected x86-64 ELF client layout, independent of the host CPU. */
    if(memcmp(data,"\177ELF\2\1\1",7) || le(data+18,2)!=62 || le(data+58,2)!=64)return BC_UNSUPPORTED;
    elf e={data,length,le(data+40,8),(uint32_t)le(data+60,2)};
    if(!e.count || !range(&e,e.sections,(uint64_t)e.count*64))return BC_PROTOCOL_ERROR;
    uint64_t va=0;uint32_t size=0;const uint8_t *name=symbol(&e,"GetFileDevStr",&va,&size);
    if(!name || size<80)return BC_UNSUPPORTED;
    static const uint8_t prefix[]={0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x20,0x48,0x89,0x75,0xf0,0x40,0x88,0x7d,0xff,
        0x0f,0xb6,0x45,0xff,0x83,0xe8,0x40,0x88,0x45,0xef,0x80,0x7d,0xef,0x04};
    static const uint8_t newer_switch[]={0x0f,0xbe,0x45,0xfc,0x83,0xe8,0x40,0x83,0xf8,0x05,0x0f,0x87};
    int newer = size >= 85 && !memcmp(name+52,newer_switch,sizeof(newer_switch));
    if (!newer && memcmp(name,prefix,sizeof(prefix))) return BC_UNSUPPORTED;
    uint32_t table_offset = newer ? 78 : 49;
    if (memcmp(name+table_offset,"\x48\x8d\x05",3)) return BC_UNSUPPORTED;
    uint64_t table=relative(va+table_offset+7,name+table_offset+3);
    const uint8_t *entry=address(&e,table,4);if(!entry)return BC_PROTOCOL_ERROR;
    uint64_t target=relative(table,entry);
    const char *iso = newer ? "ISO Image" : "ISO File";
    uint32_t label_offset = newer ? 9 : 4;
    const uint8_t *branch = address(&e,target,label_offset+7);
    if (!branch || (newer ? memcmp(branch+label_offset,"\x48\x8d\x35",3) :
        memcmp(branch,"\x48\x8b\x7d\xf0\x48\x8d\x15",7))) return BC_UNSUPPORTED;
    const uint8_t *label=address(&e,relative(target+label_offset+7,branch+label_offset+3),strlen(iso)+1);
    if(!label || memcmp(label,iso,strlen(iso)+1))return BC_UNSUPPORTED;
    const uint8_t *code=symbol(&e,"FillUSBPlugInPkt",&va,&size);if(!code)return BC_UNSUPPORTED;
    static const uint8_t assignment[]={0x80,0x7d,0xc7,0x40,0x74,0x02,0xeb,0x0d,0x48,0x8b,0x45,0xf0,0x48,0x83,0xc0,0x31,0xc6,0x00};
    static const uint8_t newer_assignment[]={0x80,0x7d,0xef,0x40,0x75,0x0d,0x48,0x8b,0x45,0xb0,0x48,0x83,0xc0,0x31,0xc6,0x00};
    const uint8_t *pattern = newer ? newer_assignment : assignment;
    size_t pattern_size = newer ? sizeof(newer_assignment) : sizeof(assignment);
    uint32_t result=0;
    for(uint32_t i=0;i+pattern_size+1<=size;++i)if(!memcmp(code+i,pattern,pattern_size)){
        uint32_t value=code[i+pattern_size];if(result || (value!=3 && value!=4))return BC_UNSUPPORTED;
        result=value==3?BC_SERVICE_ATEN_MEDIA_CD_3:BC_SERVICE_ATEN_MEDIA_CD_4;
    }
    if (newer) {
        if (result != BC_SERVICE_ATEN_MEDIA_CD_3 || !symbol(&e,"_Z19AppendDataIntegrityPhi",&va,&size)) return BC_UNSUPPORTED;
        result = BC_SERVICE_ATEN_MEDIA_CD_3_HMAC;
    }
    if(!result)return BC_UNSUPPORTED;*out=result;return BC_OK;
}

bc_status bc_aten_native_mouse_bytes(const uint8_t *data,uint32_t length,uint32_t *out){
    if(!out)return BC_INVALID_ARGUMENT;*out=0;
    if(!data || length<64)return BC_INVALID_ARGUMENT;
    if(length>16u*1024u*1024u)return BC_LIMIT_EXCEEDED;
    if(memcmp(data,"\177ELF\2\1\1",7) || le(data+18,2)!=62 || le(data+58,2)!=64)return BC_UNSUPPORTED;
    elf e={data,length,le(data+40,8),(uint32_t)le(data+60,2)};
    if(!e.count || !range(&e,e.sections,(uint64_t)e.count*64))return BC_PROTOCOL_ERROR;
    uint64_t va=0;uint32_t size=0;
    const uint8_t *code=symbol(&e,"_ZN8RFBMouse13ProcMouseInfoEv",&va,&size);
    if(!code || size!=72)return BC_UNSUPPORTED;
    static const uint8_t shape[]={
        0x53,0x48,0x8b,0x47,0x08,0x48,0x89,0xfb,0x48,0x8b,0x78,0x08,0xe8,0,0,0,0,
        0x0f,0xb6,0xc0,0x89,0x43,0x18,0x48,0x8b,0x43,0x08,0x48,0x8b,0x78,0x08,0xe8,0,0,0,0,
        0x0f,0xb6,0xc0,0x89,0x43,0x14,0x48,0x8b,0x43,0x08,0x48,0x8b,0x78,0x08,0xe8,0,0,0,0,
        0x0f,0xb6,0xc0,0xc6,0x43,0x10,0x01,0x89,0x43,0x1c,0xb8,0x01,0,0,0,0x5b,0xc3};
    for(uint32_t i=0;i<sizeof(shape);++i){
        if((i>=13 && i<17) || (i>=32 && i<36) || (i>=51 && i<55))continue;
        if(code[i]!=shape[i])return BC_UNSUPPORTED;
    }
    uint64_t target=relative(va+17,code+13);
    if(target!=relative(va+36,code+32) || target!=relative(va+55,code+51))return BC_UNSUPPORTED;
    *out=3;return BC_OK;
}
static int plt_symbol(const elf *e,uint64_t va,const char *wanted){
    const uint8_t *stub=address(e,va,6);
    if(!stub || stub[0]!=0xff || stub[1]!=0x25)return 0;
    uint64_t got=relative(va+6,stub+2);
    for(uint32_t i=0;i<e->count;++i){
        const uint8_t *r=section(e,i);if(!r || le(r+4,4)!=4)continue;
        uint64_t bytes=le(r+32,8);if(le(r+56,8)!=24 || bytes%24)return 0;
        const uint8_t *relocs=range(e,le(r+24,8),bytes),*syms=section(e,(uint32_t)le(r+40,4));
        if(!relocs || !syms || le(syms+4,4)!=11 || le(syms+56,8)!=24)return 0;
        const uint8_t *strsec=section(e,(uint32_t)le(syms+40,4));if(!strsec)return 0;
        const uint8_t *strings=range(e,le(strsec+24,8),le(strsec+32,8));if(!strings)return 0;
        for(uint64_t j=0;j<bytes;j+=24){
            const uint8_t *rel=relocs+j;if(le(rel,8)!=got || le(rel+8,4)!=7)continue;
            uint64_t index=le(rel+12,4),total=le(syms+32,8);
            if(total%24 || index>=total/24)return 0;
            const uint8_t *table=range(e,le(syms+24,8),total);if(!table)return 0;
            uint64_t n=le(table+index*24,4),len=le(strsec+32,8);size_t size=strlen(wanted);
            return n<len && size<len-n && !memcmp(strings+n,wanted,size+1);
        }
    }return 0;
}
bc_status bc_aten_native_mouse_cipher(const uint8_t *data,uint32_t length,uint32_t *out){
    if(!out)return BC_INVALID_ARGUMENT;*out=0;
    uint32_t mouse=0;bc_status status=bc_aten_native_mouse_bytes(data,length,&mouse);
    if(status!=BC_OK)return status;
    elf e={data,length,le(data+40,8),(uint32_t)le(data+60,2)};
    uint64_t va=0;uint32_t size=0;
    const uint8_t *code=symbol(&e,"_ZN10RFBKMCryto21RFB_AES128_EventCrytoEPhS0_",&va,&size);
    if(!code || size!=531)return BC_UNSUPPORTED;
    static const uint8_t key[]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint32_t keys=0,ivs=0;
    for(uint32_t i=0;i+5<=size;++i)if(!memcmp(code+i,"\xc6\x44\x24",3)){
        uint8_t at=code[i+3],value=code[i+4];
        if(at>=0x10 && at<0x20){uint32_t bit=1u<<(at-0x10);if((keys&bit)||value!=key[at-0x10])return BC_UNSUPPORTED;keys|=bit;}
        if(at>=0x70 && at<0x80){uint32_t bit=1u<<(at-0x70);if((ivs&bit)||value!=at-0x70)return BC_UNSUPPORTED;ivs|=bit;}
    }
    if(keys!=65535 || ivs!=65535 || memcmp(code+0x42,"\x4c\x8d\x4c\x24\x10",5) ||
        memcmp(code+0x51,"\x41\xb0\x01",3) || memcmp(code+0xd6,"\x48\x8d\x44\x24\x70",5) ||
        memcmp(code+0xfc,"\x31\xf6",2) || memcmp(code+0x18c,"\x31\xd2",2) ||
        memcmp(code+0x201,"\x48\x89\x44\x24\x08\xe8",6))return BC_UNSUPPORTED;
    if(!plt_symbol(&e,relative(va+0x20b,code+0x207),"_ZN10RFBKMCryto10SW_AES_CBCEiiPhiS0_S0_S0_"))return BC_UNSUPPORTED;
    *out=1;return BC_OK;
}

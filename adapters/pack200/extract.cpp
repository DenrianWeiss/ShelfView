#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <climits>
#include <cstddef>
#include "pack_memory.h"
#include "defines.h"
#include "bytes.h"
#include "utils.h"
#include "coding.h"
#include "bands.h"
#include "constants.h"
#include "zip.h"
#include "unpack.h"
extern "C" {
#include "jar.h"
}
static thread_local unpacker *active;
static thread_local size_t allocated;
static thread_local bool limited;
static thread_local const uint8_t *source;
static thread_local size_t source_size,source_offset;
static jlong read_input(unpacker *,void *out,jlong minimum,jlong maximum) {
    (void)minimum;size_t n=source_size-source_offset;
    if(maximum<0)return 0;
    if(n>(size_t)maximum)n=(size_t)maximum;
    if(n)std::memcpy(out,source+source_offset,n);source_offset+=n;return (jlong)n;
}
struct alignas(std::max_align_t) allocation {size_t size;allocation *previous,*next;};
static thread_local allocation *allocations;
void *bc_pack_malloc(size_t size) {
    if(!active || size>128u*1024u*1024u-allocated){limited=true;return nullptr;}
    allocation *p=(allocation *)std::malloc(sizeof(allocation)+size);if(!p)return nullptr;
    p->size=size;p->previous=nullptr;p->next=allocations;
    if(allocations)allocations->previous=p;allocations=p;allocated+=size;return p+1;
}
void bc_pack_free(void *pointer) {
    if(!pointer)return;
    allocation *p=(allocation *)pointer-1;volatile unsigned char *bytes=(volatile unsigned char *)pointer;
    for(size_t i=0;i<p->size;++i)bytes[i]=0;
    if(p->previous)p->previous->next=p->next;else allocations=p->next;
    if(p->next)p->next->previous=p->previous;
    std::free(p);
}
void *bc_pack_realloc(void *pointer,size_t size) {
    void *out=bc_pack_malloc(size);if(!out)return nullptr;
    if(pointer){allocation *p=(allocation *)pointer-1;std::memcpy(out,pointer,p->size<size?p->size:size);bc_pack_free(pointer);}
    return out;
}
unpacker *unpacker::non_mt_current=nullptr;
unpacker *unpacker::current(){return active;}
extern "C" bc_status bc_pack_extract(const uint8_t *data,uint32_t length,const char *const *names,uint32_t count,bc_jar_entry *entries) {
    if(active)return BC_BUSY;
    if(!data || !names || !entries || !count || count>64)return BC_INVALID_ARGUMENT;
    if(length>64u*1024u*1024u)return BC_LIMIT_EXCEEDED;
    unpacker engine;active=&engine;allocated=0;limited=false;source=data;source_size=length;source_offset=0;engine.init(read_input);
    engine.start();
    bc_status status=BC_OK;uint32_t files=0;
    while(!engine.aborting()) {
        unpacker::file *file=engine.get_next_file();if(!file)break;
        if(++files>8192 || file->size>16u*1024u*1024u){status=BC_LIMIT_EXCEEDED;break;}
        if(file->data[0].len+file->data[1].len!=file->size){status=BC_PROTOCOL_ERROR;break;}
        for(uint32_t i=0;i<count;++i)if(!std::strcmp(file->name,names[i])) {
            if(entries[i].data){status=BC_PROTOCOL_ERROR;break;}
            if(!file->size){status=BC_PROTOCOL_ERROR;break;}
            entries[i].data=(uint8_t *)std::malloc((size_t)file->size);
            if(!entries[i].data){status=BC_NO_MEMORY;break;}
            entries[i].length=(uint32_t)file->size;
            if(file->data[0].len)std::memcpy(entries[i].data,file->data[0].ptr,file->data[0].len);
            if(file->data[1].len)std::memcpy(entries[i].data+file->data[0].len,file->data[1].ptr,file->data[1].len);
        }
        if(status!=BC_OK)break;
    }
    if(limited)status=BC_LIMIT_EXCEEDED;
    else if(engine.aborting())status=BC_PROTOCOL_ERROR;
    else if(status==BC_OK && (engine.get_segments_remaining()!=0 || engine.input_remaining()!=0 || source_offset!=source_size))status=BC_UNSUPPORTED;
    engine.free();while(allocations)bc_pack_free(allocations+1);active=nullptr;source=nullptr;source_size=source_offset=0;
    for(uint32_t i=0;status==BC_OK && i<count;++i)if(!entries[i].data)status=BC_UNSUPPORTED;
    return status;
}

#include "jar.h"
#include <stdlib.h>
#include <string.h>
static void wipe_free(uint8_t *data, size_t size) {
    volatile uint8_t *p=data;
    for(size_t i=0;data && i<size;++i)p[i]=0;
    free(data);
}
#ifdef BC_JAR_ZLIB
#include <zlib.h>
bc_status bc_pack_extract(const uint8_t *,uint32_t,const char *const *,uint32_t,bc_jar_entry *);
static bc_status gzip_pack(const uint8_t *data,uint32_t size,const char *const *names,uint32_t count,bc_jar_entry *entries) {
    z_stream stream={0};stream.next_in=(Bytef *)data;stream.avail_in=size;
    if(inflateInit2(&stream,MAX_WBITS+16)!=Z_OK)return BC_NO_MEMORY;
    uint32_t capacity=65536;uint8_t *out=malloc(capacity);bc_status status=out?BC_OK:BC_NO_MEMORY;
    int result=Z_OK;
    while(status==BC_OK && result!=Z_STREAM_END) {
        if(stream.total_out==capacity){
            if(capacity==64u*1024u*1024u){status=BC_LIMIT_EXCEEDED;break;}
            uint8_t *grown=malloc(capacity*2);if(!grown){status=BC_NO_MEMORY;break;}
            memcpy(grown,out,stream.total_out);wipe_free(out,stream.total_out);
            out=grown;capacity*=2;
        }
        stream.next_out=out+stream.total_out;stream.avail_out=capacity-(uint32_t)stream.total_out;
        result=inflate(&stream,Z_NO_FLUSH);
        if(result!=Z_OK && result!=Z_STREAM_END)status=BC_PROTOCOL_ERROR;
    }
    if(status==BC_OK && (stream.avail_in || stream.total_out<4 || memcmp(out,"\xca\xfe\xd0\x0d",4)))status=BC_PROTOCOL_ERROR;
    if(status==BC_OK)status=bc_pack_extract(out,(uint32_t)stream.total_out,names,count,entries);
    wipe_free(out,stream.total_out);inflateEnd(&stream);return status;
}
static uint32_t little(const uint8_t *p, unsigned n) {
    uint32_t value = 0;
    for (unsigned i = 0; i < n; ++i) value |= (uint32_t)p[i] << (8 * i);
    return value;
}
static bc_status unpack(const uint8_t *jar, uint32_t limit, const uint8_t *entry, bc_jar_entry *out) {
    uint32_t flags = little(entry + 8, 2), method = little(entry + 10, 2);
    uint32_t crc = little(entry + 16, 4), packed = little(entry + 20, 4), size = little(entry + 24, 4);
    uint32_t name_length = little(entry + 28, 2), offset = little(entry + 42, 4);
    if (flags & ~0x080eu || (method != 0 && method != 8) || (method == 0 && (flags & 6)) || little(entry + 34, 2)) return BC_UNSUPPORTED;
    if (!size || size > 1024 * 1024 || packed > 16 * 1024 * 1024) return BC_LIMIT_EXCEEDED;
    if (offset > limit || limit - offset < 30) return BC_PROTOCOL_ERROR;
    const uint8_t *local = jar + offset;
    if (little(local, 4) != 0x04034b50 || little(local + 6, 2) != flags || little(local + 8, 2) != method ||
        little(local + 26, 2) != name_length) return BC_PROTOCOL_ERROR;
    uint32_t header = 30 + name_length + little(local + 28, 2);
    if (header > limit - offset || packed > limit - offset - header ||
        memcmp(local + 30, entry + 46, name_length)) return BC_PROTOCOL_ERROR;
    uint32_t local_crc = little(local + 14, 4), local_packed = little(local + 18, 4), local_size = little(local + 22, 4);
    if (flags & 8) {
        if ((local_crc && local_crc != crc) || (local_packed && local_packed != packed) || (local_size && local_size != size)) return BC_PROTOCOL_ERROR;
        uint32_t at = offset + header + packed;
        if (limit - at < 12) return BC_PROTOCOL_ERROR;
        if (little(jar + at, 4) == 0x08074b50) {
            if (limit - at < 16) return BC_PROTOCOL_ERROR;
            at += 4;
        }
        if (little(jar + at, 4) != crc || little(jar + at + 4, 4) != packed || little(jar + at + 8, 4) != size)
            return BC_PROTOCOL_ERROR;
    } else if (local_crc != crc || local_packed != packed || local_size != size) return BC_PROTOCOL_ERROR;
    uint8_t *data = malloc(size); if (!data) return BC_NO_MEMORY;
    bc_status status = BC_OK;
    if (method == 0) {
        if (packed != size) status = BC_PROTOCOL_ERROR;
        else memcpy(data, local + header, size);
    } else {
        z_stream stream; memset(&stream, 0, sizeof(stream));
        stream.next_in = (Bytef *)(local + header); stream.avail_in = packed;
        stream.next_out = data; stream.avail_out = size;
        int initialized = inflateInit2(&stream, -MAX_WBITS);
        if (initialized != Z_OK) status = initialized == Z_MEM_ERROR ? BC_NO_MEMORY : BC_PROTOCOL_ERROR;
        else {
            int result = inflate(&stream, Z_FINISH);
            if (result != Z_STREAM_END || stream.total_out != size || stream.total_in != packed) status = BC_PROTOCOL_ERROR;
            inflateEnd(&stream);
        }
    }
    if (status == BC_OK && (uint32_t)crc32(0, data, size) != crc) status = BC_PROTOCOL_ERROR;
    if (status == BC_OK) { out->data = data; out->length = size; }
    else wipe_free(data,size);
    return status;
}
bc_status bc_jar_extract(const uint8_t *jar, uint32_t length, const char *const *names,
    uint32_t count, bc_jar_entry *classes) {
    if (!jar || !names || !classes || !count) return BC_INVALID_ARGUMENT;
    if (length > 16u*1024u*1024u || count > 64) return BC_LIMIT_EXCEEDED;
    if(length>=4 && !memcmp(jar,"\xca\xfe\xd0\x0d",4))return bc_pack_extract(jar,length,names,count,classes);
    if(length>=2 && jar[0]==0x1f && jar[1]==0x8b)return gzip_pack(jar,length,names,count,classes);
    if (length < 22) return BC_PROTOCOL_ERROR;
    uint32_t end = length - 22, scanned = 0;
    while (little(jar + end, 4) != 0x06054b50 || little(jar + end + 20, 2) != length - end - 22) {
        if (!end || ++scanned > 65535) return BC_PROTOCOL_ERROR;
        --end;
    }
    const uint8_t *eocd = jar + end;
    uint32_t entries = little(eocd + 10, 2), bytes = little(eocd + 12, 4), start = little(eocd + 16, 4);
    if (little(eocd + 4, 2) || little(eocd + 6, 2) || entries == 65535 || little(eocd + 8, 2) != entries ||
        bytes == UINT32_MAX || start == UINT32_MAX) return BC_UNSUPPORTED;
    if (entries > 2048) return BC_LIMIT_EXCEEDED;
    if (start > end || bytes != end - start) return BC_PROTOCOL_ERROR;
    uint32_t at = start; bc_status status = BC_OK;
    for (uint32_t i = 0; i < entries && status == BC_OK; ++i) {
        if (at > end || end - at < 46 || little(jar + at, 4) != 0x02014b50) { status = BC_PROTOCOL_ERROR; break; }
        const uint8_t *entry = jar + at;
        uint32_t name = little(entry + 28, 2), record = 46 + name + little(entry + 30, 2) + little(entry + 32, 2);
        if (record > end - at) { status = BC_PROTOCOL_ERROR; break; }
        for (unsigned j = 0; j < count; ++j) {
            static const char versions[] = "META-INF/versions/";
            size_t suffix = strlen(names[j]);
            if (name > sizeof(versions) - 1 + suffix && !memcmp(entry + 46, versions, sizeof(versions) - 1) &&
                !memcmp(entry + 46 + name - suffix, names[j], suffix)) { status = BC_UNSUPPORTED; break; }
            if (name != strlen(names[j]) || memcmp(entry + 46, names[j], name)) continue;
            if (classes[j].data) status = BC_PROTOCOL_ERROR;
            else status = unpack(jar, start, entry, &classes[j]);
            break;
        }
        at += record;
    }
    if (status == BC_OK && at != end) status = BC_PROTOCOL_ERROR;
    for (uint32_t i = 0; status == BC_OK && i < count; ++i)
        if (!classes[i].data) status = BC_UNSUPPORTED;
    return status;
}
#else
bc_status bc_jar_extract(const uint8_t *jar, uint32_t size, const char *const *names, uint32_t count, bc_jar_entry *entries) {
    (void)jar; (void)size; (void)names; (void)count; (void)entries; return BC_UNSUPPORTED;
}
#endif
void bc_jar_entries_clear(bc_jar_entry *entries, uint32_t count) {
    for(uint32_t i=0;i<count;++i) {
        wipe_free(entries[i].data,entries[i].length); entries[i]=(bc_jar_entry){0};
    }
}

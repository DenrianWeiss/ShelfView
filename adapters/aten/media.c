#include "bcontrol/aten.h"
#include "bcontrol/media_factory.h"
#include "bcontrol/media_provider.h"
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/wire.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#define CAPACITY 65544u
#define MOUNT_PACKET_SIZE 226u
#define HMAC_SIZE 20u
#define CSW_SIZE 21u
typedef struct {
    bc_media_options io;
    bc_media_source source;
    bc_aten_media_ticket ticket;
    bc_media_session_info info;
    bc_service_profile profile;
    uint8_t input[CAPACITY],scratch[CAPACITY + CSW_SIZE],key,asc,device_id;
    uint32_t used,needed,phase,blocks,out_remaining,out_tag;
    uint64_t deadline,last,heartbeat;
    int allocated,closed;
} media;
static int html5(const media *m) { return m->ticket.layout == BC_SERVICE_ATEN_MEDIA_HTML5; }
static int modern_cd(const media *m) { return html5(m) || m->ticket.layout == BC_SERVICE_ATEN_MEDIA_CD_3_HMAC; }
static void rc4(uint8_t *data,uint32_t n) {
    static const uint8_t key[]="BX80570E3110Q814A447";
    uint8_t box[256];for(unsigned i=0;i<256;++i)box[i]=(uint8_t)i;
    unsigned j=0;for(unsigned i=0;i<256;++i){j=(j+box[i]+key[i%(sizeof(key)-1)])&255;uint8_t t=box[i];box[i]=box[j];box[j]=t;}
    unsigned i=0;j=0;while(n--){i=(i+1)&255;j=(j+box[i])&255;uint8_t t=box[i];box[i]=box[j];box[j]=t;*data++^=box[(box[i]+box[j])&255];}
    memset(box,0,sizeof(box));
}
static void header(const media *m,uint8_t *p,uint8_t endpoint,uint8_t tag,uint32_t n) {
    memset(p,0,8);p[0]=endpoint;p[3]=tag;
    if (endpoint == 0x22 && modern_cd(m)) p[2]=html5(m) ? m->device_id : 1;
    bc_wire_write_le(p+4,n,4);
}
static bc_status send(media *m,uint8_t endpoint,uint8_t tag,const uint8_t *data,uint32_t n) {
    if(n>65536)return BC_LIMIT_EXCEEDED;
    uint8_t *p=m->scratch;header(m,p,endpoint,tag,n);
    if(n)memmove(p+8,data,n);
    return m->io.emit(m->io.user,p,n+8);
}
static bc_status scsi_reply(media *m,const uint8_t *data,uint32_t size,uint32_t tag,uint32_t residue,int failed) {
    uint8_t p[13]={0x55,0x53,0x42,0x53};bc_wire_write_le(p+4,tag,4);bc_wire_write_le(p+8,residue,4);p[12]=(uint8_t)!!failed;
    if (size) {
        if (modern_cd(m)) {
            header(m,m->scratch,0x22,0,size);
            memcpy(m->scratch+8,data,size);
            uint8_t *status=m->scratch+8+size;
            header(m,status,0x22,0xff,sizeof(p));
            memcpy(status+8,p,sizeof(p));
            return m->io.emit(m->io.user,m->scratch,8+size+CSW_SIZE);
        }
        bc_status status=send(m,0x22,0,data,size);
        if (status!=BC_OK) return status;
    }
    return send(m,0x22,0xff,p,sizeof(p));
}
static bc_status csw(media *m,uint32_t tag,uint32_t residue,int failed) {
    return scsi_reply(m,NULL,0,tag,residue,failed);
}
static bc_status sense(media *m,uint32_t tag,uint32_t length,uint8_t key,uint8_t asc) {
    m->key=key;m->asc=asc;return csw(m,tag,length,1);
}
static bc_status scsi(media *m,const uint8_t *p,uint32_t n) {
    if(n!=31 || memcmp(p,"USBC",4) || p[13] || !p[14] || p[14]>16 || (p[12]&0x7f))return BC_PROTOCOL_ERROR;
    uint32_t tag=(uint32_t)bc_wire_read_le(p+4,4),length=(uint32_t)bc_wire_read_le(p+8,4);
    const uint8_t *c=p+15;uint8_t data[64]={0};uint32_t size=0,allocation=length;int clear_sense=0;
    ++m->info.requests;
    if(!(p[12]&0x80) && length){if(length>65536)return BC_LIMIT_EXCEEDED;m->out_remaining=length;m->out_tag=tag;m->key=7;m->asc=0x27;return BC_OK;}
    unsigned required=(c[0]==0xa8||c[0]==0xaa)?12:(c[0]>=0x20?10:6);
    if(p[14]<required)return sense(m,tag,length,5,0x24);
    switch(c[0]) {
    case 0x00:case 0x1e:case 0x1b:case 0xbb:break;
    case 0x03:
        if(c[1])return sense(m,tag,length,5,0x24);
        data[0]=0x70;data[2]=m->key;data[7]=10;data[12]=m->asc;size=18;allocation=c[4];clear_sense=1;break;
    case 0x12:
        if(c[1]||c[2])return sense(m,tag,length,5,0x24);
        data[0]=5;data[1]=0x80;data[2]=0;data[3]=2;data[4]=31;
        memcpy(data+8,"bControl",8);memcpy(data+16,"Virtual CD-ROM  ",16);memcpy(data+32,"0001",4);size=36;allocation=c[4];break;
    case 0x25:
        bc_wire_write_be(data,m->blocks-1,4);bc_wire_write_be(data+4,2048,4);size=8;break;
    case 0x28:case 0xa8: {
        uint32_t lba=(uint32_t)bc_wire_read_be(c+2,4),count=(uint32_t)bc_wire_read_be(c+(c[0]==0x28?7:6),c[0]==0x28?2:4);
        uint64_t bytes=(uint64_t)count*2048;
        if(lba>m->blocks||count>m->blocks-lba)return sense(m,tag,length,5,0x21);
        if(bytes!=length || !(p[12]&0x80))return sense(m,tag,length,5,0x24);
        uint32_t sent=0;uint8_t block[65536];
        while(sent<length){if(m->io.clock(m->io.user)>=m->deadline)return BC_TIMEOUT;
            uint32_t chunk=length-sent;if(chunk>sizeof(block))chunk=sizeof(block);
            bc_status status=m->source.read(m->source.userdata,(uint64_t)lba*2048+sent,chunk,block);
            if(status!=BC_OK)return sense(m,tag,length-sent,3,0x11);
            int final = chunk == length-sent;
            status=final?scsi_reply(m,block,chunk,tag,0,0):send(m,0x22,0,block,chunk);
            if(status!=BC_OK)return status;
            sent+=chunk;m->info.bytes_read+=chunk;m->info.bytes_served+=chunk;
            if(final)return BC_OK;
        }
        return csw(m,tag,0,0);
    }
    case 0x1a:case 0x5a:
        if((c[2]&0x3f)!=0x3f && (c[2]&0x3f)!=0x2a && (c[2]&0x3f)!=0)return sense(m,tag,length,5,0x24);
        size=c[0]==0x1a?4:8;data[c[0]==0x1a?2:3]=0x80;
        if((c[2]&0x3f)!=0){data[size]=0x2a;data[size+1]=18;data[size+2]=3;size+=20;}
        if(c[0]==0x1a){data[0]=(uint8_t)(size-1);allocation=c[4];}else{bc_wire_write_be(data,size-2,2);allocation=(uint32_t)bc_wire_read_be(c+7,2);}break;
    case 0x43: {
        unsigned format=c[2]&15;
        if (!format && (c[9]&0xc0)==0x40) format=1;
        if(format>1 || (c[6]!=0 && c[6]!=1 && c[6]!=0xaa))return sense(m,tag,length,5,0x24);
        if (format==1) {
            size=12;data[1]=10;data[2]=data[3]=1;data[5]=0x14;data[6]=1;
            if (c[1]&2) data[10]=2;
            allocation=(uint32_t)bc_wire_read_be(c+7,2);break;
        }
        size=c[6]==0xaa?12:20;bc_wire_write_be(data,size-2,2);data[2]=data[3]=1;
        for(uint32_t i=4;i<size;i+=8){int lead=c[6]==0xaa || i==12;data[i+1]=0x14;data[i+2]=lead?0xaa:1;
            uint32_t address=lead?m->blocks:0;if(c[1]&2){address+=150;data[i+5]=(uint8_t)(address/(75*60));data[i+6]=(uint8_t)(address/75%60);data[i+7]=(uint8_t)(address%75);}else bc_wire_write_be(data+i+4,address,4);}
        allocation=(uint32_t)bc_wire_read_be(c+7,2);break;
    }
    case 0x46: {
        size=8;data[7]=8;allocation=(uint32_t)bc_wire_read_be(c+7,2);
        if (modern_cd(m)) {
            static const uint8_t features[][12]={
                {0,0,3,4,0,8,1,0},
                {0,1,3,4,0,0,0,2},
                {0,2,7,4,0,0,0,0},
                {0,3,3,4,0x29,0,0,0},
                {0,0x10,1,8,0,0,8,0,0,0,1,0},
                {0,0x1e,5,4,0,0,0,0}
            };
            uint32_t type=c[1]&3;
            if (type==3) return sense(m,tag,length,5,0x24);
            uint64_t start=bc_wire_read_be(c+2,2);
            for (size_t i=0;i<sizeof(features)/sizeof(features[0]);++i) {
                uint64_t feature=bc_wire_read_be(features[i],2);
                if (feature<start || (type==2 && feature!=start)) continue;
                uint32_t bytes=4u+features[i][3];
                memcpy(data+size,features[i],bytes);
                size+=bytes;
            }
        }
        bc_wire_write_be(data,size-4,4);break;
    }
    case 0x4a:
        if(c[1]!=1)return sense(m,tag,length,5,0x24);
        size=8;data[1]=6;data[2]=4;data[3]=0x10;data[5]=2;allocation=(uint32_t)bc_wire_read_be(c+7,2);break;
    case 0x51:
        if (c[1]) return sense(m,tag,length,5,0x24);
        size=34;data[1]=32;data[2]=0x0e;data[3]=data[4]=data[5]=data[6]=1;
        data[7]=0x20;memset(data+16,0xff,8);
        allocation=(uint32_t)bc_wire_read_be(c+7,2);break;
    case 0x52:
        if (c[1]!=1 || bc_wire_read_be(c+2,4)!=1) return sense(m,tag,length,5,0x24);
        size=28;data[1]=28;data[2]=data[3]=1;data[5]=4;data[6]=1;
        bc_wire_write_be(data+24,m->blocks,4);
        allocation=(uint32_t)bc_wire_read_be(c+7,2);break;
    case 0x2a:case 0xaa:case 0x15:case 0x55:return sense(m,tag,length,7,0x27);
    default:return sense(m,tag,length,5,0x20);
    }
    if(size>allocation)size=allocation;if(size>length)size=length;
    if(size && !(p[12]&0x80))return sense(m,tag,length,5,0x24);
    bc_status status=scsi_reply(m,data,size,tag,length-size,0);
    if(status==BC_OK)m->info.bytes_served+=size;
    if(status==BC_OK&&clear_sense)m->key=m->asc=0;return status;
}
static bc_status setup(media *m) {
    const bc_aten_launch *t=&m->ticket.launch;
    if(!memchr(t->username,0,sizeof(t->username)) || !memchr(t->password,0,sizeof(t->password)))return BC_INVALID_ARGUMENT;
    if(strlen(t->username)>16||strlen(t->password)>20)return BC_UNSUPPORTED;
    int integrity = m->ticket.layout == BC_SERVICE_ATEN_MEDIA_CD_3_HMAC;
    uint8_t p[MOUNT_PACKET_SIZE + HMAC_SIZE]={0};
    p[1]=html5(m) ? 0 : 0x80;p[3]=1;bc_wire_write_le(p+4,44,4);
    memcpy(p+8,t->username,strlen(t->username));memcpy(p+24,t->password,strlen(t->password));
    if(RAND_bytes(p+44,4)!=1)return BC_IO_ERROR;
    if (html5(m)) { p[44]=p[45]=0; p[46]&=0x7f; }
    p[48]=html5(m) ? 0xc3 : 0x83;p[49]=m->ticket.layout==BC_SERVICE_ATEN_MEDIA_CD_4?4:3;
    const uint8_t descriptors[]={
        18,18,1,0,2,0,0,0,64,
        html5(m) ? 0x1f : 0xa0,html5(m) ? 0x0b : 0x0e,html5(m) ? 0xea : 0x11,html5(m) ? 0x03 : 0x11,0,2,0,0,0,1,
        39,9,2,39,0,1,1,0,0x80,0x64,9,4,0,0,3,8,modern_cd(m) ? 6 : 5,0x50,0,
        7,5,1,2,0,2,0xff,7,5,0x82,2,0,2,0xff,7,5,0x83,3,2,0,1,
        4,4,3,9,4
    };
    uint32_t at=52;
    memcpy(p + at, descriptors, sizeof(descriptors));
    at += sizeof(descriptors);
    const char *strings[]={
        modern_cd(m) ? "Flash Disk      " : "Virtual CD-ROM  ",
        modern_cd(m) ? "4E8F092C3FD7F8F7" : "0000000000000001",
        modern_cd(m) ? "SN000PQI009 " : "bControl CD "
    };
    for(unsigned i=0;i<3;++i){uint32_t len=(uint32_t)strlen(strings[i])*2+2;p[at++]=(uint8_t)len;p[at++]=(uint8_t)len;p[at++]=3;for(const char *s=strings[i];*s;++s){p[at++]=(uint8_t)*s;p[at++]=0;}}
    const uint8_t tail[]={1,0,10,10,6,0,2,0,0,0,64,1,0};memcpy(p+at,tail,sizeof(tail));at+=sizeof(tail);
    if (at != MOUNT_PACKET_SIZE) return BC_PROTOCOL_ERROR;
    if (integrity) {
        char key[sizeof(t->username) + sizeof(t->password)];
        size_t user_length = strlen(t->username), password_length = strlen(t->password);
        memcpy(key, t->username, user_length);
        memcpy(key + user_length, t->password, password_length);
        unsigned length = 0;
        int ok = HMAC(EVP_sha1(), key, (int)(user_length + password_length), p, at, p + at, &length) && length == HMAC_SIZE;
        OPENSSL_cleanse(key, sizeof(key));
        if (!ok) {
            OPENSSL_cleanse(p, sizeof(p));
            return BC_IO_ERROR;
        }
        at += length;
    } else if (!html5(m)) rc4(p+8,at-8);
    m->phase=1;m->info.flags|=BC_MEDIA_REMOVAL_UNCONFIRMED;
    bc_status status=m->io.emit(m->io.user,p,at);OPENSSL_cleanse(p,sizeof(p));memset(&m->ticket.launch,0,sizeof(m->ticket.launch));return status;
}
static bc_status packet(media *m,uint8_t *p,uint32_t n) {
    uint32_t length=n-8;uint8_t tag=p[3];++m->info.packets;
    if(p[1]&~0x82u)return BC_UNSUPPORTED;if(p[1]&0x80)rc4(p+8,length);
    if(tag==2 && m->phase==1){
        if((length!=5 && length!=9) || p[0])return BC_PROTOCOL_ERROR;m->info.device_code=p[8];
        if(p[8]){m->phase=4;m->info.flags&=~BC_MEDIA_REMOVAL_UNCONFIRMED;return p[8]==2||p[8]==4?BC_BUSY:p[8]==1||p[8]==3||p[8]==6?BC_AUTHENTICATION_FAILED:BC_UNSUPPORTED;}
        m->allocated=1;m->phase=2;uint8_t endpoints[]={6,3,1,0x10,2,0x20,3,0x30};bc_status status=send(m,0,7,endpoints,sizeof(endpoints));
        if(status==BC_OK){m->info.flags|=BC_MEDIA_CONNECTED|BC_MEDIA_READY|BC_MEDIA_MOUNT_CONFIRMED;m->profile.evidence|=BC_SERVICE_EVIDENCE_HANDSHAKE;}
        return status;
    }
    if (tag==6 && (m->phase==3 || (html5(m) && m->phase==2))) {
        if ((!html5(m) || length) && (length!=1 || p[8])) return BC_PROTOCOL_ERROR;
        m->allocated=0;m->phase=4;
        m->info.flags&=~(BC_MEDIA_CONNECTED|BC_MEDIA_MOUNT_CONFIRMED|BC_MEDIA_REMOVAL_UNCONFIRMED|BC_MEDIA_EJECTING|BC_MEDIA_READY|BC_MEDIA_SOURCE_ATTACHED);
        m->info.flags|=BC_MEDIA_REMOVAL_CONFIRMED;
        return BC_OK;
    }
    if(tag==3)return length<=4?BC_OK:BC_PROTOCOL_ERROR;
    if (tag==4) {
        static const uint8_t alive[] = {255, 255, 255, 255};
        if (length>4) return BC_PROTOCOL_ERROR;
        return html5(m) ? send(m,0,3,alive,sizeof(alive)) : send(m,0,3,p+8,length);
    }
    if(m->phase!=2 && m->phase!=3)return BC_PROTOCOL_ERROR;
    if((tag==0 || tag==0xff) && p[0]==0x11){
        if(m->out_remaining){if(!length||length>m->out_remaining)return BC_PROTOCOL_ERROR;m->out_remaining-=length;return m->out_remaining?BC_OK:csw(m,m->out_tag,0,1);}
        m->device_id=p[2];
        return scsi(m,p+8,length);
    }
    return BC_UNSUPPORTED;
}
static bc_status poll(void *user,uint32_t timeout) {
    media *m=user;if(m->closed)return BC_SHUTTING_DOWN;
    uint64_t now=m->io.clock(m->io.user);if(now<m->last)return BC_INVALID_ARGUMENT;m->last=now;
    if(m->phase==2)m->deadline=now+m->io.timeout_ms;
    if(now>=m->deadline)return BC_TIMEOUT;
    uint32_t remaining=(uint32_t)(m->deadline-now);if(timeout>remaining)timeout=remaining;
    uint32_t got=0;bc_status status=m->io.receive(m->io.user,m->input+m->used,m->needed-m->used,&got,timeout);
    if(status==BC_TIMEOUT)status=BC_OK;
    else if(status==BC_OK){if(!got||got>m->needed-m->used)return BC_PROTOCOL_ERROR;m->used+=got;
        if(m->used==8 && m->needed==8){uint32_t size=(uint32_t)bc_wire_read_le(m->input+4,4);if(size>65536)return BC_LIMIT_EXCEEDED;m->needed=8+size;}
        if(m->used==m->needed){status=packet(m,m->input,m->used);m->used=0;m->needed=8;}
    }
    if(status==BC_OK && m->phase==2 && !html5(m) && now-m->heartbeat>=10000){status=send(m,0,4,NULL,0);m->heartbeat=now;}
    if(status!=BC_OK){m->info.status=status;m->info.flags|=BC_MEDIA_FAILED;m->info.flags&=~BC_MEDIA_READY;}
    return status;
}
static bc_status control(void *user,uint32_t op) {
    media *m=user;uint64_t now=m->io.clock(m->io.user);bc_status status=BC_OK;
    if(op==BC_MEDIA_CONTROL_START){if(m->phase)return BC_BUSY;m->last=m->heartbeat=now;m->deadline=now+m->io.timeout_ms;return setup(m);}
    if(op==BC_MEDIA_CONTROL_KEEPALIVE)return send(m,0,4,NULL,0);
    if(op!=BC_MEDIA_CONTROL_CLOSE && op!=BC_MEDIA_CONTROL_EJECT)return BC_UNSUPPORTED;
    if(m->closed)return BC_OK;
    m->deadline=now+3000;
    while(m->phase==1 && status==BC_OK)status=poll(m,20);
    if(m->allocated){m->phase=3;m->info.flags|=BC_MEDIA_EJECTING;m->info.flags&=~BC_MEDIA_READY;status=send(m,0,5,NULL,0);
        while(m->allocated && status==BC_OK)status=poll(m,20);}
    if(op==BC_MEDIA_CONTROL_CLOSE)m->closed=1;
    if(m->info.flags&BC_MEDIA_REMOVAL_UNCONFIRMED)return status==BC_OK?BC_OUTCOME_UNKNOWN:status;
    return status;
}
static bc_status info(const void *user,bc_media_session_info *out){const media *m=user;*out=m->info;out->state=m->phase;return BC_OK;}
static const bc_service_profile *profile(const void *user){return &((const media *)user)->profile;}
static void destroy(void *user){memset(user,0,sizeof(media));free(user);}
bc_status bc_aten_media_create(const bc_media_options *o,bc_media_session **out) {
    if(!out)return BC_INVALID_ARGUMENT;*out=NULL;
    if(!o||o->struct_size!=sizeof(*o)||!o->source||o->source->struct_size!=sizeof(*o->source)||!o->source->read||
        !o->source->size||o->source->size%2048||o->source->size/2048>UINT32_MAX||!o->emit||!o->receive||!o->clock||!o->timeout_ms||o->flags||o->instance)return BC_INVALID_ARGUMENT;
    const bc_aten_media_ticket *ticket=bc_media_offer_payload(o->offer,BC_MEDIA_OFFER_ATEN,sizeof(*ticket));
    if(!ticket || (ticket->layout!=BC_SERVICE_ATEN_MEDIA_CD_4 && ticket->layout!=BC_SERVICE_ATEN_MEDIA_CD_3 &&
        ticket->layout!=BC_SERVICE_ATEN_MEDIA_HTML5 &&
        (ticket->layout!=BC_SERVICE_ATEN_MEDIA_CD_3_HMAC || !ticket->launch.tls)))return BC_UNSUPPORTED;
    media *m=calloc(1,sizeof(*m));if(!m)return BC_NO_MEMORY;m->io=*o;m->source=*o->source;m->ticket=*ticket;m->needed=8;m->blocks=(uint32_t)(m->source.size/2048);
    m->info.struct_size=sizeof(m->info);m->info.flags=BC_MEDIA_SOURCE_ATTACHED|BC_MEDIA_BYTES_READ_VALID;m->info.heartbeat_interval_ms=10000;
    m->profile=(bc_service_profile){sizeof(m->profile),BC_SERVICE_LOCAL_MEDIA,BC_SERVICE_FAMILY_ATEN,ticket->layout,BC_SERVICE_EVIDENCE_DESCRIPTOR|BC_SERVICE_EVIDENCE_MANUAL};
    bc_media_provider provider={sizeof(provider),NULL,poll,control,info,NULL,destroy,profile,NULL};
    bc_status status=bc_media_session_wrap(&provider,m,out);if(status!=BC_OK)destroy(m);return status;
}

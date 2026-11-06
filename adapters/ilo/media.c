#include "bcontrol/ilo_media.h"
#include "bcontrol/media_provider.h"
#include "bcontrol/wire.h"
#include "wire.h"
#include <stdlib.h>
#include <string.h>
#define READ_LIMIT (1024u * 1024u)
struct bc_ilo_media {
    bc_ilo_media_source source;
    bc_ilo_media_emit emit;
    void *user;
    bc_ilo_media_state state;
    bc_status failure;
    bc_console_failure detail;
    uint32_t sector, kind;
    uint8_t changed;
    int removal_unconfirmed;
};
static bc_status header(bc_ilo_media *m, uint8_t key, uint8_t asc, uint32_t length, uint32_t flags) {
    uint8_t data[16]={0};
    bc_wire_write_le(data,0x0badc0de,4);
    bc_wire_write_le(data+4,flags|1u,4);
    data[8]=m->state.attached?(m->kind==BC_ILO_MEDIA_FLOPPY?36:1):0;
    data[9]=key;data[10]=asc;bc_wire_write_le(data+12,length,4);
    bc_status s=m->emit(m->user,data,sizeof(data));
    if(s!=BC_OK) m->failure=s;
    return s;
}
static bc_status payload(bc_ilo_media *m,const uint8_t *data,uint32_t length) {
    bc_status s=header(m,0,0,length,0);
    if(s==BC_OK && length) s=m->emit(m->user,data,length);
    if(s!=BC_OK) m->failure=s;
    return s;
}
bc_status bc_ilo_media_create(uint32_t kind,bc_string token,const bc_ilo_media_source *source,
    bc_ilo_media_emit emit,void *user,bc_ilo_media **out) {
    if(!out) return BC_INVALID_ARGUMENT;
    *out=NULL;
    if((kind!=2 && kind!=3 && kind!=4) || !source || !source->read || !emit) return BC_INVALID_ARGUMENT;
    uint32_t sector=kind==BC_ILO_MEDIA_CD?2048:512;
    if(!source->size || source->size%sector || source->size/sector>UINT32_MAX) return BC_INVALID_ARGUMENT;
    uint8_t hello[54];bc_status s=bc_ilo5_client_hello(token,(uint8_t)kind,hello);
    if(s!=BC_OK) return s;
    bc_ilo_media *m=calloc(1,sizeof(*m));
    if(!m) s=BC_NO_MEMORY;
    else {
        m->source=*source;m->emit=emit;m->user=user;m->sector=sector;m->kind=kind;
        m->state.attached=1;m->changed=1;m->removal_unconfirmed=1;
        s=emit(user,hello,sizeof(hello));
    }
    volatile uint8_t *wipe=hello;for(unsigned i=0;i<sizeof(hello);++i) wipe[i]=0;
    if(s!=BC_OK) {free(m);return s;}
    *out=m;return BC_OK;
}
bc_status bc_ilo_media_feed(bc_ilo_media *m,const uint8_t *data,uint32_t size) {
    if(!m || !data) return BC_INVALID_ARGUMENT;
    if(m->failure!=BC_OK) return m->failure;
    if(!m->state.authenticated) {
        uint8_t code;bc_status s=bc_ilo5_server_hello(data,size,&code);
        if(s==BC_OK) {
            m->state.server_status=code;
            if(code) s=code==6 || code==33?BC_BUSY:code==35 || code==37?BC_UNSUPPORTED:BC_AUTHENTICATION_FAILED;
            else m->state.authenticated=1;
        }
        if(s!=BC_OK) m->failure=s;
        return s;
    }
    if(size!=12) return m->failure=BC_PROTOCOL_ERROR;
    uint8_t cmd=data[0];
    if(cmd==0x2a || cmd==0xaa) return header(m,7,0x27,0,0);
    if(cmd==0x1b) {
        bc_status s=header(m,0,0,0,0);
        return s==BC_OK && (data[4]&3)==2?bc_ilo_media_eject(m):s;
    }
    if(cmd==0x1e) return header(m,(data[4]&2)?5:0,(data[4]&2)?0x24:0,0,0);
    if(!m->state.attached) return header(m,2,0x3a,0,0);
    if(m->changed) {m->changed=0;return header(m,6,0x28,0,0);}
    if(cmd==0) return header(m,0,0,0,0);
    if(cmd==0x25) {
        uint8_t capacity[8];bc_wire_write_be(capacity,m->source.size/m->sector-1,4);
        bc_wire_write_be(capacity+4,m->sector,4);return payload(m,capacity,sizeof(capacity));
    }
    if(cmd==0x23 && m->sector==512) {
        uint8_t capacity[20]={0,0,0,16,0,0,0,0,2,0,2,0,0,0,11,64,0,0,2,0};
        bc_wire_write_be(capacity+4,m->source.size/512,4);return payload(m,capacity,sizeof(capacity));
    }
    if(cmd==0xfa && m->sector==512) {uint8_t zeros[255]={0};return payload(m,zeros,data[1]);}
    if(cmd!=0x28 && cmd!=0xa8) return header(m,5,0x24,0,0);
    uint64_t offset=bc_wire_read_be(data+2,4)*m->sector;
    uint64_t length=bc_wire_read_be(data+(cmd==0x28?7:6),cmd==0x28?2:4)*m->sector;
    if(bc_media_range_check(m->source.size,offset,length)!=BC_OK) return header(m,5,0x21,0,0);
    if(length>READ_LIMIT) return header(m,5,0x24,0,0);
    if(!length) return header(m,0,0,0,0);
    uint8_t *buffer=malloc((size_t)length);if(!buffer) return m->failure=BC_NO_MEMORY;
    bc_status s=m->source.read(m->source.userdata,offset,(uint32_t)length,buffer);
    if(s==BC_OK) {s=payload(m,buffer,(uint32_t)length);if(s==BC_OK) m->state.bytes_read+=length;}
    else s=header(m,3,0x10,0,0);
    free(buffer);return s;
}
bc_status bc_ilo_media_heartbeat(bc_ilo_media *m) {
    if(!m) return BC_INVALID_ARGUMENT;
    if(m->failure!=BC_OK) return m->failure;
    if(!m->state.authenticated) return BC_BUSY;
    return header(m,0,0,0,2);
}
bc_status bc_ilo_media_eject(bc_ilo_media *m) {
    if(!m) return BC_INVALID_ARGUMENT;
    if(m->failure!=BC_OK) return m->failure;
    if(!m->state.authenticated) return BC_BUSY;
    m->state.attached=0;return header(m,0,0,0,4);
}
const bc_ilo_media_state *bc_ilo_media_state_get(const bc_ilo_media *m) {return m?&m->state:NULL;}
void bc_ilo_media_destroy(bc_ilo_media *m) {free(m);}

static bc_status media_result(bc_ilo_media *media, bc_status status) {
    if (status != BC_OK) {
        uint32_t code = media->state.server_status;
        uint32_t cause = code == 1 || code == 38 ? BC_CONSOLE_CAUSE_ACCESS_DENIED :
            code == 6 || code == 33 ? BC_CONSOLE_CAUSE_BUSY :
            code == 34 || code == 36 ? BC_CONSOLE_CAUSE_SESSION_EXPIRED :
            code == 35 ? BC_CONSOLE_CAUSE_LICENSE_REQUIRED : code == 37 ? BC_CONSOLE_CAUSE_NOT_CONFIGURED :
            BC_CONSOLE_CAUSE_PROTOCOL;
        media->detail = (bc_console_failure){sizeof(media->detail), status, BC_CONSOLE_PHASE_MEDIA,
            cause, 0, 0, (int32_t)code, BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_ILO};
    }
    return status;
}
static bc_status media_feed(void *context, bc_bytes bytes) {
    return media_result(context, bc_ilo_media_feed(context, bytes.data, (uint32_t)bytes.length));
}
static bc_status media_control(void *context, uint32_t command) {
    if (command == BC_MEDIA_CONTROL_START) return BC_OK;
    return media_result(context, command == BC_MEDIA_CONTROL_KEEPALIVE ?
        bc_ilo_media_heartbeat(context) : bc_ilo_media_eject(context));
}
static bc_status media_info(const void *context, bc_media_session_info *out) {
    const bc_ilo_media_state *state = bc_ilo_media_state_get(context);
    out->flags = BC_MEDIA_BYTES_READ_VALID | (state->authenticated ? BC_MEDIA_CONNECTED : 0) |
        (state->attached ? BC_MEDIA_SOURCE_ATTACHED : 0);
    out->bytes_read = state->bytes_read;
    out->state = state->authenticated ? 2 : 1;
    out->status = ((const bc_ilo_media *)context)->failure;
    out->device_code = state->server_status;
    out->heartbeat_interval_ms = 2000;
    if (((const bc_ilo_media *)context)->removal_unconfirmed) out->flags |= BC_MEDIA_REMOVAL_UNCONFIRMED;
    if (out->status != BC_OK) { out->state = 4; out->flags |= BC_MEDIA_FAILED; }
    return BC_OK;
}
static void media_destroy(void *context) { bc_ilo_media_destroy(context); }
static const bc_console_failure *media_failure(const void *context) {
    const bc_ilo_media *media = context;
    return media->detail.status != BC_OK ? &media->detail : NULL;
}
bc_status bc_ilo_media_wrap(bc_ilo_media *media, bc_media_session **out) {
    const bc_media_provider provider = {sizeof(provider), media_feed, NULL, media_control, media_info, NULL, media_destroy, NULL, media_failure};
    return bc_media_session_wrap(&provider, media, out);
}

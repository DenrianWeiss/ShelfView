#ifndef BC_TEST_MEGARAC_CLASS_FIXTURE
#define BC_TEST_MEGARAC_CLASS_FIXTURE
#include <stdint.h>
#include <assert.h>
#include <string.h>
#ifdef BC_TEST_JAR
#include <zlib.h>
#endif
typedef struct { uint8_t data[24576]; uint32_t size; } fixture;
static void put(fixture *f, uint32_t n, uint32_t value) {
    for (uint32_t i = 0; i < n; ++i) f->data[f->size++] = (uint8_t)(value >> ((n - i - 1) * 8));
}
static void utf(fixture *f, const char *s) {
    put(f, 1, 1); put(f, 2, (uint32_t)strlen(s));
    memcpy(f->data + f->size, s, strlen(s)); f->size += (uint32_t)strlen(s);
}
static inline uint32_t media_cp_utf(fixture *f, uint32_t *next, const char *s) {
    uint32_t index = (*next)++; utf(f,s); return index;
}
static inline uint32_t media_cp_one(fixture *f, uint32_t *next, uint32_t tag, uint32_t a) {
    uint32_t index = (*next)++; put(f,1,tag); put(f,2,a); return index;
}
static inline uint32_t media_cp_member(fixture *f, uint32_t *next, uint32_t tag, uint32_t owner,
    const char *name, const char *desc) {
    uint32_t a = media_cp_utf(f,next,name), b = media_cp_utf(f,next,desc), nt = (*next)++;
    put(f,1,12); put(f,2,a); put(f,2,b);
    uint32_t index = (*next)++; put(f,1,tag); put(f,2,owner); put(f,2,nt); return index;
}
static fixture make_ex(int app, uint32_t size, const uint8_t *code, uint32_t length, unsigned change) {
    fixture f = {{0}, 0}; put(&f, 4, 0xcafebabe); put(&f, 2, 0); put(&f, 2, 50); put(&f, 2, 35);
    utf(&f, app ? "com/ami/kvm/jviewer/gui/JViewerApp" : "com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr"); /* 1 */
    put(&f, 1, 7); put(&f, 2, 1); /* 2 */
    utf(&f, "VIDEO_PACKET_SIZE"); utf(&f, "S"); utf(&f, "ConstantValue"); /* 3-5 */
    put(&f, 1, 3); put(&f, 4, size); /* 6 */
    utf(&f, "OnsendWebsessionToken"); utf(&f, "()I"); utf(&f, "Code"); /* 7-9 */
    utf(&f, "com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr"); /* 10 */
    put(&f, 1, 7); put(&f, 2, 10); /* 11 */
    utf(&f, "<init>"); utf(&f, "(SIS)V"); /* 12-13 */
    put(&f, 1, 12); put(&f, 2, 12); put(&f, 2, 13); /* 14 */
    put(&f, 1, 10); put(&f, 2, 11); put(&f, 2, 14); /* 15 */
    utf(&f,"array"); utf(&f,"()[B");
    put(&f,1,12); put(&f,2,16); put(&f,2,17);
    put(&f,1,10); put(&f,2,11); put(&f,2,18);
    utf(&f,"java/nio/ByteBuffer"); put(&f,1,7); put(&f,2,20);
    utf(&f,"put"); utf(&f,"([B)Ljava/nio/ByteBuffer;");
    put(&f,1,12); put(&f,2,22); put(&f,2,23);
    put(&f,1,10); put(&f,2,21); put(&f,2,24);
    utf(&f,"get"); put(&f,1,12); put(&f,2,26); put(&f,2,23);
    put(&f,1,10); put(&f,2,21); put(&f,2,27);
    utf(&f,"com/ami/kvm/jviewer/kvmpkts/KVMClient"); put(&f,1,7); put(&f,2,29);
    utf(&f,"sendMessage"); utf(&f,"([BI)I");
    put(&f,1,12); put(&f,2,31); put(&f,2,32);
    put(&f,1,10); put(&f,2,30); put(&f,2,33);
    uint32_t next = 35, type_name = 0, int_desc = 0, type_field = 0, getter = 0, connect = 0, connect_desc = 0;
    uint32_t ip = 0, port = 0, enc = 0, token = 0, server_ip = 0, exception_type = 0;
    if (app) {
        type_name = media_cp_utf(&f,&next,"m_session_token_type"); int_desc = media_cp_utf(&f,&next,"I");
        type_field = media_cp_member(&f,&next,9,2,"m_session_token_type","I");
        getter = media_cp_utf(&f,&next,"getSessionTokenType");
        connect = media_cp_utf(&f,&next,"OnConnectToServer");
        connect_desc = media_cp_utf(&f,&next,"(Ljava/lang/String;ILjava/lang/String;IZZIIIBBBIIILjava/lang/String;I)V");
        ip = media_cp_member(&f,&next,9,2,"m_serverIP","[B"); port = media_cp_member(&f,&next,9,2,"m_serverPort","I");
        enc = media_cp_member(&f,&next,9,2,"m_encToken","Ljava/lang/String;");
        token = media_cp_member(&f,&next,9,2,"m_session_token","Ljava/lang/String;");
        uint32_t entry_name = media_cp_utf(&f,&next,"com/ami/kvm/jviewer/JViewer");
        uint32_t entry = media_cp_one(&f,&next,7,entry_name);
        server_ip = media_cp_member(&f,&next,10,entry,"getServerIP","(Ljava/lang/String;)[B");
        if (change >= 20) {
            uint32_t exception_name = media_cp_utf(&f,&next,"java/lang/Exception");
            exception_type = media_cp_one(&f,&next,7,exception_name);
        }
        f.data[8] = (uint8_t)(next >> 8); f.data[9] = (uint8_t)next;
    }
    put(&f, 2, 1); put(&f, 2, 2); put(&f, 2, 0); put(&f, 2, 0);
    put(&f, 2, 1);
    if (!app) {
        put(&f, 2, 0x19); put(&f, 2, 3); put(&f, 2, 4); put(&f, 2, 1);
        put(&f, 2, 5); put(&f, 4, 2); put(&f, 2, 6);
    } else {
        put(&f,2,2); put(&f,2,type_name); put(&f,2,int_desc); put(&f,2,0);
    }
    put(&f, 2, app ? 3 : 0);
    if (app) {
        put(&f, 2, 1); put(&f, 2, 7); put(&f, 2, 8); put(&f, 2, 1);
        uint32_t extra = change >= 20 ? 3 : 0;
        put(&f, 2, 9); put(&f, 4, length + extra + 12 + (extra ? 8 : 0));
        put(&f, 2, 8); put(&f, 2, 4); put(&f, 4, length + extra);
        memcpy(f.data + f.size, code, length); f.size += length;
        if (extra) { put(&f,1,76); put(&f,1,change == 21 ? 3 : 2); put(&f,1,change == 22 ? 0 : 172); }
        put(&f, 2, extra ? 1 : 0);
        if (extra) { put(&f,2,0); put(&f,2,change == 23 ? length + 4 : length); put(&f,2,length); put(&f,2,exception_type); }
        put(&f, 2, 0);
        fixture body = {{0},0};
        if (change == 1) put(&body,1,3);
        else { put(&body,1,42); put(&body,1,180); put(&body,2,type_field); }
        put(&body,1,172);
        put(&f,2,1); put(&f,2,getter); put(&f,2,8); put(&f,2,1); put(&f,2,9); put(&f,4,body.size+12);
        put(&f,2,2); put(&f,2,1); put(&f,4,body.size); memcpy(f.data+f.size,body.data,body.size); f.size += body.size;
        put(&f,2,0); put(&f,2,0);
        body.size = 0; put(&body,1,42); put(&body,1,43); put(&body,1,184); put(&body,2,server_ip); put(&body,1,181); put(&body,2,ip);
        put(&body,1,42); put(&body,1,28); put(&body,1,181); put(&body,2,port);
        put(&body,1,42); put(&body,1,45); put(&body,1,181); put(&body,2,enc);
        put(&body,1,42); put(&body,1,45); put(&body,1,181); put(&body,2,token);
        put(&body,1,42); put(&body,1,21); put(&body,1,change == 2 ? 5 : 4); put(&body,1,181); put(&body,2,type_field);
        if (change == 3) { put(&body,1,42); put(&body,1,3); put(&body,1,181); put(&body,2,type_field); }
        put(&body,1,177);
        put(&f,2,1); put(&f,2,connect); put(&f,2,connect_desc); put(&f,2,1); put(&f,2,9); put(&f,4,body.size+12);
        put(&f,2,4); put(&f,2,18); put(&f,4,body.size); memcpy(f.data+f.size,body.data,body.size); f.size += body.size;
        put(&f,2,0); put(&f,2,0);
    }
    put(&f, 2, 0); return f;
}
static fixture make(int app, uint32_t size, const uint8_t *code, uint32_t length) {
    return make_ex(app,size,code,length,0);
}

static fixture app_fixture(const uint8_t *code, uint32_t length) {
    static const uint8_t sequence[] = {0xb6,0,19,0xb6,0,25,0xb6,0,28,0xb6,0,34};
    uint8_t combined[1024]; assert(length >= 2 && length + sizeof(sequence) <= sizeof(combined));
    memcpy(combined,code,length-2); memcpy(combined+length-2,sequence,sizeof(sequence));
    memcpy(combined+length-2+sizeof(sequence),code+length-2,2);
    return make(1,0,combined,length+(uint32_t)sizeof(sequence));
}

static inline fixture token_default_fixture(const uint8_t *code, uint32_t length) {
    fixture f = {{0},0}; put(&f,4,0xcafebabe); put(&f,2,0); put(&f,2,50); put(&f,2,12);
    utf(&f,"com/ami/kvm/jviewer/JViewer"); put(&f,1,7); put(&f,2,1);
    utf(&f,"kvmTokenType"); utf(&f,"I"); utf(&f,"<clinit>"); utf(&f,"()V"); utf(&f,"Code");
    put(&f,1,12); put(&f,2,3); put(&f,2,4);
    put(&f,1,9); put(&f,2,2); put(&f,2,8);
    utf(&f,"java/lang/Object"); put(&f,1,7); put(&f,2,10);
    put(&f,2,0x21); put(&f,2,2); put(&f,2,11); put(&f,2,0);
    put(&f,2,1); put(&f,2,8); put(&f,2,3); put(&f,2,4); put(&f,2,0);
    put(&f,2,1); put(&f,2,8); put(&f,2,5); put(&f,2,6); put(&f,2,1);
    put(&f,2,7); put(&f,4,12+length); put(&f,2,2); put(&f,2,1); put(&f,4,length);
    memcpy(f.data+f.size,code,length); f.size+=length;
    put(&f,2,0); put(&f,2,0); put(&f,2,0);
    return f;
}
static inline fixture media_header_fixture(uint32_t major, uint32_t header_length, int payload) {
    static const char *const names[] = {"signature","packetHeaderLen","major","minor","sequenceNumber",
        "direction","dataPacketLen","deviceType","deviceNumber","interfaceNumber","protocol"};
    uint32_t values[] = {0,header_length,major,0,0,128,0,5,0,0,1};
    fixture f = {{0},0}, code = {{0},0};
    put(&f,4,0xcafebabe); put(&f,2,0); put(&f,2,50); put(&f,2,61);
    utf(&f,"com/ami/iusb/protocol/IUSBHeader"); put(&f,1,7); put(&f,2,1);
    utf(&f,"<init>"); utf(&f,"()V"); put(&f,1,12); put(&f,2,3); put(&f,2,4);
    put(&f,1,10); put(&f,2,2); put(&f,2,5);
    utf(&f,"createCDROMHeader"); utf(&f,"(I)Lcom/ami/iusb/protocol/IUSBHeader;"); utf(&f,"Code");
    for (uint32_t i = 0; i < 11; ++i) {
        utf(&f,names[i]); utf(&f,i == 0 ? "Ljava/lang/String;" : (i == 4 || i == 6) ? "J" : "I");
        put(&f,1,12); put(&f,2,10+4*i); put(&f,2,11+4*i);
        put(&f,1,9); put(&f,2,2); put(&f,2,12+4*i);
    }
    utf(&f,"IUSB    "); put(&f,1,8); put(&f,2,54);
    utf(&f,"HEADER_LEN"); put(&f,1,3); put(&f,4,32); utf(&f,"ConstantValue");
    utf(&f,"java/lang/Object"); put(&f,1,7); put(&f,2,59);
    put(&code,1,187); put(&code,2,2); put(&code,1,89); put(&code,1,183); put(&code,2,6); put(&code,1,76);
    for (uint32_t i = 0; i < 11; ++i) {
        put(&code,1,43);
        if (i == 0) { put(&code,1,18); put(&code,1,55); }
        else if (i == 4) put(&code,1,9);
        else if (i == 6) { put(&code,1,payload ? 26 : 3); put(&code,1,133); }
        else if (values[i] <= 5) put(&code,1,values[i]+3);
        else { put(&code,1,17); put(&code,2,values[i]); }
        put(&code,1,181); put(&code,2,13+4*i);
    }
    put(&code,1,43); put(&code,1,176);
    put(&f,2,0x21); put(&f,2,2); put(&f,2,60); put(&f,2,0);
    put(&f,2,1); put(&f,2,0x18); put(&f,2,56); put(&f,2,15); put(&f,2,1);
    put(&f,2,58); put(&f,4,2); put(&f,2,57);
    put(&f,2,1); put(&f,2,8); put(&f,2,7); put(&f,2,8); put(&f,2,1);
    put(&f,2,9); put(&f,4,12+code.size); put(&f,2,4); put(&f,2,2); put(&f,4,code.size);
    memcpy(f.data+f.size,code.data,code.size); f.size += code.size;
    put(&f,2,0); put(&f,2,0); put(&f,2,0);
    return f;
}
static inline void media_invoke(fixture *f, uint32_t op, uint32_t index) { put(f,1,op); put(f,2,index); }
static inline void media_mask(fixture *f, uint32_t value) { put(f,1,17); put(f,2,value); put(f,1,126); }
static inline void media_fixture_method(fixture *f, uint32_t name, uint32_t desc, uint32_t attr, fixture *code) {
    put(f,2,1); put(f,2,name); put(f,2,desc); put(f,2,1); put(f,2,attr); put(f,4,12+code->size);
    put(f,2,32); put(f,2,8); put(f,4,code->size); memcpy(f->data+f->size,code->data,code->size); f->size += code->size;
    put(f,2,0); put(f,2,0);
}
static inline fixture media_serialization_fixture(unsigned change) {
    static const char *const names[] = {"signature","major","minor","packetHeaderLen","headerChecksum",
        "dataPacketLen","serverCaps","deviceType","protocol","direction","deviceNumber","interfaceNumber",
        "clientData","Instance","sequenceNumber","reserved"};
    fixture f = {{0},0}, code = {{0},0}; uint32_t next = 1, fields[16];
    put(&f,4,0xcafebabe); put(&f,2,0); put(&f,2,50); put(&f,2,0);
    uint32_t name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/IUSBHeader");
    uint32_t owner = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/RedirHeader"); uint32_t super = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"java/nio/ByteBuffer"); uint32_t buffer = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"java/lang/String"); uint32_t string = media_cp_one(&f,&next,7,name);
    for (unsigned i = 0; i < 16; ++i)
        fields[i] = media_cp_member(&f,&next,9,owner,names[i],i == 0 ? "Ljava/lang/String;" :
            i == 15 ? "[B" : (i == 5 || i == 14) ? "J" : "I");
    uint32_t bytes = media_cp_member(&f,&next,10,string,"getBytes","()[B");
    uint32_t put_array = media_cp_member(&f,&next,10,buffer,"put","([B)Ljava/nio/ByteBuffer;");
    uint32_t put_byte = media_cp_member(&f,&next,10,buffer,"put","(B)Ljava/nio/ByteBuffer;");
    uint32_t put_word = media_cp_member(&f,&next,10,buffer,"putInt","(I)Ljava/nio/ByteBuffer;");
    uint32_t limit = media_cp_member(&f,&next,10,buffer,"limit","()I");
    uint32_t get = media_cp_member(&f,&next,10,buffer,"get","(I)B");
    uint32_t put_index = media_cp_member(&f,&next,10,buffer,"put","(IB)Ljava/nio/ByteBuffer;");
    uint32_t mask = next; next += 2; put(&f,1,5); put(&f,4,change == 7 ? UINT32_MAX : 0); put(&f,4,change == 4 ? 65535 : UINT32_MAX);
    uint32_t field_name = media_cp_utf(&f,&next,"HEADER_LEN"), integer = media_cp_utf(&f,&next,"I");
    uint32_t constant = next++; put(&f,1,3); put(&f,4,32);
    uint32_t attribute = media_cp_utf(&f,&next,"ConstantValue");
    uint32_t method_name = media_cp_utf(&f,&next,"write"), desc = media_cp_utf(&f,&next,"(Ljava/nio/ByteBuffer;)V");
    uint32_t code_attr = media_cp_utf(&f,&next,"Code");
    uint32_t constructor = media_cp_member(&f,&next,10,owner,"<init>","()V");
    uint32_t factory_name = media_cp_utf(&f,&next,"createCDROMHeader");
    uint32_t factory_desc = media_cp_utf(&f,&next,"(I)Lcom/ami/iusb/protocol/IUSBHeader;");
    name = media_cp_utf(&f,&next,"IUSB    "); uint32_t signature = media_cp_one(&f,&next,8,name);
    uint32_t parent_constructor = media_cp_member(&f,&next,10,super,"<init>","()V");
    uint32_t init_name = media_cp_utf(&f,&next,"<init>"), init_desc = media_cp_utf(&f,&next,"()V");
    uint32_t header_len = media_cp_member(&f,&next,9,owner,"headerLen","I"), read[6];
    read[0] = media_cp_member(&f,&next,10,string,"<init>","([B)V");
    read[1] = media_cp_member(&f,&next,10,buffer,"get","([B)Ljava/nio/ByteBuffer;");
    read[2] = media_cp_member(&f,&next,10,string,"equals","(Ljava/lang/Object;)Z");
    read[3] = media_cp_member(&f,&next,10,buffer,"get","()B");
    read[4] = media_cp_member(&f,&next,10,buffer,"getInt","()I");
    read[5] = media_cp_utf(&f,&next,"read");
    f.data[8] = (uint8_t)(next >> 8); f.data[9] = (uint8_t)next;
    for (unsigned i = 0; i < 16; ++i) {
        put(&code,1,43); put(&code,1,42); media_invoke(&code,180,fields[change == 1 && i == 5 ? 14 : i]);
        if (i == 0) media_invoke(&code,182,bytes);
        else if (i == 5 || i == 14) { media_invoke(&code,20,mask); put(&code,1,127); put(&code,1,136); }
        else if (i != 15) { media_mask(&code,change == 6 ? 254 : 255); put(&code,1,145); }
        media_invoke(&code,182,(i == 0 || i == 15) ? put_array : (i == 5 || i == 14) ? put_word : put_byte);
        put(&code,1,87);
    }
    put(&code,1,3); put(&code,1,61); put(&code,1,3); put(&code,1,62);
    uint32_t condition = code.size;
    put(&code,1,29); put(&code,1,43); media_invoke(&code,182,limit);
    uint32_t branch = code.size; put(&code,1,162); put(&code,2,0);
    put(&code,1,28); put(&code,1,43); put(&code,1,29); media_invoke(&code,182,get);
    media_mask(&code,255); put(&code,1,96); media_mask(&code,255); put(&code,1,61);
    put(&code,1,132); put(&code,1,3); put(&code,1,1);
    uint32_t back = code.size; put(&code,1,167); put(&code,2,change == 3 ? 3 : condition-back);
    uint32_t offset = code.size-branch; code.data[branch+1] = (uint8_t)(offset >> 8); code.data[branch+2] = (uint8_t)offset;
    put(&code,1,43); put(&code,1,16); put(&code,1,change == 2 ? 12 : 11); put(&code,1,28);
    media_mask(&code,255); put(&code,1,145); put(&code,1,116); put(&code,1,145);
    media_invoke(&code,182,put_index); put(&code,1,87); put(&code,1,177);
    if (change == 5) put(&code,1,0);
    put(&f,2,0x21); put(&f,2,owner); put(&f,2,super); put(&f,2,0);
    put(&f,2,1); put(&f,2,0x18); put(&f,2,field_name); put(&f,2,integer); put(&f,2,1);
    put(&f,2,attribute); put(&f,4,2); put(&f,2,constant);
    put(&f,2,4); put(&f,2,1); put(&f,2,method_name); put(&f,2,desc); put(&f,2,1);
    put(&f,2,code_attr); put(&f,4,12+code.size); put(&f,2,4); put(&f,2,4); put(&f,4,code.size);
    memcpy(f.data+f.size,code.data,code.size); f.size += code.size;
    put(&f,2,0); put(&f,2,0);
    code.size = 0; media_invoke(&code,187,owner); put(&code,1,89); media_invoke(&code,183,constructor); put(&code,1,76);
    static const unsigned factory_fields[] = {0,3,1,2,14,9,5,7,10,11,8};
    static const unsigned values[] = {0,32,1,0,0,128,0,5,0,0,1};
    for (unsigned i = 0; i < 11; ++i) {
        put(&code,1,43);
        if (i == 0) media_invoke(&code,19,signature);
        else if (i == 4) put(&code,1,9);
        else if (i == 6) { put(&code,1,26); put(&code,1,133); }
        else if (values[i] <= 5) put(&code,1,values[i]+3);
        else { put(&code,1,17); put(&code,2,values[i]); }
        media_invoke(&code,181,fields[factory_fields[i]]);
    }
    put(&code,1,43); put(&code,1,176);
    put(&f,2,8); put(&f,2,factory_name); put(&f,2,factory_desc); put(&f,2,1);
    put(&f,2,code_attr); put(&f,4,12+code.size); put(&f,2,4); put(&f,2,2); put(&f,4,code.size);
    memcpy(f.data+f.size,code.data,code.size); f.size += code.size;
    put(&f,2,0); put(&f,2,0);
    code.size = 0; put(&code,1,42); media_invoke(&code,183,parent_constructor);
    put(&code,1,42); put(&code,1,change == 8 ? 8 : 7); put(&code,1,188); put(&code,1,8);
    media_invoke(&code,181,fields[15]); put(&code,1,42); put(&code,1,16); put(&code,1,change == 9 ? 33 : 32);
    media_invoke(&code,181,header_len); put(&code,1,177);
    put(&f,2,1); put(&f,2,init_name); put(&f,2,init_desc); put(&f,2,1);
    put(&f,2,code_attr); put(&f,4,12+code.size); put(&f,2,2); put(&f,2,1); put(&f,4,code.size);
    memcpy(f.data+f.size,code.data,code.size); f.size += code.size;
    put(&f,2,0); put(&f,2,0);
    code.size = 0; put(&code,1,16); put(&code,1,8); put(&code,1,188); put(&code,1,8); put(&code,1,77);
    put(&code,1,43); put(&code,1,44); media_invoke(&code,182,read[1]); put(&code,1,87);
    put(&code,1,42); media_invoke(&code,187,string); put(&code,1,89); put(&code,1,44);
    media_invoke(&code,183,read[0]); media_invoke(&code,181,fields[0]);
    put(&code,1,42); media_invoke(&code,180,fields[0]); media_invoke(&code,19,signature);
    media_invoke(&code,182,read[2]); uint32_t valid = code.size; put(&code,1,154); put(&code,2,0);
    put(&code,1,1); put(&code,1,191);
    uint32_t skip = code.size-valid; code.data[valid+1] = (uint8_t)(skip >> 8); code.data[valid+2] = (uint8_t)skip;
    for (unsigned i = 1; i < 15; ++i) {
        put(&code,1,42); put(&code,1,43);
        if (i == 5 || i == 14) {
            media_invoke(&code,182,change == 12 && i == 5 ? read[3] : read[4]);
            put(&code,1,133); media_invoke(&code,20,mask); put(&code,1,127);
        } else { media_invoke(&code,182,read[3]); media_mask(&code,change == 13 ? 254 : 255); }
        media_invoke(&code,181,fields[change == 11 && i == 1 ? 2 : i]);
    }
    put(&code,1,43); put(&code,1,42); media_invoke(&code,180,fields[15]); media_invoke(&code,182,read[1]); put(&code,1,87);
    if (change == 14) { put(&code,1,42); put(&code,1,16); put(&code,1,33); media_invoke(&code,181,header_len); }
    put(&code,1,177); media_fixture_method(&f,read[5],desc,code_attr,&code);
    put(&f,2,0); return f;
}
static inline void media_auth_buffer(fixture *code, uint32_t field) { put(code,1,42); media_invoke(code,180,field); }
static inline void media_auth_position(fixture *code, uint32_t field, uint32_t call, uint32_t position) {
    media_auth_buffer(code,field); put(code,1,17); put(code,2,position); media_invoke(code,182,call); put(code,1,87);
}
static inline void media_auth_limit(fixture *code, uint32_t field, uint32_t clear, uint32_t call, uint32_t limit) {
    media_auth_buffer(code,field); media_invoke(code,182,clear); put(code,1,87);
    media_auth_buffer(code,field); put(code,1,17); put(code,2,limit); media_invoke(code,182,call); put(code,1,87);
}
static inline void media_patch_branch(fixture *code, uint32_t at, uint32_t target) {
    uint32_t offset = target-at; code->data[at+1] = (uint8_t)(offset >> 8); code->data[at+2] = (uint8_t)offset;
}
static inline fixture media_order_fixture(int cdrom, unsigned change) {
    fixture f = {{0},0}, code = {{0},0}; uint32_t next = 1;
    put(&f,4,0xcafebabe); put(&f,2,0); put(&f,2,50); put(&f,2,0);
    uint32_t name = media_cp_utf(&f,&next,cdrom ? "com/ami/iusb/CDROMRedir" : "com/ami/iusb/protocol/PacketMaster");
    uint32_t owner = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"java/lang/Object"); uint32_t super = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/PacketMaster"); uint32_t packet = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"java/nio/ByteBuffer"); uint32_t buffer = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"java/nio/ByteOrder"); uint32_t order = media_cp_one(&f,&next,7,name);
    uint32_t fields[4];
    const char *const packet_fields[] = {"netIn","netOut","appIn","appOut"};
    const char *const cd_fields[] = {"protocol","packetMaster","packetReadBuffer","packetWriteBuffer"};
    for (unsigned i = 0; i < 4; ++i)
        fields[i] = media_cp_member(&f,&next,9,owner,cdrom ? cd_fields[i] : packet_fields[i],
            cdrom && i == 0 ? "Lcom/ami/iusb/protocol/CDROMProtocol;" :
            cdrom && i == 1 ? "Lcom/ami/iusb/protocol/PacketMaster;" : "Ljava/nio/ByteBuffer;");
    uint32_t clear = media_cp_member(&f,&next,10,buffer,"clear","()Ljava/nio/Buffer;");
    uint32_t set_order = media_cp_member(&f,&next,10,buffer,"order","(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;");
    uint32_t setup = media_cp_member(&f,&next,10,packet,"setupBuffers","(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)V");
    uint32_t endian = media_cp_member(&f,&next,10,packet,"setBufferEndianness","(Ljava/nio/ByteOrder;Ljava/nio/ByteOrder;)V");
    uint32_t constructor = media_cp_member(&f,&next,10,packet,"<init>","(Ljava/lang/String;IZLcom/ami/iusb/protocol/RedirProtocol;Z)V");
    uint32_t little = media_cp_member(&f,&next,9,order,change == 4 ? "BIG_ENDIAN" : "LITTLE_ENDIAN","Ljava/nio/ByteOrder;");
    uint32_t setup_name = media_cp_utf(&f,&next,cdrom ? "cdromConnect" : "setupBuffers");
    uint32_t setup_desc = media_cp_utf(&f,&next,cdrom ? "(Ljava/lang/String;IZ)I" : "(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)V");
    uint32_t order_name = media_cp_utf(&f,&next,"setBufferEndianness");
    uint32_t order_desc = media_cp_utf(&f,&next,"(Ljava/nio/ByteOrder;Ljava/nio/ByteOrder;)V");
    uint32_t auth[15] = {0};
    if (cdrom) {
        name = media_cp_utf(&f,&next,"com/ami/kvm/jviewer/gui/JViewerApp"); uint32_t app = media_cp_one(&f,&next,7,name);
        name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/IUSBHeader"); uint32_t header = media_cp_one(&f,&next,7,name);
        name = media_cp_utf(&f,&next,"java/lang/String"); uint32_t string = media_cp_one(&f,&next,7,name);
        auth[0] = media_cp_member(&f,&next,10,app,"getInstance","()Lcom/ami/kvm/jviewer/gui/JViewerApp;");
        auth[1] = media_cp_member(&f,&next,10,app,"getSessionTokenType","()I");
        auth[2] = media_cp_member(&f,&next,10,buffer,"limit","(I)Ljava/nio/Buffer;");
        auth[3] = media_cp_member(&f,&next,10,header,"createCDROMHeader","(I)Lcom/ami/iusb/protocol/IUSBHeader;");
        auth[4] = media_cp_member(&f,&next,10,header,"write","(Ljava/nio/ByteBuffer;)V");
        auth[5] = media_cp_member(&f,&next,10,buffer,"position","(I)Ljava/nio/Buffer;");
        auth[6] = media_cp_member(&f,&next,10,buffer,"put","(B)Ljava/nio/ByteBuffer;");
        auth[7] = media_cp_member(&f,&next,10,buffer,"put","([B)Ljava/nio/ByteBuffer;");
        auth[8] = media_cp_member(&f,&next,10,string,"getBytes","()[B");
        auth[9] = media_cp_member(&f,&next,9,owner,"CDDevice_no","I");
        name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/IUSBSCSI"); auth[10] = media_cp_one(&f,&next,7,name);
        auth[11] = media_cp_member(&f,&next,10,auth[10],"<init>","(Ljava/nio/ByteBuffer;Z)V");
        auth[12] = media_cp_member(&f,&next,10,packet,"sendPacket","(Lcom/ami/iusb/protocol/RedirPacket;)V");
        auth[13] = media_cp_utf(&f,&next,"SendAuth_SessionToken"); auth[14] = media_cp_utf(&f,&next,"(Ljava/lang/String;)V");
    }
    uint32_t send[9] = {0};
    if (!cdrom) {
        name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/RedirPacket"); uint32_t redir = media_cp_one(&f,&next,7,name);
        name = media_cp_utf(&f,&next,"java/net/Socket"); uint32_t socket = media_cp_one(&f,&next,7,name);
        name = media_cp_utf(&f,&next,"java/io/OutputStream"); uint32_t stream = media_cp_one(&f,&next,7,name);
        send[0] = media_cp_member(&f,&next,10,redir,"writePacket","(Ljava/nio/ByteBuffer;)V");
        send[1] = media_cp_member(&f,&next,10,buffer,"flip","()Ljava/nio/Buffer;");
        send[2] = media_cp_member(&f,&next,10,buffer,"remaining","()I");
        send[3] = media_cp_member(&f,&next,10,buffer,"get","([B)Ljava/nio/ByteBuffer;");
        send[4] = media_cp_member(&f,&next,10,owner,"getSock","()Ljava/net/Socket;");
        send[5] = media_cp_member(&f,&next,10,socket,"getOutputStream","()Ljava/io/OutputStream;");
        send[6] = media_cp_member(&f,&next,10,stream,"write",change == 17 ? "([BII)V" : "([B)V");
        send[7] = media_cp_utf(&f,&next,"sendPacket"); send[8] = media_cp_utf(&f,&next,"(Lcom/ami/iusb/protocol/RedirPacket;)V");
    }
    uint32_t attr = media_cp_utf(&f,&next,"Code"); f.data[8] = (uint8_t)(next >> 8); f.data[9] = (uint8_t)next;
    put(&f,2,0x21); put(&f,2,owner); put(&f,2,super); put(&f,2,0); put(&f,2,0); put(&f,2,cdrom ? 2 : 3);
    if (cdrom) {
        put(&code,1,42); media_invoke(&code,187,packet); put(&code,1,89); put(&code,1,43); put(&code,1,28);
        put(&code,1,3); put(&code,1,42); media_invoke(&code,180,fields[0]); put(&code,1,29);
        media_invoke(&code,183,constructor); media_invoke(&code,181,fields[1]);
        put(&code,1,42); media_invoke(&code,180,fields[1]);
        put(&code,1,42); media_invoke(&code,180,fields[change == 5 ? 3 : 2]);
        put(&code,1,42); media_invoke(&code,180,fields[3]); media_invoke(&code,182,setup);
        put(&code,1,42); media_invoke(&code,180,fields[1]);
        media_invoke(&code,178,little); media_invoke(&code,178,little);
        media_invoke(&code,182,change == 6 ? setup : endian); put(&code,1,3); put(&code,1,172);
    } else {
        for (unsigned i = 0; i < 4; ++i) {
            put(&code,1,42);
            if (i < 2) put(&code,1,43+i);
            else { put(&code,1,42); media_invoke(&code,180,fields[change == 1 && i == 3 ? 0 : i-2]); }
            media_invoke(&code,181,fields[i]);
        }
        for (unsigned i = 0; i < 2; ++i) {
            put(&code,1,42); media_invoke(&code,180,fields[i]); media_invoke(&code,182,clear); put(&code,1,87);
        }
        put(&code,1,177);
    }
    media_fixture_method(&f,setup_name,setup_desc,attr,&code);
    if (!cdrom) {
        code.size = 0;
        for (unsigned i = 0; i < 2; ++i) {
            put(&code,1,42); media_invoke(&code,180,fields[i+2]); put(&code,1,change == 2 && i == 1 ? 43 : 43+i);
            media_invoke(&code,182,change == 3 ? clear : set_order); put(&code,1,87);
        }
        put(&code,1,177); media_fixture_method(&f,order_name,order_desc,attr,&code);
    }
    if (cdrom) {
        code.size = 0; put(&code,1,3); put(&code,1,61); media_invoke(&code,184,auth[0]);
        media_invoke(&code,182,auth[1]); put(&code,1,62); put(&code,1,29);
        uint32_t other = code.size; put(&code,1,154); put(&code,2,0);
        put(&code,1,17); put(&code,2,change == 8 ? 129 : 128); put(&code,1,61);
        media_auth_limit(&code,fields[3],clear,auth[2],change == 7 ? 161 : 160);
        uint32_t join = code.size; put(&code,1,167); put(&code,2,0); media_patch_branch(&code,other,code.size);
        put(&code,1,29); put(&code,1,4); uint32_t second = code.size; put(&code,1,change == 9 ? 159 : 160); put(&code,2,0);
        put(&code,1,17); put(&code,2,240); put(&code,1,61); media_auth_limit(&code,fields[3],clear,auth[2],272);
        media_patch_branch(&code,join,code.size); media_patch_branch(&code,second,code.size);
        put(&code,1,28); media_invoke(&code,184,auth[3]); put(&code,1,58); put(&code,1,4);
        put(&code,1,25); put(&code,1,4); media_auth_buffer(&code,fields[3]); media_invoke(&code,182,auth[4]);
        media_auth_position(&code,fields[3],auth[5],41); media_auth_buffer(&code,fields[3]);
        put(&code,1,16); put(&code,1,change == 10 ? 243 : 242); media_invoke(&code,182,auth[6]); put(&code,1,87);
        media_auth_position(&code,fields[3],auth[5],change == 11 ? 61 : 62);
        media_auth_buffer(&code,fields[3]); put(&code,1,3); media_invoke(&code,182,auth[6]); put(&code,1,87);
        media_auth_buffer(&code,fields[3]); put(&code,1,43); media_invoke(&code,182,auth[8]); media_invoke(&code,182,auth[7]); put(&code,1,87);
        media_auth_position(&code,fields[3],auth[5],23); media_auth_buffer(&code,fields[3]);
        media_auth_buffer(&code,auth[9]); put(&code,1,145); media_invoke(&code,182,auth[6]); put(&code,1,87);
        media_auth_position(&code,fields[3],auth[5],0); media_invoke(&code,187,auth[10]); put(&code,1,89);
        media_auth_buffer(&code,fields[3]); put(&code,1,change == 12 ? 3 : 4); media_invoke(&code,183,auth[11]);
        put(&code,1,58); put(&code,1,5); media_auth_buffer(&code,fields[1]); put(&code,1,25); put(&code,1,5);
        media_invoke(&code,182,auth[12]); put(&code,1,177); media_fixture_method(&f,auth[13],auth[14],attr,&code);
    } else {
        code.size = 0;
        media_auth_buffer(&code,fields[3]); media_invoke(&code,182,clear); put(&code,1,87);
        media_auth_buffer(&code,fields[1]); media_invoke(&code,182,clear); put(&code,1,87);
        put(&code,1,43); media_auth_buffer(&code,fields[3]); media_invoke(&code,182,send[0]);
        media_auth_buffer(&code,fields[3]); media_invoke(&code,182,change == 15 ? clear : send[1]); put(&code,1,87);
        media_auth_buffer(&code,fields[change == 13 ? 0 : 1]); media_invoke(&code,182,send[2]);
        put(&code,1,188); put(&code,1,change == 16 ? 10 : 8); put(&code,1,77);
        media_auth_buffer(&code,fields[1]); put(&code,1,44); media_invoke(&code,182,send[3]); put(&code,1,87);
        put(&code,1,42); media_invoke(&code,182,send[4]); media_invoke(&code,182,send[5]);
        put(&code,1,change == 14 ? 43 : 44); media_invoke(&code,182,send[6]); put(&code,1,177);
        media_fixture_method(&f,send[7],send[8],attr,&code);
    }
    put(&f,2,0); return f;
}
static inline fixture media_scsi_fixture(unsigned change) {
    fixture f = {{0},0}, code = {{0},0}; uint32_t next = 1;
    put(&f,4,0xcafebabe); put(&f,2,0); put(&f,2,50); put(&f,2,0);
    uint32_t name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/IUSBSCSI"), owner = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/RedirPacket"); uint32_t super = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/IUSBHeader"); uint32_t header = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/RedirHeader"); uint32_t base = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"java/nio/ByteBuffer"); uint32_t buffer = media_cp_one(&f,&next,7,name);
    uint32_t head = media_cp_member(&f,&next,9,owner,"header","Lcom/ami/iusb/protocol/RedirHeader;");
    uint32_t pre = media_cp_member(&f,&next,9,owner,"preBuffered","Z"), length = media_cp_member(&f,&next,9,owner,"dataLen","I");
    uint32_t data = media_cp_member(&f,&next,9,owner,"data","Ljava/nio/ByteBuffer;");
    uint32_t direction = media_cp_member(&f,&next,9,header,"direction","I");
    uint32_t write = media_cp_member(&f,&next,10,base,"write","(Ljava/nio/ByteBuffer;)V");
    uint32_t limit = media_cp_member(&f,&next,10,buffer,"limit","(I)Ljava/nio/Buffer;");
    uint32_t get_limit = media_cp_member(&f,&next,10,buffer,"limit","()I");
    uint32_t position = media_cp_member(&f,&next,10,buffer,"position","(I)Ljava/nio/Buffer;");
    uint32_t copy = media_cp_member(&f,&next,10,buffer,"put","(Ljava/nio/ByteBuffer;)Ljava/nio/ByteBuffer;");
    uint32_t method = media_cp_utf(&f,&next,"writePacket"), desc = media_cp_utf(&f,&next,"(Ljava/nio/ByteBuffer;)V");
    uint32_t parent_ctor = media_cp_member(&f,&next,10,super,"<init>","()V");
    uint32_t header_ctor = media_cp_member(&f,&next,10,header,"<init>","()V");
    uint32_t status = media_cp_member(&f,&next,9,owner,"connectionStatus","I");
    uint32_t read = media_cp_member(&f,&next,10,base,"read","(Ljava/nio/ByteBuffer;)V");
    uint32_t header_len = media_cp_member(&f,&next,9,base,"headerLen","I");
    uint32_t data_len = media_cp_member(&f,&next,9,header,"dataPacketLen","J");
    uint32_t slice = media_cp_member(&f,&next,10,buffer,"slice","()Ljava/nio/ByteBuffer;");
    uint32_t remaining = media_cp_member(&f,&next,10,buffer,"remaining","()I");
    uint32_t ctor = media_cp_utf(&f,&next,"<init>"), ctor_desc = media_cp_utf(&f,&next,"(Ljava/nio/ByteBuffer;Z)V");
    uint32_t attr = media_cp_utf(&f,&next,"Code"); f.data[8] = (uint8_t)(next >> 8); f.data[9] = (uint8_t)next;
    put(&f,2,0x21); put(&f,2,owner); put(&f,2,super); put(&f,2,0); put(&f,2,0); put(&f,2,2);
    media_auth_buffer(&code,head); media_invoke(&code,192,header); put(&code,1,17); put(&code,2,change == 4 ? 0 : 128);
    media_invoke(&code,181,direction); media_auth_buffer(&code,head); put(&code,1,43); media_invoke(&code,182,write);
    media_auth_buffer(&code,pre); uint32_t branch = code.size; put(&code,1,change == 2 ? 154 : 153); put(&code,2,0);
    put(&code,1,43); media_auth_buffer(&code,length); put(&code,1,17); put(&code,2,change == 1 ? 33 : 32);
    put(&code,1,96); media_invoke(&code,182,limit); put(&code,1,87);
    put(&code,1,43); put(&code,1,43); media_invoke(&code,182,get_limit); media_invoke(&code,182,change == 3 ? limit : position); put(&code,1,87);
    uint32_t end = code.size; put(&code,1,167); put(&code,2,0); media_patch_branch(&code,branch,code.size);
    uint32_t copy_start = code.size; put(&code,1,43); media_auth_buffer(&code,data); media_invoke(&code,182,copy); put(&code,1,87);
    media_patch_branch(&code,end,change == 5 ? copy_start : code.size); put(&code,1,177);
    media_fixture_method(&f,method,desc,attr,&code);
    code.size = 0; put(&code,1,42); media_invoke(&code,183,parent_ctor);
    put(&code,1,42); put(&code,1,2); media_invoke(&code,181,status);
    put(&code,1,42); put(&code,1,change == 16 ? 4 : 28); media_invoke(&code,181,pre);
    put(&code,1,42); media_invoke(&code,187,header); put(&code,1,89); media_invoke(&code,183,header_ctor); media_invoke(&code,181,head);
    media_auth_buffer(&code,head); put(&code,1,43); media_invoke(&code,182,read);
    media_auth_buffer(&code,head); media_invoke(&code,192,header); put(&code,1,43);
    media_invoke(&code,182,change == 18 ? remaining : get_limit);
    media_auth_buffer(&code,head); media_invoke(&code,180,header_len); put(&code,1,change == 17 ? 96 : 100); put(&code,1,133);
    media_invoke(&code,181,data_len); put(&code,1,42); media_auth_buffer(&code,head); media_invoke(&code,192,header);
    media_invoke(&code,180,data_len); put(&code,1,136); media_invoke(&code,181,length);
    put(&code,1,42); put(&code,1,change == 19 ? 42 : 43); media_invoke(&code,182,slice); media_invoke(&code,181,data);
    put(&code,1,177); media_fixture_method(&f,ctor,ctor_desc,attr,&code);
    put(&f,2,0); return f;
}
static inline fixture media_entry_fixture(unsigned change) {
    static const char *const names[] = {"ip","kvmPort","kvmToken","kvmTokenType","UseSSL","VMUseSSL",
        "cdserver_port","fdserver_port","hdserver_port","Num_CD","Num_FD","Num_HD","CD_State","FD_State",
        "HD_State","webSessionToken","webSecPort"};
    static const char *const types[] = {"Ljava/lang/String;","I","Ljava/lang/String;","I","Z","Z","I","I","I",
        "B","B","B","I","I","I","Ljava/lang/String;","I"};
    fixture f = {{0},0}, code = {{0},0}; uint32_t next = 1, fields[17];
    put(&f,4,0xcafebabe); put(&f,2,0); put(&f,2,50); put(&f,2,0);
    uint32_t name = media_cp_utf(&f,&next,"com/ami/kvm/jviewer/JViewer"), owner = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"java/lang/Object"); uint32_t super = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"com/ami/kvm/jviewer/gui/JViewerApp"); uint32_t app = media_cp_one(&f,&next,7,name);
    for (unsigned i = 0; i < 17; ++i) fields[i] = media_cp_member(&f,&next,9,owner,names[i],types[i]);
    uint32_t enabled = media_cp_member(&f,&next,10,owner,"isKVMEnabled","()Z");
    uint32_t instance = media_cp_member(&f,&next,10,app,"getInstance","()Lcom/ami/kvm/jviewer/gui/JViewerApp;");
    uint32_t connect = media_cp_member(&f,&next,10,app,"OnConnectToServer",change == 6 ? "()V" :
        "(Ljava/lang/String;ILjava/lang/String;IZZIIIBBBIIILjava/lang/String;I)V");
    uint32_t create = media_cp_member(&f,&next,10,app,"create_IUSBSession","()V");
    uint32_t type_name = media_cp_utf(&f,&next,"kvmTokenType"), type_desc = media_cp_utf(&f,&next,"I");
    uint32_t redirect = media_cp_utf(&f,&next,"redirect"), desc = media_cp_utf(&f,&next,"()V");
    uint32_t single = media_cp_member(&f,&next,9,owner,"isSinglePortEnabled","Z");
    uint32_t single_name = media_cp_utf(&f,&next,"isSinglePortEnabled"), boolean = media_cp_utf(&f,&next,"Z");
    uint32_t getter_desc = media_cp_utf(&f,&next,"()Z");
    uint32_t init = media_cp_utf(&f,&next,"<clinit>"), attr = media_cp_utf(&f,&next,"Code");
    f.data[8] = (uint8_t)(next >> 8); f.data[9] = (uint8_t)next;
    put(&f,2,0x21); put(&f,2,owner); put(&f,2,super); put(&f,2,0); put(&f,2,2);
    put(&f,2,8); put(&f,2,type_name); put(&f,2,type_desc); put(&f,2,0);
    put(&f,2,8); put(&f,2,single_name); put(&f,2,boolean); put(&f,2,0); put(&f,2,3);
    put(&code,1,3); media_invoke(&code,179,fields[3]);
    if (change == 8) put(&code,1,177);
    put(&code,1,change == 7 ? 4 : 3); media_invoke(&code,179,single); put(&code,1,177);
    uint32_t at = f.size; media_fixture_method(&f,init,desc,attr,&code); f.data[at+1] = 8;
    code.size = 0; media_invoke(&code,184,enabled);
    uint32_t disabled = code.size; put(&code,1,153); put(&code,2,0); media_invoke(&code,184,instance);
    for (unsigned i = 0; i < 17; ++i) media_invoke(&code,178,fields[change == 4 && i == 3 ? 1 : change == 5 && i == 4 ? 5 : i]);
    media_invoke(&code,182,connect); media_invoke(&code,184,instance); media_invoke(&code,182,create);
    uint32_t end = code.size; put(&code,1,167); put(&code,2,0); media_patch_branch(&code,disabled,code.size);
    put(&code,1,0); media_patch_branch(&code,end,code.size); put(&code,1,177);
    at = f.size; media_fixture_method(&f,redirect,desc,attr,&code); f.data[at+1] = 8;
    code.size = 0; media_invoke(&code,178,change == 9 ? fields[3] : single); put(&code,1,172);
    at = f.size; media_fixture_method(&f,single_name,getter_desc,attr,&code); f.data[at+1] = 8;
    put(&f,2,0); return f;
}
static inline fixture media_scsi_parent_fixture(int encrypted) {
    fixture f = {{0},0}, code = {{0},0}; uint32_t next = 1;
    put(&f,4,0xcafebabe); put(&f,2,0); put(&f,2,50); put(&f,2,0);
    uint32_t name = media_cp_utf(&f,&next,"com/ami/iusb/protocol/RedirPacket"), owner = media_cp_one(&f,&next,7,name);
    name = media_cp_utf(&f,&next,"java/lang/Object"); uint32_t super = media_cp_one(&f,&next,7,name);
    uint32_t ctor = media_cp_member(&f,&next,10,super,"<init>","()V");
    uint32_t field = media_cp_member(&f,&next,9,owner,"encrypted","Z");
    uint32_t method = media_cp_utf(&f,&next,"<init>"), desc = media_cp_utf(&f,&next,"()V"), attr = media_cp_utf(&f,&next,"Code");
    f.data[8] = (uint8_t)(next >> 8); f.data[9] = (uint8_t)next;
    put(&f,2,0x21); put(&f,2,owner); put(&f,2,super); put(&f,2,0); put(&f,2,0); put(&f,2,1);
    put(&code,1,42); media_invoke(&code,183,ctor); put(&code,1,42); put(&code,1,encrypted ? 4 : 3); media_invoke(&code,181,field); put(&code,1,177);
    media_fixture_method(&f,method,desc,attr,&code); put(&f,2,0); return f;
}
static inline fixture media_parent_fixture(int extra) {
    fixture f = {{0},0}; put(&f,4,0xcafebabe); put(&f,2,0); put(&f,2,50); put(&f,2,10);
    utf(&f,"com/ami/iusb/protocol/RedirHeader"); put(&f,1,7); put(&f,2,1);
    utf(&f,"java/lang/Object"); put(&f,1,7); put(&f,2,3);
    utf(&f,"<init>"); utf(&f,"()V"); put(&f,1,12); put(&f,2,5); put(&f,2,6);
    put(&f,1,10); put(&f,2,4); put(&f,2,7); utf(&f,"Code");
    put(&f,2,0x21); put(&f,2,2); put(&f,2,4); put(&f,2,0); put(&f,2,0);
    put(&f,2,1); put(&f,2,1); put(&f,2,5); put(&f,2,6); put(&f,2,1);
    put(&f,2,9); put(&f,4,17+(extra ? 1 : 0)); put(&f,2,1); put(&f,2,1); put(&f,4,5+(extra ? 1 : 0));
    put(&f,1,42); put(&f,1,183); put(&f,2,8);
    if (extra) put(&f,1,0);
    put(&f,1,177); put(&f,2,0); put(&f,2,0); put(&f,2,0); return f;
}
#ifdef BC_TEST_JAR
static void le(fixture *f, uint32_t n, uint32_t value) {
    for (uint32_t i = 0; i < n; ++i) f->data[f->size++] = (uint8_t)(value >> (i * 8));
}
static fixture jar_classes(fixture *const *classes, const char *const *names, uint32_t count, int compressed) {
    fixture jar = {{0},0}; uint32_t offsets[12], crc[12], packed[12];
    assert(count <= 12);
    for (unsigned i = 0; i < count; ++i) {
        uint8_t output[2048]; const uint8_t *bytes = classes[i]->data; packed[i] = classes[i]->size;
        if (compressed) {
            z_stream stream = {0};
            assert(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) == Z_OK);
            stream.next_in = classes[i]->data; stream.avail_in = classes[i]->size;
            stream.next_out = output; stream.avail_out = sizeof(output);
            assert(deflate(&stream, Z_FINISH) == Z_STREAM_END); packed[i] = (uint32_t)stream.total_out;
            deflateEnd(&stream); bytes = output;
        }
        offsets[i] = jar.size; crc[i] = (uint32_t)crc32(0, classes[i]->data, classes[i]->size);
        le(&jar,4,0x04034b50); le(&jar,2,20); le(&jar,2,compressed ? 10 : 0); le(&jar,2,compressed ? 8 : 0);
        le(&jar,4,0); le(&jar,4,compressed ? 0 : crc[i]); le(&jar,4,compressed ? 0 : packed[i]); le(&jar,4,compressed ? 0 : classes[i]->size);
        le(&jar,2,(uint32_t)strlen(names[i])); le(&jar,2,0);
        memcpy(jar.data+jar.size,names[i],strlen(names[i])); jar.size+=(uint32_t)strlen(names[i]);
        memcpy(jar.data+jar.size,bytes,packed[i]); jar.size+=packed[i];
        if (compressed) { le(&jar,4,0x08074b50); le(&jar,4,crc[i]); le(&jar,4,packed[i]); le(&jar,4,classes[i]->size); }
    }
    uint32_t start = jar.size;
    for (unsigned i = 0; i < count; ++i) {
        le(&jar,4,0x02014b50); le(&jar,2,20); le(&jar,2,20); le(&jar,2,compressed ? 10 : 0); le(&jar,2,compressed ? 8 : 0);
        le(&jar,4,0); le(&jar,4,crc[i]); le(&jar,4,packed[i]); le(&jar,4,classes[i]->size);
        le(&jar,2,(uint32_t)strlen(names[i])); le(&jar,2,0); le(&jar,2,0); le(&jar,2,0); le(&jar,2,0);
        le(&jar,4,0); le(&jar,4,offsets[i]);
        memcpy(jar.data+jar.size,names[i],strlen(names[i])); jar.size+=(uint32_t)strlen(names[i]);
    }
    uint32_t length = jar.size - start;
    le(&jar,4,0x06054b50); le(&jar,2,0); le(&jar,2,0); le(&jar,2,count); le(&jar,2,count);
    le(&jar,4,length); le(&jar,4,start); le(&jar,2,0);
    assert(jar.size <= sizeof(jar.data)); return jar;
}
static fixture jar_of(fixture *header, fixture *app, int compressed, int duplicate) {
    fixture *classes[] = {header, app};
    const char *names[] = {"com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr.class",
        duplicate ? "com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr.class" : "com/ami/kvm/jviewer/gui/JViewerApp.class"};
    return jar_classes(classes,names,2,compressed);
}

#endif
#endif

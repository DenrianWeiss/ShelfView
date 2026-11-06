#include "bcontrol/megarac.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#if defined(_WIN32)
#include <io.h>
#include <fcntl.h>
#endif
#include "megarac_class_fixture.h"
#ifdef BC_TEST_JAR
#include <zlib.h>
#endif

static bc_status evidence(fixture *h, fixture *a, bc_service_profile *p) {
    return bc_megarac_jviewer_class_evidence(h->data, h->size, a->data, a->size, p);
}

static void check_failure_handlers(void) {
    const uint8_t code[] = {0xbb,0,11,0x59,0x10,18,0x11,1,125,3,0xb7,0,15,
        0xb6,0,19,0xb6,0,25,0xb6,0,28,0xb6,0,34,3,0xac};
    fixture h = make(0,373,NULL,0); bc_service_profile p;
    for (unsigned change = 20; change <= 23; ++change) {
        fixture a = make_ex(1,0,code,sizeof(code),change);
        assert(evidence(&h,&a,&p) == (change == 20 ? BC_OK : change == 23 ? BC_PROTOCOL_ERROR : BC_UNSUPPORTED));
        if (change != 20) assert(!p.evidence);
    }
}

static void check_single_port_default(void) {
    fixture entry = media_entry_fixture(0); uint32_t value;
    assert(bc_megarac_jviewer_class_single_port_default(entry.data,entry.size,&value) == BC_OK && !value);
    for (uint32_t n = 0; n < entry.size; ++n)
        assert(bc_megarac_jviewer_class_single_port_default(entry.data,n,&value) != BC_OK && value == UINT32_MAX);
    for (unsigned change = 7; change <= 9; ++change) {
        entry = media_entry_fixture(change);
        assert(bc_megarac_jviewer_class_single_port_default(entry.data,entry.size,&value) == BC_UNSUPPORTED && value == UINT32_MAX);
    }
#ifdef BC_TEST_JAR
    entry = media_entry_fixture(0); fixture *classes[] = {&entry,&entry};
    const char *names[] = {"com/ami/kvm/jviewer/JViewer.class","com/ami/kvm/jviewer/JViewer.class"};
    fixture jar = jar_classes(classes,names,1,1);
    assert(bc_megarac_jviewer_jar_single_port_default(jar.data,jar.size,&value) == BC_OK && !value);
    jar = jar_classes(classes,names,2,1);
    assert(bc_megarac_jviewer_jar_single_port_default(jar.data,jar.size,&value) == BC_PROTOCOL_ERROR && value == UINT32_MAX);
#endif
}

static void check_media_state(void) {
    fixture header = media_serialization_fixture(0), scsi = media_scsi_fixture(0), parent = media_scsi_parent_fixture(0); bc_service_profile p;
    assert(bc_megarac_jviewer_class_media_state_hint(header.data,header.size,scsi.data,scsi.size,parent.data,parent.size,&p) == BC_OK);
    assert(p.evidence == BC_SERVICE_EVIDENCE_HINT && !bc_service_profile_can_attempt(&p,BC_SERVICE_LOCAL_MEDIA));
    for (uint32_t n = 0; n < parent.size; ++n)
        assert(bc_megarac_jviewer_class_media_state_hint(header.data,header.size,scsi.data,scsi.size,parent.data,n,&p) != BC_OK && !p.evidence);
    for (unsigned change = 11; change <= 14; ++change) {
        header = media_serialization_fixture(change);
        assert(bc_megarac_jviewer_class_media_state_hint(header.data,header.size,scsi.data,scsi.size,parent.data,parent.size,&p) == BC_UNSUPPORTED && !p.evidence);
    }
    header = media_serialization_fixture(0);
    for (unsigned change = 16; change <= 19; ++change) {
        scsi = media_scsi_fixture(change);
        assert(bc_megarac_jviewer_class_media_state_hint(header.data,header.size,scsi.data,scsi.size,parent.data,parent.size,&p) == BC_UNSUPPORTED && !p.evidence);
    }
    scsi = media_scsi_fixture(0); parent = media_scsi_parent_fixture(1);
    assert(bc_megarac_jviewer_class_media_state_hint(header.data,header.size,scsi.data,scsi.size,parent.data,parent.size,&p) == BC_UNSUPPORTED && !p.evidence);
}

static void check_media_send(void) {
    fixture scsi = media_scsi_fixture(0), packet = media_order_fixture(0,0); bc_service_profile p;
    assert(bc_megarac_jviewer_class_media_send_hint(scsi.data,scsi.size,packet.data,packet.size,&p) == BC_OK);
    assert(p.evidence == BC_SERVICE_EVIDENCE_HINT && !bc_service_profile_can_attempt(&p,BC_SERVICE_LOCAL_MEDIA));
    for (uint32_t n = 0; n < scsi.size; ++n)
        assert(bc_megarac_jviewer_class_media_send_hint(scsi.data,n,packet.data,packet.size,&p) != BC_OK && !p.evidence);
    for (uint32_t n = 0; n < packet.size; ++n)
        assert(bc_megarac_jviewer_class_media_send_hint(scsi.data,scsi.size,packet.data,n,&p) != BC_OK && !p.evidence);
    for (unsigned change = 1; change <= 5; ++change) {
        scsi = media_scsi_fixture(change);
        assert(bc_megarac_jviewer_class_media_send_hint(scsi.data,scsi.size,packet.data,packet.size,&p) == BC_UNSUPPORTED && !p.evidence);
    }
    scsi = media_scsi_fixture(0);
    for (unsigned change = 13; change <= 17; ++change) {
        packet = media_order_fixture(0,change);
        assert(bc_megarac_jviewer_class_media_send_hint(scsi.data,scsi.size,packet.data,packet.size,&p) == BC_UNSUPPORTED && !p.evidence);
    }
}

static void check_media_runtime(void) {
    const uint8_t ret[] = {3,172}; fixture entry = media_entry_fixture(0), app = make_ex(1,0,ret,sizeof(ret),0); bc_service_profile p;
    assert(bc_megarac_jviewer_class_media_runtime_hint(entry.data,entry.size,app.data,app.size,&p) == BC_OK);
    assert(p.evidence == BC_SERVICE_EVIDENCE_HINT && !bc_service_profile_can_attempt(&p,BC_SERVICE_LOCAL_MEDIA));
    for (uint32_t n = 0; n < entry.size; ++n)
        assert(bc_megarac_jviewer_class_media_runtime_hint(entry.data,n,app.data,app.size,&p) != BC_OK && !p.evidence);
    for (uint32_t n = 0; n < app.size; ++n)
        assert(bc_megarac_jviewer_class_media_runtime_hint(entry.data,entry.size,app.data,n,&p) != BC_OK && !p.evidence);
    for (unsigned change = 1; change <= 6; ++change) {
        entry = media_entry_fixture(change); app = make_ex(1,0,ret,sizeof(ret),change);
        assert(bc_megarac_jviewer_class_media_runtime_hint(entry.data,entry.size,app.data,app.size,&p) == BC_UNSUPPORTED && !p.evidence);
    }
}

static void check_media_auth(void) {
    fixture f = media_order_fixture(1,0); bc_service_profile p;
    assert(bc_megarac_jviewer_class_media_auth_hint(f.data,f.size,&p) == BC_OK);
    assert(p.evidence == BC_SERVICE_EVIDENCE_HINT && !bc_service_profile_can_attempt(&p,BC_SERVICE_LOCAL_MEDIA));
    for (uint32_t n = 0; n < f.size; ++n)
        assert(bc_megarac_jviewer_class_media_auth_hint(f.data,n,&p) != BC_OK && !p.evidence);
    for (unsigned change = 7; change <= 12; ++change) {
        f = media_order_fixture(1,change);
        assert(bc_megarac_jviewer_class_media_auth_hint(f.data,f.size,&p) == BC_UNSUPPORTED && !p.evidence);
    }
}

static void check_media_order(void) {
    fixture cdrom = media_order_fixture(1,0), packet = media_order_fixture(0,0); bc_service_profile p;
    assert(bc_megarac_jviewer_class_media_order_hint(cdrom.data,cdrom.size,packet.data,packet.size,&p) == BC_OK);
    assert(p.evidence == BC_SERVICE_EVIDENCE_HINT && !bc_service_profile_can_attempt(&p,BC_SERVICE_LOCAL_MEDIA));
    for (uint32_t n = 0; n < packet.size; ++n)
        assert(bc_megarac_jviewer_class_media_order_hint(cdrom.data,cdrom.size,packet.data,n,&p) != BC_OK && !p.evidence);
    for (uint32_t n = 0; n < cdrom.size; ++n)
        assert(bc_megarac_jviewer_class_media_order_hint(cdrom.data,n,packet.data,packet.size,&p) != BC_OK && !p.evidence);
    for (unsigned change = 1; change <= 6; ++change) {
        cdrom = media_order_fixture(1,change); packet = media_order_fixture(0,change);
        assert(bc_megarac_jviewer_class_media_order_hint(cdrom.data,cdrom.size,packet.data,packet.size,&p) == BC_UNSUPPORTED && !p.evidence);
    }
}

static void check_media_defaults(void) {
    fixture media = media_serialization_fixture(0), parent = media_parent_fixture(0); bc_service_profile p;
    assert(bc_megarac_jviewer_class_media_hint(media.data,media.size,parent.data,parent.size,&p) == BC_OK);
    assert(!bc_service_profile_can_attempt(&p,BC_SERVICE_LOCAL_MEDIA));
    for (uint32_t n = 0; n < parent.size; ++n)
        assert(bc_megarac_jviewer_class_media_hint(media.data,media.size,parent.data,n,&p) != BC_OK && !p.evidence);
    parent = media_parent_fixture(1);
    assert(bc_megarac_jviewer_class_media_hint(media.data,media.size,parent.data,parent.size,&p) == BC_UNSUPPORTED && !p.evidence);
    parent = media_parent_fixture(0);
    for (unsigned change = 8; change <= 9; ++change) {
        media = media_serialization_fixture(change);
        assert(bc_megarac_jviewer_class_media_hint(media.data,media.size,parent.data,parent.size,&p) == BC_UNSUPPORTED && !p.evidence);
    }
}

static void check_media_serialization(void) {
    bc_service_profile profile; fixture f = media_serialization_fixture(0);
    assert(bc_megarac_jviewer_class_media_serialization_hint(f.data,f.size,&profile) == BC_OK);
    assert(profile.evidence == BC_SERVICE_EVIDENCE_HINT && !bc_service_profile_can_attempt(&profile,BC_SERVICE_LOCAL_MEDIA));
    for (uint32_t i = 0; i < f.size; ++i)
        assert(bc_megarac_jviewer_class_media_serialization_hint(f.data,i,&profile) != BC_OK && !profile.evidence);
    f = media_serialization_fixture(7);
    assert(bc_megarac_jviewer_class_media_serialization_hint(f.data,f.size,&profile) == BC_OK);
    for (unsigned change = 1; change <= 6; ++change) {
        f = media_serialization_fixture(change);
        assert(bc_megarac_jviewer_class_media_serialization_hint(f.data,f.size,&profile) == BC_UNSUPPORTED && !profile.evidence);
    }
}

static void check_media_header(void) {
    bc_service_profile profile;
    fixture f = media_header_fixture(1,32,1);
    assert(bc_megarac_jviewer_class_media_header_hint(f.data,f.size,&profile) == BC_OK);
    assert(profile.service == BC_SERVICE_LOCAL_MEDIA && profile.family == BC_SERVICE_FAMILY_MEGARAC &&
        profile.variant == BC_SERVICE_MEGARAC_MEDIA_IUSB_CD && profile.evidence == BC_SERVICE_EVIDENCE_HINT);
    assert(!bc_service_profile_can_attempt(&profile,BC_SERVICE_LOCAL_MEDIA));
    for (uint32_t i = 0; i < f.size; ++i)
        assert(bc_megarac_jviewer_class_media_header_hint(f.data,i,&profile) != BC_OK && !profile.evidence);
    f = media_header_fixture(2,32,1);
    assert(bc_megarac_jviewer_class_media_header_hint(f.data,f.size,&profile) == BC_UNSUPPORTED && !profile.evidence);
    f = media_header_fixture(1,33,1);
    assert(bc_megarac_jviewer_class_media_header_hint(f.data,f.size,&profile) == BC_UNSUPPORTED && !profile.evidence);
    f = media_header_fixture(1,32,0);
    assert(bc_megarac_jviewer_class_media_header_hint(f.data,f.size,&profile) == BC_UNSUPPORTED && !profile.evidence);
}

#ifdef BC_TEST_JAR
static void check_media_jar(void) {
    fixture media = media_serialization_fixture(0), parent = media_parent_fixture(0),
        cdrom = media_order_fixture(1,0), packet = media_order_fixture(0,0);
    const uint8_t code[] = {3,172}; fixture app = app_fixture(code,sizeof(code)), entry = media_entry_fixture(0), scsi = media_scsi_fixture(0), packet_parent = media_scsi_parent_fixture(0);
    fixture *classes[] = {&media,&parent,&cdrom,&packet,&entry,&app,&scsi,&packet_parent,&media};
    const char *names[] = {"com/ami/iusb/protocol/IUSBHeader.class","com/ami/iusb/protocol/RedirHeader.class",
        "com/ami/iusb/CDROMRedir.class", "com/ami/iusb/protocol/PacketMaster.class",
        "com/ami/kvm/jviewer/JViewer.class", "com/ami/kvm/jviewer/gui/JViewerApp.class",
        "com/ami/iusb/protocol/IUSBSCSI.class", "com/ami/iusb/protocol/RedirPacket.class", "com/ami/iusb/protocol/IUSBHeader.class"};
    bc_service_profile p;
    for (int compressed = 0; compressed <= 1; ++compressed) {
        fixture jar = jar_classes(classes,names,1,compressed);
        assert(bc_megarac_jviewer_jar_media_hint(jar.data,jar.size,&p) == BC_UNSUPPORTED && !p.evidence);
        jar = jar_classes(classes,names,8,compressed);
        assert(bc_megarac_jviewer_jar_media_hint(jar.data,jar.size,&p) == BC_OK && p.evidence == BC_SERVICE_EVIDENCE_HINT);
        assert(!bc_service_profile_can_attempt(&p,BC_SERVICE_LOCAL_MEDIA));
        jar = jar_classes(classes,names,9,compressed);
        assert(bc_megarac_jviewer_jar_media_hint(jar.data,jar.size,&p) == BC_PROTOCOL_ERROR && !p.evidence);
        media = media_serialization_fixture(2); jar = jar_classes(classes,names,8,compressed);
        assert(bc_megarac_jviewer_jar_media_hint(jar.data,jar.size,&p) == BC_UNSUPPORTED && !p.evidence);
        media = media_serialization_fixture(0);
        cdrom = media_order_fixture(1,7); jar = jar_classes(classes,names,8,compressed);
        assert(bc_megarac_jviewer_jar_media_hint(jar.data,jar.size,&p) == BC_UNSUPPORTED && !p.evidence);
        cdrom = media_order_fixture(1,0);
        entry = media_entry_fixture(4); jar = jar_classes(classes,names,8,compressed);
        assert(bc_megarac_jviewer_jar_media_hint(jar.data,jar.size,&p) == BC_UNSUPPORTED && !p.evidence);
        entry = media_entry_fixture(0);
        scsi = media_scsi_fixture(1); jar = jar_classes(classes,names,8,compressed);
        assert(bc_megarac_jviewer_jar_media_hint(jar.data,jar.size,&p) == BC_UNSUPPORTED && !p.evidence);
        scsi = media_scsi_fixture(0);
        packet_parent = media_scsi_parent_fixture(1); jar = jar_classes(classes,names,8,compressed);
        assert(bc_megarac_jviewer_jar_media_hint(jar.data,jar.size,&p) == BC_UNSUPPORTED && !p.evidence);
        packet_parent = media_scsi_parent_fixture(0);
    }
}
#endif

static void check_token_default(void) {
    const uint8_t valid[] = {3,179,0,9,177};
    fixture f = token_default_fixture(valid,sizeof(valid)); uint32_t value;
    assert(bc_megarac_jviewer_class_token_default(f.data,f.size,&value) == BC_OK && value == 0);
    for (uint32_t i=0;i<f.size;++i)
        assert(bc_megarac_jviewer_class_token_default(f.data,i,&value) != BC_OK && value == UINT32_MAX);
    const uint8_t bypass[] = {3,153,0,7,3,179,0,9,177};
    f = token_default_fixture(bypass,sizeof(bypass));
    assert(bc_megarac_jviewer_class_token_default(f.data,f.size,&value) == BC_UNSUPPORTED && value == UINT32_MAX);
    const uint8_t nonzero[] = {4,179,0,9,177};
    f = token_default_fixture(nonzero,sizeof(nonzero));
    assert(bc_megarac_jviewer_class_token_default(f.data,f.size,&value) == BC_UNSUPPORTED && value == UINT32_MAX);
    const uint8_t operand[] = {3,167,0,4,3,179,0,9,177};
    f = token_default_fixture(operand,sizeof(operand));
    assert(bc_megarac_jviewer_class_token_default(f.data,f.size,&value) == BC_UNSUPPORTED && value == UINT32_MAX);
}

#ifdef BC_TEST_JAR
static void check_jar(void) {
    uint8_t code[] = {0x11,0,203,0x3d,0xbb,0,11,0x59,0x10,18,0x1c,3,0xb7,0,15,3,0xac};
    fixture h = make(0,195,NULL,0), a = app_fixture(code,sizeof(code)); bc_service_profile p;
    for (int compressed = 0; compressed < 2; ++compressed) {
        fixture jar = jar_of(&h,&a,compressed,0);
        assert(bc_megarac_jviewer_jar_evidence(jar.data,jar.size,&p) == BC_OK);
        assert(p.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195 && p.evidence == BC_SERVICE_EVIDENCE_HINT);
        for (uint32_t i = 0; i < jar.size; ++i)
            assert(bc_megarac_jviewer_jar_evidence(jar.data,i,&p) != BC_OK && !p.evidence);
        jar.data[14] ^= 1;
        assert(bc_megarac_jviewer_jar_evidence(jar.data,jar.size,&p) == BC_PROTOCOL_ERROR && !p.evidence);
        jar = jar_of(&h,&a,compressed,1);
        assert(bc_megarac_jviewer_jar_evidence(jar.data,jar.size,&p) == BC_PROTOCOL_ERROR && !p.evidence);
        jar = jar_of(&h,&a,compressed,0); jar.data[30 + strlen("com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr.class")] ^= 1;
        assert(bc_megarac_jviewer_jar_evidence(jar.data,jar.size,&p) == BC_PROTOCOL_ERROR && !p.evidence);
    }
    fixture jar = jar_of(&h,&a,0,0);
    uint32_t start = (uint32_t)jar.data[jar.size-6] | ((uint32_t)jar.data[jar.size-5] << 8);
    jar.data[start+8] = 1;
    assert(bc_megarac_jviewer_jar_evidence(jar.data,jar.size,&p) == BC_UNSUPPORTED && !p.evidence);
    jar = jar_of(&h,&a,0,0); jar.data[start+24] = 1; jar.data[start+25] = 0; jar.data[start+26] = 16; jar.data[start+27] = 0;
    assert(bc_megarac_jviewer_jar_evidence(jar.data,jar.size,&p) == BC_LIMIT_EXCEEDED && !p.evidence);
    const uint8_t initialized[] = {3,179,0,9,177};
    fixture entry = token_default_fixture(initialized,sizeof(initialized));
    fixture *all[] = {&h,&a,&entry,&entry};
    const char *names[] = {"com/ami/kvm/jviewer/kvmpkts/IVTPPktHdr.class", "com/ami/kvm/jviewer/gui/JViewerApp.class",
        "com/ami/kvm/jviewer/JViewer.class", "com/ami/kvm/jviewer/JViewer.class"};
    uint32_t value;
    for (int compressed=0;compressed<2;++compressed) {
        jar = jar_classes(all,names,3,compressed);
        assert(bc_megarac_jviewer_jar_token_default(jar.data,jar.size,&value) == BC_OK && value == 0);
        jar = jar_classes(all,names,4,compressed);
        assert(bc_megarac_jviewer_jar_token_default(jar.data,jar.size,&value) == BC_PROTOCOL_ERROR && value == UINT32_MAX);
    }
    jar = jar_of(&h,&a,0,0);
    assert(bc_megarac_jviewer_jar_token_default(jar.data,jar.size,&value) == BC_UNSUPPORTED && value == UINT32_MAX);
    uint8_t empty[22] = {0};
    assert(bc_megarac_jviewer_jar_evidence(empty,16*1024*1024+1,&p) == BC_LIMIT_EXCEEDED);
}
#endif

static bc_status resource_path(const char *xml, char *out, uint32_t capacity) {
    const char *origin = "https://bmc.example:443", *launch = "/Java/jviewer.jnlp";
    return bc_megarac_jviewer_resource_path((const uint8_t *)xml, (uint32_t)strlen(xml),
        (bc_string){origin, strlen(origin)}, (bc_string){launch, strlen(launch)}, out, capacity);
}
static void check_resources(void) {
    char out[1025];
    const char *valid = "<jnlp codebase='https://bmc.example:443/Java'><resources><jar href='release/client.jar'/></resources></jnlp>";
    assert(resource_path(valid, out, sizeof(out)) == BC_OK && !strcmp(out,"/Java/release/client.jar"));
    assert(resource_path(valid, out, 4) == BC_LIMIT_EXCEEDED && !out[0]);
    const char *canonical = "<jnlp codebase='HTTPS://BMC.EXAMPLE:443/Java'><resources><jar href='release/client.jar'/></resources></jnlp>";
    char sliced[sizeof("https://bmc.example/")-1]; memcpy(sliced,"https://bmc.example/",sizeof(sliced));
    const char *launch = "/Java/jviewer.jnlp";
    assert(bc_megarac_jviewer_resource_path((const uint8_t *)canonical,(uint32_t)strlen(canonical),
        (bc_string){sliced,sizeof(sliced)},(bc_string){launch,strlen(launch)},out,sizeof(out)) == BC_OK);
    assert(!strcmp(out,"/Java/release/client.jar"));
    const char *main = "<jnlp><resources><jar href='aux.jar'/><jar main='true' href='/shared/main.jar'/></resources></jnlp>";
    assert(resource_path(main, out, sizeof(out)) == BC_OK && !strcmp(out,"/shared/main.jar"));
    const char *qualified = "<jnlp><resources os='Windows'><jar href='windows.jar'/></resources><resources><jar href='portable.jar'/></resources></jnlp>";
    assert(resource_path(qualified,out,sizeof(out)) == BC_OK && !strcmp(out,"/Java/portable.jar"));
    const char *implicit_main = "<jnlp><resources><jar href='release/JViewer.jar'/><jar href='release/JViewer-SOC.jar'/></resources></jnlp>";
    assert(resource_path(implicit_main,out,sizeof(out)) == BC_OK && !strcmp(out,"/Java/release/JViewer.jar"));
    const char *unsupported[] = {
        "<jnlp codebase='https://foreign.example/Java'><resources><jar href='a.jar'/></resources></jnlp>",
        "<jnlp><resources os='Windows'><jar href='a.jar'/></resources></jnlp>",
        "<jnlp><resources><nativelib href='native.jar'/></resources></jnlp>",
        "<jnlp><resources><jar href='a.jar' version='1.0'/></resources></jnlp>",
        "<jnlp><resources><jar href='https://bmc.example:4430/a.jar'/></resources></jnlp>"
    };
    for (size_t i=0;i<sizeof(unsupported)/sizeof(unsupported[0]);++i)
        assert(resource_path(unsupported[i],out,sizeof(out)) == BC_UNSUPPORTED && !out[0]);
    const char *hrefs[] = {"../a.jar", "/Java/../a.jar", "/Java/%2e/a.jar", "//foreign/a.jar", "a.jar?token=fixture", "a.jar#x", "https://bmc.example:444/a.jar", "https://bmc.example:443@foreign/a.jar", "http://bmc.example:443/a.jar", "a\\b.jar"};
    for (size_t i=0;i<sizeof(hrefs)/sizeof(hrefs[0]);++i) {
        char xml[512]; snprintf(xml,sizeof(xml),"<jnlp><resources><jar href='%s'/></resources></jnlp>",hrefs[i]);
        assert(resource_path(xml,out,sizeof(out)) == BC_UNSUPPORTED && !out[0]);
    }
    const char *invalid[] = {
        "<jnlp><resources><jar href='a.jar' href='b.jar'/></resources></jnlp>",
        "<jnlp><resources><jar/></resources></jnlp>",
        "<jnlp><resources><jar main='true' href='a.jar'/><jar main='true' href='b.jar'/></resources></jnlp>"
    };
    for (size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i)
        assert(resource_path(invalid[i],out,sizeof(out)) == BC_PROTOCOL_ERROR && !out[0]);
}
int main(int argc, char **argv) {
    check_token_default();
    check_media_header();
    check_media_serialization();
    check_media_defaults();
    check_media_order();
    check_media_auth();
    check_media_runtime();
    check_media_send();
    check_media_state();
    check_single_port_default();
    check_failure_handlers();
#ifdef BC_TEST_JAR
    check_media_jar();
#endif
#ifdef BC_TEST_JAR
    if (argc == 2 && !strcmp(argv[1],"--emit-jar")) {
        uint8_t code[] = {0x11,0,203,0x3d,0xbb,0,11,0x59,0x10,18,0x1c,3,0xb7,0,15,3,0xac};
        fixture h = make(0,195,NULL,0), a = app_fixture(code,sizeof(code)), jar = jar_of(&h,&a,1,0);
#if defined(_WIN32)
        _setmode(_fileno(stdout),_O_BINARY);
#endif
        return fwrite(jar.data,1,jar.size,stdout) == jar.size ? 0 : 1;
    }
#endif
    (void)argc; (void)argv;
    check_resources();
#ifdef BC_TEST_JAR
    check_jar();
#else
    uint8_t jar_byte = 0; bc_service_profile absent;
    assert(bc_megarac_jviewer_jar_evidence(&jar_byte, 1, &absent) == BC_UNSUPPORTED && !absent.evidence);
#endif
    uint8_t code[] = {0x11,0,203,0x3d,0xbb,0,11,0x59,0x10,18,0x1c,3,0xb7,0,15,3,0xac};
    fixture h = make(0, 195, NULL, 0), a = app_fixture(code,sizeof(code)); bc_service_profile p;
    fixture unsent = make(1,0,code,sizeof(code));
    assert(evidence(&h, &unsent, &p) == BC_UNSUPPORTED && !p.evidence);
    assert(evidence(&h, &a, &p) == BC_OK && p.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195);
    assert(p.evidence == BC_SERVICE_EVIDENCE_HINT && !bc_service_profile_can_attempt(&p, BC_SERVICE_KVM));
    code[1] = 1; code[2] = 125; a = app_fixture(code,sizeof(code));
    assert(evidence(&h, &a, &p) == BC_UNSUPPORTED && !p.evidence);
    h = make(0, 373, NULL, 0);
    assert(evidence(&h, &a, &p) == BC_OK && p.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_373);
    for (uint32_t i = 0; i < h.size; ++i) {
        assert(bc_megarac_jviewer_class_evidence(h.data, i, a.data, a.size, &p) != BC_OK && !p.evidence);
    }
    for (uint32_t i = 0; i < a.size; ++i) {
        assert(bc_megarac_jviewer_class_evidence(h.data, h.size, a.data, i, &p) != BC_OK && !p.evidence);
    }
    uint8_t dead[] = {3,0xac,0xbb,0,11,0x59,0x10,18,0x11,1,125,3,0xb7,0,15,3,0xac};
    a = app_fixture(dead,sizeof(dead)); assert(evidence(&h, &a, &p) == BC_UNSUPPORTED);
    uint8_t separated[] = {3,0x99,0,19,0xbb,0,11,0x59,0x10,18,0x11,0,203,3,0xb7,0,15,0xa7,0,15,
        0xb6,0,19,0xb6,0,25,0xb6,0,28,0xb6,0,34,3,0xac};
    h = make(0,195,NULL,0); a = make(1,0,separated,sizeof(separated));
    assert(evidence(&h,&a,&p) == BC_UNSUPPORTED && !p.evidence);
    h = make(0,373,NULL,0);
    uint8_t overwritten[] = {0x11,1,125,0x3d,1,0x4d,0xbb,0,11,0x59,0x10,18,0x1c,3,0xb7,0,15,3,0xac};
    a = app_fixture(overwritten,sizeof(overwritten)); assert(evidence(&h, &a, &p) == BC_UNSUPPORTED);
    uint8_t bad_jump[] = {0xa7,0,1,3,0xac}; a = app_fixture(bad_jump,sizeof(bad_jump));
    assert(evidence(&h, &a, &p) == BC_PROTOCOL_ERROR && !p.evidence);
    h = make(0, 324, NULL, 0); a = app_fixture(code,sizeof(code));
    assert(evidence(&h, &a, &p) == BC_UNSUPPORTED && !p.evidence);
    return 0;
}

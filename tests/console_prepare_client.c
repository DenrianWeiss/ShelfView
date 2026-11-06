#include "bcontrol/console_client.h"
#include <stdio.h>
#include <string.h>
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static bc_status read_source(void *user, uint64_t offset, uint32_t n, uint8_t *out) {
    (void)user; if (offset + n > 1024u * 2048u) return BC_IO_ERROR;
    for (uint32_t i=0;i<n;++i) out[i]=(uint8_t)((offset+i)%251);
    return BC_OK;
}
static bc_status decode(void *user,bc_decode_job *job) { (void)user; (void)bc_decode_job_execute(job);bc_decode_job_destroy(job);return BC_OK; }
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    bc_console_client_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.service = BC_CLIENT_PREPARE; options.timeout_ms = 10000;
    options.address = text(argv[1]); options.ca_file = text(argv[2]);
    options.username = text("user"); options.password = text("test-secret");
    options.tls_min = BC_TLS_1_2;
    int view = !strcmp(argv[3], "aten-view");
    int aten = !strcmp(argv[3], "aten") || !strcmp(argv[3], "aten-probe") || !strcmp(argv[3], "aten-media") || !strcmp(argv[3], "aten-live") || view;
    if(!strncmp(argv[3], "aten-probe",10))options.service=BC_CLIENT_PREPARE_MEDIA;
    if(view || !strcmp(argv[3],"aten-live") || !strcmp(argv[3],"failure-live")){options.service=BC_CLIENT_CONSOLE;options.submit=decode;}
    int media = !strncmp(argv[3], "media", 5) || !strcmp(argv[3], "aten-media");
    int rejected = !strcmp(argv[3], "media-busy") || !strcmp(argv[3], "media-race");
    int uncertain = !strcmp(argv[3], "media-uncertain");
    bc_media_source source = {sizeof(source), NULL, 1024u * 2048u, read_source};
    if (media) { options.service = BC_CLIENT_MEDIA; options.source = &source; }
    bc_console_client *client = NULL;
    bc_status status = bc_console_client_create(&options, &client);
    if (status == BC_OK) status = bc_console_client_start(client);
    bc_console_client_info info = {0}; info.struct_size = sizeof(info);
    bc_console_client_info_get(client, &info);
    int avocent = (media && !aten) || !strcmp(argv[3], "avocent");
    int success = !rejected && (aten || avocent || !strcmp(argv[3], "success"));
    int valid = success ? status == BC_OK && (avocent ? info.profile.family == BC_SERVICE_FAMILY_AVOCENT && (media ? (info.flags & BC_CLIENT_MOUNT_CONFIRMED) != 0 : !info.profile.variant) :
        info.profile.family == BC_SERVICE_FAMILY_MEGARAC && info.profile.variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195) : status != BC_OK;
    if(aten)valid=status==BC_OK && info.profile.family==BC_SERVICE_FAMILY_ATEN && (options.service!=BC_CLIENT_PREPARE_MEDIA || (info.flags&BC_CLIENT_LOCAL_MEDIA));
    if (media && status == BC_OK) {
        for (unsigned i=0;i<100 && info.bytes_read<5u*2048u;++i) {
            status=bc_console_client_poll(client,20);
            bc_console_client_info_get(client,&info);
            if(status!=BC_OK)break;
        }
        valid &= status==BC_OK && info.bytes_read==5u*2048u;
    }
    if(aten && options.service==BC_CLIENT_CONSOLE && status==BC_OK) {
        bc_display_tile tile={0};tile.struct_size=sizeof(tile);
        for(unsigned i=0;i<100;++i){status=bc_console_client_poll(client,20);if(status!=BC_OK)break;
            if(bc_console_client_tile(client,&tile)==BC_OK && tile.width)break;}
        valid &= status==BC_OK && tile.width==2 && tile.height==2 && tile.pixels.data && tile.pixels.data[0]==255;
    }
    if (!view && aten && options.service == BC_CLIENT_CONSOLE && status == BC_OK) {
        bc_console_input event={0};event.struct_size=sizeof(event);event.type=BC_CONSOLE_INPUT_KEY;event.keysym='a';event.down=1;
        valid &= bc_console_client_input(client,&event)==BC_OK;
        const uint32_t keys[]={'a','A','A','!','!'};
        const uint8_t down[]={0,1,0,1,0};
        for(unsigned i=0;i<5;++i){event.keysym=keys[i];event.down=down[i];valid &= bc_console_client_input(client,&event)==BC_OK;}
        event.type=BC_CONSOLE_INPUT_POINTER;event.width=2;event.height=2;event.x=1;event.y=1;event.buttons=1;
        valid &= bc_console_client_input(client,&event)==BC_OK;
        event.type=BC_CONSOLE_INPUT_SCROLL;event.wheel=1;
        valid &= bc_console_client_input(client,&event)==BC_OK;
        valid &= bc_console_client_poll(client,20)==BC_OK;
    }
    bc_status cleanup = bc_console_client_close(client);
    if (success && !uncertain && cleanup != BC_OK) valid = 0;
    if (uncertain) {
        bc_console_client_info_get(client, &info);
        valid &= cleanup != BC_OK && (info.flags & BC_CLIENT_REMOVAL_UNCONFIRMED) != 0;
    }
    fprintf(stderr, "prepare status=%u family=%u variant=%u cleanup=%u\n", status,
        info.profile.family, info.profile.variant, cleanup);
    bc_console_client_destroy(client);
    return valid ? 0 : 1;
}

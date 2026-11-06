#include "bcontrol/vault_media.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bc_string str(const char *s){return(bc_string){s,strlen(s)};}
static bc_bytes bytes(const char *s){return(bc_bytes){(const uint8_t *)s,strlen(s)};}
static bc_vault_media_scope *scope(const char *address,const char *username) {
    bc_vault_media_scope *out=NULL;assert(bc_vault_media_scope_create(str(address),str(username),&out)==BC_OK);return out;
}
static char *exported(bc_vault_merge *m) {
    uint32_t size=0;assert(bc_vault_merge_export(m,NULL,0,&size)==BC_LIMIT_EXCEEDED);
    char *out=calloc((size_t)size+1,1);assert(out);
    assert(bc_vault_merge_export(m,(uint8_t *)out,size,&size)==BC_OK);bc_vault_merge_destroy(m);return out;
}
static char *patch(bc_vault_media_scope *s,const char *data,uint32_t op) {
    bc_vault_merge *m=NULL;assert(bc_vault_media_scope_patch(s,bytes(data),op,0,&m)==BC_OK);return exported(m);
}
static void identities(void) {
    const char *pairs[][2]={{"HTTPS://BMC.EXAMPLE","https://bmc.example:443/"},
        {"https://[2001:0DB8:0:0:0:0:0:1]","https://[2001:db8::1]:443"},
        {"https://[::ffff:192.0.2.1]","https://[::ffff:c000:201]"}};
    for(unsigned i=0;i<sizeof(pairs)/sizeof(pairs[0]);++i){
        bc_vault_media_scope *a=scope(pairs[i][0],"fixture"),*b=scope(pairs[i][1],"fixture"),*other=scope(pairs[i][1],"another user");
        assert(!memcmp(bc_vault_media_scope_id(a).data,bc_vault_media_scope_id(b).data,76));
        assert(memcmp(bc_vault_media_scope_id(a).data,bc_vault_media_scope_id(other).data,76));
        bc_vault_media_scope_destroy(a);bc_vault_media_scope_destroy(b);bc_vault_media_scope_destroy(other);
    }
    bc_vault_media_scope *invalid=NULL;
    assert(bc_vault_media_scope_create(str("https://[:::1]"),str("fixture"),&invalid)==BC_INVALID_ARGUMENT&&!invalid);
    assert(bc_vault_media_scope_create(str("https://bmc.example:0"),str("fixture"),&invalid)==BC_INVALID_ARGUMENT&&!invalid);
    assert(bc_vault_media_scope_create(str("https://user@bmc.example"),str("fixture"),&invalid)==BC_INVALID_ARGUMENT&&!invalid);
}
static void generations(void) {
    const char *empty="{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{}}";
    bc_vault_media_scope *owner=scope("https://bmc.example","fixture"),*reader=scope("https://bmc.example","fixture");
    char *first=patch(owner,empty,BC_VAULT_MEDIA_BEGIN);int known=0,pending=0;
    assert(bc_vault_media_scope_read(reader,bytes(first),&known,&pending)==BC_OK&&known&&pending);
    bc_vault_media_scope *observer=NULL;
    assert(bc_vault_media_scope_observe(owner,bytes(first),&observer,&known,&pending)==BC_OK&&known&&pending);
    bc_vault_merge *rejected=NULL;
    assert(bc_vault_media_scope_patch(reader,bytes(first),BC_VAULT_MEDIA_BEGIN,0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    char *cleared=patch(owner,first,BC_VAULT_MEDIA_CLEAR),*second=patch(owner,cleared,BC_VAULT_MEDIA_BEGIN);
    bc_vault_merge *conflict=NULL;
    assert(bc_vault_merge_create(bytes(first),bytes(cleared),bytes(second),&conflict)==BC_OK);
    assert(bc_vault_merge_pending(conflict)==1);bc_vault_merge_destroy(conflict);
    assert(bc_vault_media_scope_patch(reader,bytes(second),BC_VAULT_MEDIA_CLEAR,0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    assert(bc_vault_media_scope_read(owner,bytes(second),&known,&pending)==BC_OK&&pending);
    assert(bc_vault_media_scope_patch(observer,bytes(second),BC_VAULT_MEDIA_CLEAR_OBSERVED,0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    char *ack=patch(reader,second,BC_VAULT_MEDIA_ACKNOWLEDGE),*imported=patch(owner,ack,BC_VAULT_MEDIA_IMPORT_PENDING);
    assert(bc_vault_media_scope_read(reader,bytes(imported),&known,&pending)==BC_OK&&known&&!pending);
    free(first);free(cleared);free(second);free(ack);free(imported);
    bc_vault_media_scope_destroy(owner);bc_vault_media_scope_destroy(reader);
    bc_vault_media_scope_destroy(observer);
}
static void legacy(void) {
    const char *data="{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{"
        "\"state:media:41ee6c8b57b0195bffd4e0f85e389e7cc560378607d6b3d42d42c6ba5ed41074\":{\"fields\":{\"pending\":true},\"deleted\":false,\"modified_at_ms\":0}}}";
    bc_vault_media_scope *s=scope("ipmi://bmc.example","fixture");int known=0,pending=0;
    assert(bc_vault_media_scope_read(s,bytes(data),&known,&pending)==BC_OK&&known&&pending);
    char *cleared=patch(s,data,BC_VAULT_MEDIA_CLEAR),*imported=patch(s,cleared,BC_VAULT_MEDIA_IMPORT_PENDING);
    assert(bc_vault_media_scope_read(s,bytes(imported),&known,&pending)==BC_OK&&known&&!pending);
    free(cleared);free(imported);bc_vault_media_scope_destroy(s);
}
static void migration(void) {
    const char *data="{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{\"migration:apple\":{\"fields\":{\"media_migration_pending\":true},\"deleted\":false,\"modified_at_ms\":0}}}";
    bc_vault_media_scope *s=scope("https://bmc.example","fixture");int known=0,pending=0;
    assert(bc_vault_media_scope_read(s,bytes(data),&known,&pending)==BC_OK&&!known&&!pending);
    bc_string ids[2]={bc_vault_media_scope_id(s),bc_vault_media_scope_id(s)};bc_vault_merge *m=NULL;
    assert(bc_vault_media_import_pending(bytes(data),ids,2,0,&m)==BC_OK);char *imported=exported(m);
    assert(bc_vault_media_scope_read(s,bytes(imported),&known,&pending)==BC_OK&&pending);
    assert(bc_vault_record_patch(bytes(imported),str("migration:apple"),bytes("{\"media_migration_pending\":false}"),0,0,&m)==BC_OK);
    char *ready=exported(m);assert(bc_vault_media_scope_read(s,bytes(ready),&known,&pending)==BC_OK&&known&&pending);
    ids[1]=str("invalid");assert(bc_vault_media_import_pending(bytes(ready),ids,2,0,&m)==BC_INVALID_ARGUMENT&&!m);
    free(imported);free(ready);bc_vault_media_scope_destroy(s);
}
static char *remote_patch(bc_vault_media_scope *s,const char *data,const char *uri,const char *expected,uint32_t action,uint32_t phase) {
    bc_vault_merge *m=NULL;assert(bc_vault_media_remote_patch(s,bytes(data),str(uri),str(expected),action,phase,phase==BC_VAULT_REMOTE_SUBMITTING?(bc_bytes){0}:bytes("opaque reference"),0,&m)==BC_OK);return exported(m);
}
static void remote_generation(const char *data,char generation[33]) {
    const char *prefix="\"operation_id\":\"",*found=strstr(data,prefix);assert(found);
    memcpy(generation,found+strlen(prefix),32);generation[32]=0;
}
static void remote_records(void) {
    const char *empty="{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{}}";
    const char *uri="/redfish/v1/Managers/1/VirtualMedia/1";
    bc_vault_media_scope *s=scope("https://bmc.example","fixture"),*other=scope("https://bmc.example","other");
    char *first=remote_patch(s,empty,uri,"",BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_SUBMITTING),generation[33];remote_generation(first,generation);
    bc_vault_merge *rejected=NULL;
    assert(bc_vault_media_remote_patch(s,bytes(first),str(uri),str(generation),BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_SUBMITTING,(bc_bytes){0},0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    char *accepted=remote_patch(s,first,uri,generation,BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_ACCEPTED);
    assert(bc_vault_media_scope_patch(s,bytes(first),BC_VAULT_MEDIA_BEGIN,0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    assert(bc_vault_media_scope_patch(s,bytes(accepted),BC_VAULT_MEDIA_BEGIN,0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    char *settled=remote_patch(s,accepted,uri,generation,BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_SETTLED);
    assert(bc_vault_media_scope_patch(s,bytes(settled),BC_VAULT_MEDIA_BEGIN,0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    assert(bc_vault_media_scope_patch(other,bytes(settled),BC_VAULT_MEDIA_BEGIN,0,&rejected)==BC_OK);
    bc_vault_merge_destroy(rejected);rejected=NULL;
    char *cleared=remote_patch(s,first,uri,generation,BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_CLEARED);
    assert(bc_vault_media_scope_patch(s,bytes(cleared),BC_VAULT_MEDIA_BEGIN,0,&rejected)==BC_OK);
    bc_vault_merge_destroy(rejected);rejected=NULL;
    bc_vault_merge *conflict=NULL;assert(bc_vault_merge_create(bytes(first),bytes(accepted),bytes(cleared),&conflict)==BC_OK);
    assert(bc_vault_merge_pending(conflict)==1);bc_vault_merge_destroy(conflict);
    char *second=remote_patch(s,cleared,uri,"",BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_SUBMITTING);
    assert(bc_vault_media_remote_patch(s,bytes(second),str(uri),str(generation),BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_CLEARED,(bc_bytes){0},0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    char *another=remote_patch(s,empty,"/redfish/v1/Managers/1/VirtualMedia/2","",BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_SUBMITTING);
    assert(bc_vault_merge_create(bytes(empty),bytes(first),bytes(another),&conflict)==BC_OK&&bc_vault_merge_pending(conflict)==0);
    char *merged=exported(conflict);uint32_t size=0;
    assert(bc_vault_media_remote_list(s,bytes(merged),NULL,0,&size)==BC_LIMIT_EXCEEDED&&size>2);
    unsigned char hidden[2];assert(bc_vault_media_remote_list(other,bytes(merged),hidden,2,&size)==BC_OK&&size==2&&!memcmp(hidden,"[]",2));
    assert(bc_vault_media_remote_list(s,bytes(cleared),hidden,2,&size)==BC_OK&&size==2&&!memcmp(hidden,"[]",2));
    char *local=patch(s,empty,BC_VAULT_MEDIA_BEGIN);
    assert(bc_vault_media_remote_patch(s,bytes(local),str(uri),str(""),BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_SUBMITTING,(bc_bytes){0},0,&rejected)==BC_CONFIRMATION_REQUIRED&&!rejected);
    assert(bc_vault_media_remote_patch(s,bytes(local),str(uri),str(""),BC_VAULT_REMOTE_EJECT,BC_VAULT_REMOTE_SUBMITTING,(bc_bytes){0},0,&rejected)==BC_OK);
    char *ejecting=exported(rejected);int known=0,pending=0;
    assert(bc_vault_media_scope_read(s,bytes(ejecting),&known,&pending)==BC_OK&&pending);free(ejecting);
    free(first);free(accepted);free(settled);free(cleared);free(second);free(another);free(merged);free(local);
    bc_vault_media_scope_destroy(s);bc_vault_media_scope_destroy(other);
}
static void source_verification(void) {
    const char *empty="{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{}}";
    const char *uri="/redfish/v1/Managers/1/VirtualMedia/cd",*source="https://images.invalid/image.iso?token=private-token";
    bc_vault_media_scope *s=scope("https://bmc.example","fixture");bc_vault_merge *m=NULL;char generation[33];
    assert(bc_vault_media_remote_begin(s,bytes(empty),str(uri),str(""),BC_VAULT_REMOTE_INSERT,str(source),0,&m)==BC_OK);
    char *first=exported(m);remote_generation(first,generation);assert(!strstr(first,"private-token"));
    assert(bc_vault_media_remote_observe_source(s,bytes(first),str(uri),str(generation),str(""),1,0,0,&m)==BC_OK);
    char *acknowledged=exported(m);
    assert(bc_vault_media_remote_reject(s,bytes(acknowledged),str(uri),str(generation),0,&m)==BC_CONFIRMATION_REQUIRED&&!m);
    assert(bc_vault_media_remote_observe_source(s,bytes(acknowledged),str(uri),str(generation),str(source),0,1,0,&m)==BC_OK);
    char *delayed=exported(m);assert(strstr(delayed,"\"source_verification\":1"));
    assert(strstr(delayed,"\"phase\":3"));free(acknowledged);free(delayed);
    assert(bc_vault_media_remote_observe_source(s,bytes(first),str(uri),str(generation),str(""),0,1,0,&m)==BC_OK);
    char *waiting=exported(m);
    assert(bc_vault_media_remote_begin(s,bytes(waiting),str(uri),str(generation),BC_VAULT_REMOTE_EJECT,str(""),0,&m)==BC_CONFIRMATION_REQUIRED&&!m);free(waiting);
    assert(bc_vault_media_remote_observe_source(s,bytes(first),str(uri),str(generation),str(""),1,1,0,&m)==BC_OK);
    char *missing=exported(m);assert(strstr(missing,"\"source_verification\":2"));
    assert(bc_vault_media_remote_begin(s,bytes(missing),str(uri),str(generation),BC_VAULT_REMOTE_EJECT,str(""),0,&m)==BC_OK);
    char *ejecting=exported(m);free(ejecting);
    assert(bc_vault_media_remote_observe_source(s,bytes(first),str(uri),str(generation),str("https://other.invalid/image.iso"),1,1,0,&m)==BC_OK);
    char *different=exported(m);assert(strstr(different,"\"source_verification\":3"));
    assert(bc_vault_media_remote_patch(s,bytes(different),str(uri),str(generation),BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_SETTLED,(bc_bytes){0},0,&m)==BC_CONFIRMATION_REQUIRED&&!m);
    assert(bc_vault_media_remote_observe_source(s,bytes(different),str(uri),str(generation),str(source),0,1,0,&m)==BC_OK);
    char *matched=exported(m);assert(strstr(matched,"\"source_verification\":1"));
    assert(bc_vault_media_remote_patch(s,bytes(matched),str(uri),str(generation),BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_CLEARED,(bc_bytes){0},0,&m)==BC_OK);
    char *cleared=exported(m);
    assert(bc_vault_media_remote_observe_source(s,bytes(cleared),str(uri),str(generation),str(source),1,1,0,&m)==BC_CONFIRMATION_REQUIRED&&!m);
    assert(bc_vault_media_remote_begin(s,bytes(cleared),str(uri),str(""),BC_VAULT_REMOTE_INSERT,str(source),0,&m)==BC_OK);
    char *replacement=exported(m);
    assert(bc_vault_media_remote_observe_source(s,bytes(replacement),str(uri),str(generation),str(source),1,1,0,&m)==BC_CONFIRMATION_REQUIRED&&!m);
    free(first);free(missing);free(different);free(matched);free(cleared);free(replacement);bc_vault_media_scope_destroy(s);
}
static void rejected_eject(void) {
    const char *empty="{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{}}";
    const char *uri="/redfish/v1/Managers/1/VirtualMedia/cd";
    bc_vault_media_scope *s=scope("https://bmc.example","fixture");bc_vault_merge *m=NULL;
    char original[33],ejection[33],restored_id[33];
    assert(bc_vault_media_remote_begin(s,bytes(empty),str(uri),str(""),BC_VAULT_REMOTE_INSERT,str("https://images.invalid/source.iso"),0,&m)==BC_OK);
    char *first=exported(m);remote_generation(first,original);
    const unsigned char reference[]={0,255,42};
    assert(bc_vault_media_remote_patch(s,bytes(first),str(uri),str(original),BC_VAULT_REMOTE_INSERT,BC_VAULT_REMOTE_ACCEPTED,
        (bc_bytes){reference,sizeof(reference)},0,&m)==BC_OK);
    char *accepted=exported(m);
    assert(bc_vault_media_remote_observe_source(s,bytes(accepted),str(uri),str(original),str(""),1,1,0,&m)==BC_OK);
    char *mounted=exported(m);
    char *ejecting=remote_patch(s,mounted,uri,original,BC_VAULT_REMOTE_EJECT,BC_VAULT_REMOTE_SUBMITTING);remote_generation(ejecting,ejection);
    uint32_t size=0;assert(bc_vault_media_remote_list(s,bytes(ejecting),NULL,0,&size)==BC_LIMIT_EXCEEDED);
    unsigned char *listed=calloc((size_t)size+1,1);assert(listed);
    assert(bc_vault_media_remote_list(s,bytes(ejecting),listed,size,&size)==BC_OK&&!strstr((char *)listed,"previous_insert"));free(listed);
    assert(bc_vault_media_remote_reject(s,bytes(ejecting),str(uri),str(ejection),0,&m)==BC_OK);
    char *restored=exported(m);remote_generation(restored,restored_id);
    assert(strcmp(original,restored_id)&&strcmp(ejection,restored_id));
    assert(strstr(restored,"\"phase\":3")&&strstr(restored,"\"source_verification\":2")&&
        strstr(restored,"\"reference\":\"AP8q\"")&&!strstr(restored,"previous_insert"));
    assert(bc_vault_media_remote_observe_source(s,bytes(restored),str(uri),str(original),str(""),1,1,0,&m)==BC_CONFIRMATION_REQUIRED&&!m);
    assert(bc_vault_media_remote_reject(s,bytes(restored),str(uri),str(ejection),0,&m)==BC_CONFIRMATION_REQUIRED&&!m);
    assert(bc_vault_media_remote_patch(s,bytes(restored),str(uri),str(ejection),BC_VAULT_REMOTE_EJECT,BC_VAULT_REMOTE_CLEARED,(bc_bytes){0},0,&m)==BC_CONFIRMATION_REQUIRED&&!m);
    char *retry=remote_patch(s,restored,uri,restored_id,BC_VAULT_REMOTE_EJECT,BC_VAULT_REMOTE_SUBMITTING);remote_generation(retry,ejection);
    char *submitted=remote_patch(s,retry,uri,ejection,BC_VAULT_REMOTE_EJECT,BC_VAULT_REMOTE_ACCEPTED);
    assert(!strstr(submitted,"previous_insert"));
    assert(bc_vault_media_remote_reject(s,bytes(submitted),str(uri),str(ejection),0,&m)==BC_CONFIRMATION_REQUIRED&&!m);
    char *foreign=remote_patch(s,empty,uri,"",BC_VAULT_REMOTE_EJECT,BC_VAULT_REMOTE_SUBMITTING);remote_generation(foreign,ejection);
    assert(bc_vault_media_remote_reject(s,bytes(foreign),str(uri),str(ejection),0,&m)==BC_OK);
    char *cleared=exported(m);assert(strstr(cleared,"\"phase\":4"));
    free(first);free(accepted);free(mounted);free(ejecting);free(restored);free(retry);free(submitted);free(foreign);free(cleared);
    bc_vault_media_scope_destroy(s);
}
int main(void){identities();generations();legacy();migration();remote_records();source_verification();rejected_eject();return 0;}

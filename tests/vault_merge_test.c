#include "bcontrol/vault_merge.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bc_bytes text(const char *s){return(bc_bytes){(const uint8_t *)s,strlen(s)};}
static void snapshot(char out[2048],const char *fields,unsigned time,int deleted) {
    int size=snprintf(out,2048,"{\"version\":1,\"vault_id\":\"00112233445566778899aabbccddeeff\",\"records\":{\"device-1\":{\"fields\":%s,\"deleted\":%s,\"modified_at_ms\":%u}}}",fields,deleted?"true":"false",time);
    assert(size>0&&size<2048);
}
static char *result(bc_vault_merge *m) {
    uint32_t count=0;assert(bc_vault_merge_export(m,NULL,0,&count)==BC_LIMIT_EXCEEDED);
    char *out=calloc((size_t)count+1,1);assert(out);assert(bc_vault_merge_export(m,(uint8_t *)out,count,&count)==BC_OK);return out;
}
int main(void) {
    char base[2048],local[2048],remote[2048];bc_vault_merge *m=NULL;
    snapshot(base,"{\"name\":\"old\",\"address\":\"old.invalid\"}",100,0);
    snapshot(local,"{\"name\":\"local\",\"address\":\"old.invalid\"}",1,0);
    snapshot(remote,"{\"name\":\"old\",\"address\":\"remote.invalid\"}",999,0);
    assert(bc_vault_merge_create(text(base),text(local),text(remote),&m)==BC_OK);
    assert(bc_vault_merge_pending(m)==0);char *out=result(m);
    assert(strstr(out,"\"name\":\"local\"")&&strstr(out,"\"address\":\"remote.invalid\"")&&strstr(out,"\"modified_at_ms\":999"));
    free(out);bc_vault_merge_destroy(m);m=NULL;
    snapshot(remote,"{\"name\":\"remote\",\"address\":\"old.invalid\"}",999,0);
    assert(bc_vault_merge_create(text(base),text(local),text(remote),&m)==BC_OK);
    assert(bc_vault_merge_conflicts(m)==1&&bc_vault_merge_pending(m)==1);
    uint32_t size=99;assert(bc_vault_merge_export(m,NULL,0,&size)==BC_CONFIRMATION_REQUIRED&&size==0);
    bc_bytes detail={0};assert(bc_vault_merge_conflict(m,0,&detail)==BC_OK&&detail.length);
    assert(bc_vault_merge_resolve(m,0,BC_VAULT_MERGE_REMOTE)==BC_OK);
    assert(bc_vault_merge_resolve(m,0,BC_VAULT_MERGE_LOCAL)==BC_BUSY);
    out=result(m);assert(strstr(out,"\"name\":\"remote\""));free(out);bc_vault_merge_destroy(m);m=NULL;
    snapshot(local,"{}",200,1);
    assert(bc_vault_merge_create(text(base),text(local),text(remote),&m)==BC_OK&&bc_vault_merge_pending(m)==1);
    assert(bc_vault_merge_resolve(m,0,BC_VAULT_MERGE_LOCAL)==BC_OK);out=result(m);
    assert(strstr(out,"\"deleted\":true")&&strstr(out,"\"fields\":{}")&&!strstr(out,"remote.invalid"));
    free(out);bc_vault_merge_destroy(m);m=NULL;
    snapshot(local,"{\"name\":\"one\",\"name\":\"two\"}",100,0);
    assert(bc_vault_merge_create(text(base),text(local),text(remote),&m)==BC_PROTOCOL_ERROR&&!m);
    snapshot(local,"{}",200,0);char *id=strstr(local,"00112233");assert(id);id[0]='1';
    assert(bc_vault_merge_create(text(base),text(local),text(remote),&m)==BC_INVALID_ARGUMENT&&!m);
    const char *patch="{\"device-1\":{\"fields\":{\"name\":\"patched\"},\"deleted\":false,\"modified_at_ms\":101},"
        "\"device-2\":{\"fields\":{\"name\":\"added\"},\"deleted\":false,\"modified_at_ms\":102}}";
    assert(bc_vault_records_patch(text(base),text(patch),&m)==BC_OK);out=result(m);
    assert(strstr(out,"\"name\":\"patched\"")&&strstr(out,"old.invalid")&&strstr(out,"device-2"));
    free(out);bc_vault_merge_destroy(m);m=NULL;
    assert(bc_vault_record_patch(text(base),(bc_string){"device-1",8},text("{}"),1,103,&m)==BC_OK);out=result(m);
    assert(strstr(out,"\"deleted\":true")&&!strstr(out,"old.invalid"));
    free(out);bc_vault_merge_destroy(m);
    return 0;
}

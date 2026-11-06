#include "bcontrol/vault_merge.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bc_bytes bytes(const void *data,size_t size){return(bc_bytes){data,size};}
static bc_string text(const char *data){return(bc_string){data,strlen(data)};}
static uint8_t *exported(bc_vault *v,uint32_t *size){
    assert(bc_vault_export(v,NULL,0,size)==BC_LIMIT_EXCEEDED);uint8_t *out=malloc(*size);assert(out);
    assert(bc_vault_export(v,out,*size,size)==BC_OK);return out;
}
static uint8_t *resolved(bc_vault_conflict *c,uint32_t *size){
    assert(bc_vault_conflict_export(c,NULL,0,size)==BC_LIMIT_EXCEEDED);uint8_t *out=malloc(*size);assert(out);
    assert(bc_vault_conflict_export(c,out,*size,size)==BC_OK);return out;
}
static void data(char *out,const char *id,const char *secret){
    int size=snprintf(out,512,"{\"version\":1,\"vault_id\":\"%s\",\"records\":{\"credential:fixture\":{\"fields\":{\"credential\":\"%s\"},\"deleted\":false,\"modified_at_ms\":0}}}",id,secret);
    assert(size>0&&size<512);
}
int main(void){
    bc_vault *base=NULL,*local=NULL,*remote=NULL,*opened=NULL;uint8_t key[32];
    assert(bc_vault_create(bytes(NULL,0),text("fixture password"),&base)==BC_OK);
    bc_vault_info info={0};info.struct_size=sizeof(info);assert(bc_vault_info_get(base,&info)==BC_OK);
    char id[33],plain[512];static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<16;++i){id[i*2]=hex[info.vault_id[i]>>4];id[i*2+1]=hex[info.vault_id[i]&15];}id[32]=0;
    data(plain,id,"base-secret");assert(bc_vault_replace(base,bytes(plain,strlen(plain)))==BC_OK);
    uint32_t base_size,local_size,remote_size,size;uint8_t *a=exported(base,&base_size);
    assert(bc_vault_key_copy(base,key,32)==BC_OK);
    assert(bc_vault_open_key(bytes(a,base_size),bytes(key,32),&local)==BC_OK);
    assert(bc_vault_open_key(bytes(a,base_size),bytes(key,32),&remote)==BC_OK);
    data(plain,id,"local-secret");assert(bc_vault_replace(local,bytes(plain,strlen(plain)))==BC_OK);
    data(plain,id,"remote-secret");assert(bc_vault_replace(remote,bytes(plain,strlen(plain)))==BC_OK);
    uint8_t *b=exported(local,&local_size),*c=exported(remote,&remote_size);bc_vault_conflict *review=NULL;
    assert(bc_vault_conflict_create(bytes(a,base_size),bytes(b,local_size),bytes(c,remote_size),bytes(key,32),&review)==BC_OK);
    assert(bc_vault_conflict_fields(review)&&bc_vault_conflict_count(review)==1);
    bc_bytes field;assert(bc_vault_conflict_field(review,0,&field)==BC_OK);
    char *view=calloc((size_t)field.length+1,1);assert(view);memcpy(view,field.data,(size_t)field.length);
    assert(!strstr(view,"base-secret")&&!strstr(view,"local-secret")&&!strstr(view,"remote-secret")&&strstr(view,"\"kind\":2"));free(view);
    assert(bc_vault_conflict_export(review,NULL,0,&size)==BC_CONFIRMATION_REQUIRED);
    assert(bc_vault_conflict_resolve(review,0,BC_VAULT_MERGE_BASE)==BC_INVALID_ARGUMENT);
    assert(bc_vault_conflict_resolve(review,0,BC_VAULT_MERGE_LOCAL)==BC_OK);
    uint8_t *output=resolved(review,&size);
    assert(bc_vault_open_key(bytes(output,size),bytes(key,32),&opened)==BC_OK);
    data(plain,id,"local-secret");bc_bytes value=bc_vault_data(opened);assert(value.length==strlen(plain));
    assert(!memcmp(value.data,plain,(size_t)value.length));bc_vault_destroy(opened);opened=NULL;free(output);bc_vault_conflict_destroy(review);
    assert(bc_vault_change_password(local,text("new fixture password"))==BC_OK);free(b);b=exported(local,&local_size);
    assert(bc_vault_conflict_create(bytes(a,base_size),bytes(b,local_size),bytes(c,remote_size),bytes(key,32),&review)==BC_OK);
    assert(!bc_vault_conflict_fields(review)&&bc_vault_conflict_count(review)==0);
    assert(bc_vault_conflict_select(review,BC_VAULT_MERGE_LOCAL)==BC_OK);output=resolved(review,&size);
    assert(bc_vault_open_password(bytes(output,size),text("fixture password"),&opened)==BC_AUTHENTICATION_FAILED&&!opened);
    assert(bc_vault_open_password(bytes(output,size),text("new fixture password"),&opened)==BC_OK);
    bc_vault_info result={0},parent={0};result.struct_size=parent.struct_size=sizeof(result);
    assert(bc_vault_info_get(opened,&result)==BC_OK&&bc_vault_info_get(remote,&parent)==BC_OK);
    assert(!memcmp(result.parent_revision,parent.revision,16));
    bc_vault_destroy(opened);bc_vault_conflict_destroy(review);bc_vault_destroy(base);bc_vault_destroy(local);bc_vault_destroy(remote);
    memset(key,0,sizeof(key));free(a);free(b);free(c);free(output);return 0;
}

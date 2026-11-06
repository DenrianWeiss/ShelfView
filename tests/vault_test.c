#include "bcontrol/vault.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static bc_string text(const char *s) { return (bc_string){s,strlen(s)}; }
static bc_bytes bytes(const void *p, size_t size) { return (bc_bytes){p,size}; }
static uint8_t *export_file(bc_vault *v, uint32_t *size) {
    assert(bc_vault_export(v,NULL,0,size)==BC_LIMIT_EXCEEDED);
    uint8_t *out=malloc(*size);assert(out);
    assert(bc_vault_export(v,out,*size,size)==BC_OK);return out;
}
int main(void) {
    const char *payload="{\"records\":[{\"address\":\"fixture.invalid\",\"password\":\"fixture-secret\"}]}";
    bc_vault *v=NULL,*opened=NULL;
    assert(bc_vault_create(bytes(payload,strlen(payload)),text("master fixture one"),&v)==BC_OK);
    uint32_t size=0;uint8_t *file=export_file(v,&size),key[32];
    assert(size>strlen(payload));assert(bc_vault_key_copy(v,key,sizeof(key))==BC_OK);
    assert(bc_vault_open_key(bytes(file,size),bytes(key,32),&opened)==BC_OK);
    bc_bytes plain=bc_vault_data(opened);assert(plain.length==strlen(payload)&&!memcmp(plain.data,payload,(size_t)plain.length));
    bc_vault_destroy(opened);opened=NULL;
    assert(bc_vault_open_password(bytes(file,size),text("master fixture one"),&opened)==BC_OK);
    bc_vault_destroy(opened);opened=NULL;
    assert(bc_vault_open_password(bytes(file,size),text("wrong master"),&opened)==BC_AUTHENTICATION_FAILED&&!opened);
    key[0]^=1;assert(bc_vault_open_key(bytes(file,size),bytes(key,32),&opened)==BC_AUTHENTICATION_FAILED&&!opened);key[0]^=1;
    for(uint32_t i=0;i<size;++i){
        file[i]^=1;
        assert(bc_vault_open_key(bytes(file,size),bytes(key,32),&opened)!=BC_OK&&!opened);
        file[i]^=1;
    }
    file[80]=31;
    assert(bc_vault_open_password(bytes(file,size),text("master fixture one"),&opened)==BC_LIMIT_EXCEEDED&&!opened);
    file[80]=17;
    bc_vault_info before={0},after={0};before.struct_size=after.struct_size=sizeof(before);
    assert(bc_vault_info_get(v,&before)==BC_OK);
    assert(bc_vault_file_info(bytes(file,size),&after)==BC_OK);
    assert(!memcmp(before.vault_id,after.vault_id,16)&&after.data_size==strlen(payload));
    assert(bc_vault_change_password(v,text("master fixture two"))==BC_OK);
    uint32_t updated_size=0;uint8_t *updated=export_file(v,&updated_size);
    assert(updated_size==size);
    assert(!memcmp(file+size-strlen(payload),updated+updated_size-strlen(payload),strlen(payload)));
    assert(bc_vault_open_password(bytes(updated,updated_size),text("master fixture one"),&opened)==BC_AUTHENTICATION_FAILED&&!opened);
    assert(bc_vault_open_password(bytes(updated,updated_size),text("master fixture two"),&opened)==BC_OK);
    bc_vault_destroy(opened);opened=NULL;
    assert(bc_vault_open_key(bytes(updated,updated_size),bytes(key,32),&opened)==BC_OK);
    bc_vault_destroy(opened);opened=NULL;
    int direct=1;
    assert(bc_vault_file_direct_child(bytes(file,size),bytes(updated,updated_size),bytes(key,32),&direct)==BC_OK&&!direct);
    assert(bc_vault_replace(v,bytes("new data",8))==BC_OK);
    assert(bc_vault_info_get(v,&after)==BC_OK);
    assert(!memcmp(before.vault_id,after.vault_id,16)&&!memcmp(before.key_id,after.key_id,16));
    assert(memcmp(before.revision,after.revision,16)&&!memcmp(before.revision,after.parent_revision,16));
    uint32_t parent_size=updated_size;uint8_t *parent=updated;updated=export_file(v,&updated_size);
    assert(bc_vault_file_direct_child(bytes(parent,parent_size),bytes(updated,updated_size),bytes(key,32),&direct)==BC_OK&&direct);
    assert(bc_vault_file_direct_child(bytes(file,size),bytes(updated,updated_size),bytes(key,32),&direct)==BC_OK&&!direct);
    assert(bc_vault_file_direct_child(bytes(updated,updated_size),bytes(parent,parent_size),bytes(key,32),&direct)==BC_OK&&!direct);
    assert(bc_vault_file_direct_child(bytes(parent,parent_size),bytes(parent,parent_size),bytes(key,32),&direct)==BC_OK&&!direct);
    updated[updated_size-1]^=1;
    assert(bc_vault_file_direct_child(bytes(parent,parent_size),bytes(updated,updated_size),bytes(key,32),&direct)==BC_AUTHENTICATION_FAILED&&!direct);
    updated[updated_size-1]^=1;
    assert(bc_vault_open_key(bytes(updated,updated_size),bytes(key,32),&opened)==BC_OK);
    assert(bc_vault_data(opened).length==8&&!memcmp(bc_vault_data(opened).data,"new data",8));
    assert(bc_vault_replace(v,bytes("third data",10))==BC_OK);
    uint32_t third_size=0;uint8_t *third=export_file(v,&third_size);
    assert(bc_vault_file_direct_child(bytes(updated,updated_size),bytes(third,third_size),bytes(key,32),&direct)==BC_OK&&direct);
    assert(bc_vault_file_direct_child(bytes(parent,parent_size),bytes(third,third_size),bytes(key,32),&direct)==BC_OK&&!direct);
    free(parent);free(third);
    bc_vault_destroy(opened);bc_vault_destroy(v);free(file);free(updated);
    assert(bc_vault_create(bytes(NULL,0),text("empty fixture"),&v)==BC_OK);
    file=export_file(v,&size);
    assert(bc_vault_open_password(bytes(file,size),text("empty fixture"),&opened)==BC_OK);
    assert(bc_vault_data(opened).length==0);
    bc_vault_destroy(opened);bc_vault_destroy(v);free(file);
    assert(bc_vault_create(bytes(NULL,1),text("invalid"),&v)==BC_INVALID_ARGUMENT&&!v);
    assert(bc_vault_create(bytes("",0),text(""),&v)==BC_INVALID_ARGUMENT&&!v);
    return 0;
}

#include "bcontrol/vault_merge.h"
#include "vault_internal.h"
#include "yyjson.h"
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

struct bc_vault_conflict {
    bc_vault *base,*local,*current;
    bc_vault_merge *merge;
    int fields,prepared;
    uint32_t choice;
    char *cached;
    size_t cached_size;
};
static bc_status valid_document(bc_vault *v,bc_vault_info *info) {
    info->struct_size=sizeof(*info);bc_status status=bc_vault_info_get(v,info);if(status!=BC_OK)return status;
    bc_bytes bytes=bc_vault_data(v);bc_vault_merge *check=NULL;
    status=bc_vault_merge_create(bytes,bytes,bytes,&check);bc_vault_merge_destroy(check);if(status!=BC_OK)return status;
    yyjson_doc *doc=yyjson_read((const char *)bytes.data,(size_t)bytes.length,0);if(!doc)return BC_NO_MEMORY;
    yyjson_val *id=yyjson_obj_get(yyjson_doc_get_root(doc),"vault_id");char hex[33];static const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<16;++i){hex[i*2]=digits[info->vault_id[i]>>4];hex[i*2+1]=digits[info->vault_id[i]&15];}hex[32]=0;
    int matches=yyjson_is_str(id)&&yyjson_get_len(id)==32&&!memcmp(yyjson_get_str(id),hex,32);
    yyjson_doc_free(doc);return matches?BC_OK:BC_PROTOCOL_ERROR;
}
bc_status bc_vault_conflict_create(bc_bytes base,bc_bytes local,bc_bytes current,bc_bytes key,bc_vault_conflict **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;bc_vault_conflict *c=calloc(1,sizeof(*c));if(!c)return BC_NO_MEMORY;
    bc_status status=bc_vault_open_key(base,key,&c->base);
    if(status==BC_OK)status=bc_vault_open_key(local,key,&c->local);
    if(status==BC_OK)status=bc_vault_open_key(current,key,&c->current);
    bc_vault *versions[]={c->base,c->local,c->current};bc_vault_info first={0};
    for(unsigned i=0;status==BC_OK&&i<3;++i){bc_vault_info info={0};status=valid_document(versions[i],&info);
        if(i==0)first=info;
        else if(status==BC_OK&&(memcmp(first.vault_id,info.vault_id,16)||memcmp(first.key_id,info.key_id,16)))status=BC_INVALID_ARGUMENT;
    }
    if(status==BC_OK){c->fields=vault_direct_child(c->base,c->local)&&vault_direct_child(c->base,c->current);
        if(c->fields)status=bc_vault_merge_create(bc_vault_data(c->base),bc_vault_data(c->local),bc_vault_data(c->current),&c->merge);
    }
    if(status!=BC_OK){bc_vault_conflict_destroy(c);return status;}
    *out=c;return BC_OK;
}
int bc_vault_conflict_fields(const bc_vault_conflict *c){return c&&c->fields;}
uint32_t bc_vault_conflict_count(const bc_vault_conflict *c){return c&&c->fields?bc_vault_merge_conflicts(c->merge):0;}
static int contains(const char *text,const char *needle) {
    size_t length=strlen(needle);
    for(;*text;++text){size_t i=0;for(;i<length&&text[i];++i){unsigned char ch=(unsigned char)text[i];if(ch>='A'&&ch<='Z')ch+=32;if(ch!=(unsigned char)needle[i])break;}if(i==length)return 1;}
    return 0;
}
static int secret(const char *record,const char *field) {
    return !strncmp(record,"credential:",11)||contains(field,"password")||contains(field,"passwd")||contains(field,"pwd")||
        contains(field,"passphrase")||contains(field,"passcode")||contains(field,"authorization")||contains(field,"credential")||contains(field,"secret")||contains(field,"token")||contains(field,"cookie")||contains(field,"privatekey")||contains(field,"sessionkey");
}
static yyjson_mut_val *preview(yyjson_mut_doc *doc,yyjson_val *variant,int hidden,int record) {
    yyjson_val *value=yyjson_obj_get(variant,"value");uint32_t kind=0;const char *text="";char *rendered=NULL;
    if(yyjson_is_true(yyjson_obj_get(variant,"present"))){
        if(hidden)kind=2;
        else if(record)kind=yyjson_is_true(yyjson_obj_get(value,"deleted"))?4:3;
        else if(yyjson_is_str(value)){kind=1;text=yyjson_get_str(value);}
        else if(yyjson_is_obj(value)||yyjson_is_arr(value))kind=3;
        else {kind=1;rendered=yyjson_val_write(value,0,NULL);if(!rendered)return NULL;text=rendered;}
    }
    yyjson_mut_val *out=yyjson_mut_obj(doc);
    size_t length=strlen(text);if(length>256){length=256;while(length&&((unsigned char)text[length]&0xc0)==0x80)--length;}
    int ok=out&&yyjson_mut_obj_add_uint(doc,out,"kind",kind)&&yyjson_mut_obj_add_strncpy(doc,out,"text",text,length);
    free(rendered);return ok?out:NULL;
}
bc_status bc_vault_conflict_field(bc_vault_conflict *c,uint32_t index,bc_bytes *out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=(bc_bytes){0};if(!c||!c->fields||c->prepared)return BC_INVALID_ARGUMENT;
    bc_bytes raw;bc_status status=bc_vault_merge_conflict(c->merge,index,&raw);if(status!=BC_OK)return status;
    yyjson_doc *input=yyjson_read((const char *)raw.data,(size_t)raw.length,0);if(!input)return BC_NO_MEMORY;
    yyjson_val *root=yyjson_doc_get_root(input);const char *record=yyjson_get_str(yyjson_obj_get(root,"record")),*field=yyjson_get_str(yyjson_obj_get(root,"field"));
    yyjson_mut_doc *doc=yyjson_mut_doc_new(NULL);yyjson_mut_val *object=doc?yyjson_mut_obj(doc):NULL;
    int ok=object&&yyjson_mut_obj_add_strcpy(doc,object,"record",record)&&yyjson_mut_obj_add_strcpy(doc,object,"field",field);
    const char *names[]={"base","local","remote"};
    for(unsigned i=0;ok&&i<3;++i){yyjson_mut_val *value=preview(doc,yyjson_obj_get(root,names[i]),secret(record,field),!field[0]);ok=value&&yyjson_mut_obj_add_val(doc,object,names[i],value);}
    free(c->cached);c->cached=NULL;c->cached_size=0;
    if(ok){yyjson_mut_doc_set_root(doc,object);c->cached=yyjson_mut_write(doc,0,&c->cached_size);}
    if(doc)yyjson_mut_doc_free(doc);
    yyjson_doc_free(input);if(!c->cached)return BC_NO_MEMORY;
    *out=(bc_bytes){(const uint8_t *)c->cached,c->cached_size};return BC_OK;
}
bc_status bc_vault_conflict_resolve(bc_vault_conflict *c,uint32_t index,uint32_t choice) {
    if(!c||!c->fields||c->prepared||(choice!=BC_VAULT_MERGE_LOCAL&&choice!=BC_VAULT_MERGE_REMOTE))return BC_INVALID_ARGUMENT;
    return bc_vault_merge_resolve(c->merge,index,choice);
}
bc_status bc_vault_conflict_select(bc_vault_conflict *c,uint32_t choice) {
    if(!c||c->fields||c->prepared||(choice!=BC_VAULT_MERGE_LOCAL&&choice!=BC_VAULT_MERGE_REMOTE))return BC_INVALID_ARGUMENT;
    c->choice=choice;return BC_OK;
}
bc_status bc_vault_conflict_export(bc_vault_conflict *c,uint8_t *output,uint32_t capacity,uint32_t *written) {
    if(!written)return BC_INVALID_ARGUMENT;
    *written=0;
    if(!c)return BC_INVALID_ARGUMENT;
    if(!c->prepared){bc_status status=BC_OK;
        if(c->fields){uint32_t size=0;status=bc_vault_merge_export(c->merge,NULL,0,&size);if(status!=BC_LIMIT_EXCEEDED)return status;
            uint8_t *plain=malloc(size?size:1);if(!plain)return BC_NO_MEMORY;
            status=bc_vault_merge_export(c->merge,plain,size,&size);
            if(status==BC_OK)status=bc_vault_replace(c->current,(bc_bytes){plain,size});
            OPENSSL_cleanse(plain,size);free(plain);
        }else if(c->choice==BC_VAULT_MERGE_LOCAL)status=vault_replace_selected(c->current,c->local);
        else if(c->choice!=BC_VAULT_MERGE_REMOTE)return BC_CONFIRMATION_REQUIRED;
        if(status!=BC_OK)return status;
        c->prepared=1;
    }
    return bc_vault_export(c->current,output,capacity,written);
}
void bc_vault_conflict_destroy(bc_vault_conflict *c) {
    if(!c)return;
    bc_vault_destroy(c->base);bc_vault_destroy(c->local);bc_vault_destroy(c->current);bc_vault_merge_destroy(c->merge);free(c->cached);OPENSSL_cleanse(c,sizeof(*c));free(c);
}

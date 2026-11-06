#include "bcontrol/vault_merge.h"
#include "media_internal.h"
#include "yyjson.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#define MEMORY_LIMIT (256u*1024u*1024u)
#define INPUT_LIMIT (16u*1024u*1024u)
#define RECORD_LIMIT 8192u
#define FIELD_LIMIT 128u
typedef struct {size_t used;int limited;} budget;
#ifdef _MSC_VER
typedef union {long double align;void *pointer;uint64_t integer;size_t size;} allocation;
#else
typedef union {max_align_t align;size_t size;} allocation;
#endif
static void *allocate(void *user,size_t size) {
    budget *b=user;if(size>MEMORY_LIMIT-b->used){b->limited=1;return NULL;}
    allocation *p=malloc(sizeof(*p)+size);if(!p)return NULL;p->size=size;b->used+=size;return p+1;
}
static void release(void *user,void *ptr) {
    if(!ptr)return;
    allocation *p=(allocation *)ptr-1;((budget *)user)->used-=p->size;OPENSSL_cleanse(ptr,p->size);free(p);
}
static void *resize(void *user,void *ptr,size_t old,size_t size) {
    (void)old;if(!size){release(user,ptr);return NULL;}
    void *result=allocate(user,size);if(!result)return NULL;
    if(ptr){size_t length=((allocation *)ptr-1)->size;memcpy(result,ptr,length<size?length:size);release(user,ptr);}return result;
}
typedef struct {
    const char *record,*field;
    yyjson_val *values[3];
    yyjson_mut_val *target;
    uint64_t timestamp;
    int resolved;
} conflict;
struct bc_vault_merge {
    budget memory;yyjson_alc allocator;
    yyjson_doc *inputs[3];yyjson_mut_doc *output;
    yyjson_mut_val *records;
    conflict *conflicts;uint32_t count,capacity,pending;
    char *cached;size_t cached_size;
};
typedef struct {const char *name;size_t length;unsigned side;yyjson_val *value;} entry;
static int compare(const void *left,const void *right) {
    const entry *a=left,*b=right;size_t n=a->length<b->length?a->length:b->length;
    int result=memcmp(a->name,b->name,n);if(result)return result;
    if(a->length!=b->length)return a->length<b->length?-1:1;
    return a->side<b->side?-1:a->side>b->side?1:0;
}
static int equal(yyjson_val *a,yyjson_val *b) {return (!a||!b)?a==b:yyjson_equals(a,b);}
static int valid_tree(yyjson_val *value,unsigned depth) {
    if(depth>32)return 0;
    if(yyjson_is_obj(value)){
        if(yyjson_obj_size(value)>(depth==1?RECORD_LIMIT:FIELD_LIMIT))return 0;
        size_t i,n;yyjson_val *key,*child;
        yyjson_obj_foreach(value,i,n,key,child){
            const char *name=yyjson_get_str(key);size_t length=yyjson_get_len(key);
            if(!length||length>128||strlen(name)!=length||yyjson_obj_get(value,name)!=child||!valid_tree(child,depth+1))return 0;
        }
    }else if(yyjson_is_arr(value)){
        if(yyjson_arr_size(value)>RECORD_LIMIT)return 0;
        size_t i,n;yyjson_val *child;yyjson_arr_foreach(value,i,n,child)if(!valid_tree(child,depth+1))return 0;
    }
    return 1;
}
static int valid_id(yyjson_val *value) {
    const char *id=yyjson_get_str(value);if(!id||yyjson_get_len(value)!=32)return 0;
    for(unsigned i=0;i<32;++i)if(!((id[i]>='0'&&id[i]<='9')||(id[i]>='a'&&id[i]<='f')))return 0;
    return 1;
}
static int validate(yyjson_val *root) {
    if(!yyjson_is_obj(root)||yyjson_obj_size(root)!=3||!valid_tree(root,0))return 0;
    yyjson_val *version=yyjson_obj_get(root,"version"),*records=yyjson_obj_get(root,"records");
    if(!yyjson_is_uint(version)||yyjson_get_uint(version)!=1||!valid_id(yyjson_obj_get(root,"vault_id"))||
        !yyjson_is_obj(records)||yyjson_obj_size(records)>RECORD_LIMIT)return 0;
    size_t i,n;yyjson_val *key,*record;
    yyjson_obj_foreach(records,i,n,key,record){
        (void)key;yyjson_val *fields=yyjson_obj_get(record,"fields"),*time=yyjson_obj_get(record,"modified_at_ms");
        if(!yyjson_is_obj(record)||yyjson_obj_size(record)!=3||!yyjson_is_obj(fields)||yyjson_obj_size(fields)>FIELD_LIMIT||
            !yyjson_is_bool(yyjson_obj_get(record,"deleted"))||!yyjson_is_uint(time)||yyjson_get_uint(time)>253402300799999ull)return 0;
    }
    return 1;
}
static bc_status names(bc_vault_merge *m,yyjson_val *objects[3],uint32_t limit,entry **out,size_t *count) {
    size_t total=0;for(unsigned side=0;side<3;++side){size_t n=yyjson_obj_size(objects[side]);if(n>limit)return BC_LIMIT_EXCEEDED;total+=n;}
    entry *items=allocate(&m->memory,(total?total:1)*sizeof(*items));if(!items)return m->memory.limited?BC_LIMIT_EXCEEDED:BC_NO_MEMORY;
    size_t at=0;
    for(unsigned side=0;side<3;++side){
        size_t i,n;yyjson_val *key,*value;
        yyjson_obj_foreach(objects[side],i,n,key,value)items[at++]=(entry){yyjson_get_str(key),yyjson_get_len(key),side,value};
    }
    qsort(items,total,sizeof(*items),compare);*out=items;*count=total;return BC_OK;
}
static size_t group(entry *items,size_t at,size_t count,yyjson_val *values[3]) {
    memset(values,0,3*sizeof(*values));size_t next=at;
    while(next<count&&items[next].length==items[at].length&&!memcmp(items[next].name,items[at].name,items[at].length)){
        values[items[next].side]=items[next].value;++next;
    }
    return next;
}
static int deleted(yyjson_val *record){return !record||yyjson_get_bool(yyjson_obj_get(record,"deleted"));}
static yyjson_val *fields(yyjson_val *record){return record?yyjson_obj_get(record,"fields"):NULL;}
static int same_record(yyjson_val *a,yyjson_val *b) {
    if(!a||!b)return a==b;
    if(deleted(a)||deleted(b))return deleted(a)==deleted(b);
    return equal(fields(a),fields(b));
}
static uint64_t latest(yyjson_val *records[3]) {
    uint64_t result=0;for(unsigned i=0;i<3;++i){uint64_t value=yyjson_get_uint(yyjson_obj_get(records[i],"modified_at_ms"));if(value>result)result=value;}return result;
}
static yyjson_mut_val *record_copy(bc_vault_merge *m,yyjson_val *record,uint64_t timestamp) {
    yyjson_mut_doc *doc=m->output;yyjson_mut_val *result=yyjson_mut_obj(doc);
    yyjson_mut_val *value=!deleted(record)?yyjson_val_mut_copy(doc,fields(record)):yyjson_mut_obj(doc);
    if(!result||!value||!yyjson_mut_obj_add_val(doc,result,"fields",value)||
        !yyjson_mut_obj_add_bool(doc,result,"deleted",deleted(record))||
        !yyjson_mut_obj_add_uint(doc,result,"modified_at_ms",timestamp))return NULL;
    return result;
}
static int put(bc_vault_merge *m,yyjson_mut_val *target,const char *name,yyjson_mut_val *value) {
    yyjson_mut_val *key=yyjson_mut_strcpy(m->output,name);return key&&value&&yyjson_mut_obj_put(target,key,value);
}
static bc_status add_conflict(bc_vault_merge *m,const char *record,const char *field,
    yyjson_val *values[3],yyjson_mut_val *target,uint64_t timestamp) {
    if(m->count==65536)return BC_LIMIT_EXCEEDED;
    if(m->count==m->capacity){
        uint32_t capacity=m->capacity?m->capacity*2:16;
        conflict *grown=resize(&m->memory,m->conflicts,0,capacity*sizeof(*grown));
        if(!grown)return m->memory.limited?BC_LIMIT_EXCEEDED:BC_NO_MEMORY;
        m->conflicts=grown;m->capacity=capacity;
    }
    conflict *c=&m->conflicts[m->count++];memset(c,0,sizeof(*c));
    c->record=record;c->field=field;c->target=target;c->timestamp=timestamp;memcpy(c->values,values,sizeof(c->values));++m->pending;return BC_OK;
}
static bc_status merge_fields(bc_vault_merge *m,const char *id,yyjson_val *records[3],uint64_t timestamp) {
    yyjson_mut_val *record=record_copy(m,records[1],timestamp);if(!record)return BC_NO_MEMORY;
    yyjson_mut_val *target=yyjson_mut_obj(m->output);if(!target||!put(m,record,"fields",target)||!put(m,m->records,id,record))return BC_NO_MEMORY;
    yyjson_val *objects[3]={fields(records[0]),fields(records[1]),fields(records[2])};
    if(deleted(records[0]))objects[0]=NULL;
    entry *items=NULL;size_t count=0;bc_status status=names(m,objects,FIELD_LIMIT,&items,&count);if(status!=BC_OK)return status;
    for(size_t at=0;at<count&&status==BC_OK;){
        yyjson_val *values[3];size_t next=group(items,at,count,values);yyjson_val *chosen=NULL;int conflict_found=0;
        if(equal(values[1],values[2]))chosen=values[1];
        else if(equal(values[1],values[0]))chosen=values[2];
        else if(equal(values[2],values[0]))chosen=values[1];
        else conflict_found=1;
        if(conflict_found)status=add_conflict(m,id,items[at].name,values,target,timestamp);
        else if(chosen&&!put(m,target,items[at].name,yyjson_val_mut_copy(m->output,chosen)))status=BC_NO_MEMORY;
        at=next;
    }
    if(status==BC_OK&&yyjson_mut_obj_size(target)>FIELD_LIMIT)status=BC_LIMIT_EXCEEDED;
    release(&m->memory,items);return status;
}
bc_status bc_vault_merge_create(bc_bytes base,bc_bytes local,bc_bytes remote,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;bc_bytes input[3]={base,local,remote};
    bc_vault_merge *m=calloc(1,sizeof(*m));if(!m)return BC_NO_MEMORY;
    m->allocator=(yyjson_alc){allocate,resize,release,&m->memory};bc_status status=BC_OK;
    for(unsigned i=0;i<3;++i){
        if(!input[i].data||!input[i].length||input[i].length>INPUT_LIMIT){status=BC_LIMIT_EXCEEDED;break;}
        m->inputs[i]=yyjson_read_opts((char *)(void *)input[i].data,(size_t)input[i].length,0,&m->allocator,NULL);
        if(!m->inputs[i]||!validate(yyjson_doc_get_root(m->inputs[i]))){status=BC_PROTOCOL_ERROR;break;}
    }
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    yyjson_val *roots[3];for(unsigned i=0;i<3;++i)roots[i]=yyjson_doc_get_root(m->inputs[i]);
    yyjson_val *id=yyjson_obj_get(roots[0],"vault_id");
    if(!equal(id,yyjson_obj_get(roots[1],"vault_id"))||!equal(id,yyjson_obj_get(roots[2],"vault_id"))){bc_vault_merge_destroy(m);return BC_INVALID_ARGUMENT;}
    m->output=yyjson_mut_doc_new(&m->allocator);
    yyjson_mut_val *root=m->output?yyjson_mut_obj(m->output):NULL;m->records=m->output?yyjson_mut_obj(m->output):NULL;
    if(!root||!m->records||!yyjson_mut_obj_add_uint(m->output,root,"version",1)||
        !yyjson_mut_obj_add_val(m->output,root,"vault_id",yyjson_val_mut_copy(m->output,id))||
        !yyjson_mut_obj_add_val(m->output,root,"records",m->records)){bc_vault_merge_destroy(m);return BC_NO_MEMORY;}
    yyjson_mut_doc_set_root(m->output,root);
    yyjson_val *objects[3];for(unsigned i=0;i<3;++i)objects[i]=yyjson_obj_get(roots[i],"records");
    entry *items=NULL;size_t count=0;status=names(m,objects,RECORD_LIMIT,&items,&count);
    for(size_t at=0;at<count&&status==BC_OK;){
        yyjson_val *values[3],*chosen=NULL;size_t next=group(items,at,count,values);uint64_t timestamp=latest(values);int conflict_found=0;
        if((deleted(values[1])&&deleted(values[2]))||same_record(values[1],values[2]))chosen=values[1]?values[1]:values[2];
        else if(same_record(values[1],values[0]))chosen=values[2];
        else if(same_record(values[2],values[0]))chosen=values[1];
        else if(!deleted(values[1])&&!deleted(values[2])){status=merge_fields(m,items[at].name,values,timestamp);at=next;continue;}
        else conflict_found=1;
        yyjson_mut_val *record=record_copy(m,chosen,timestamp);
        if(!record||!put(m,m->records,items[at].name,record))status=BC_NO_MEMORY;
        if(status==BC_OK&&conflict_found)status=add_conflict(m,items[at].name,NULL,values,m->records,timestamp);
        at=next;
    }
    release(&m->memory,items);
    if(status==BC_OK&&yyjson_mut_obj_size(m->records)>RECORD_LIMIT)status=BC_LIMIT_EXCEEDED;
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    *out=m;return BC_OK;
}
static int record_name_valid(const char *name,size_t size) {
    if(!name||!size||size>128||memchr(name,0,size))return 0;
    for(size_t i=0;i<size;++i)if((unsigned char)name[i]<33||(unsigned char)name[i]>126)return 0;
    return 1;
}
static bc_status patch_apply(bc_vault_merge *m,yyjson_val *root,const char *name,yyjson_val *updates,int remove_record,uint64_t timestamp) {
    yyjson_val *previous=yyjson_obj_get(yyjson_obj_get(root,"records"),name);
    if(!previous&&yyjson_mut_obj_size(m->records)>=RECORD_LIMIT){return BC_LIMIT_EXCEEDED;}
    yyjson_mut_val *record=record_copy(m,previous,yyjson_get_uint(yyjson_obj_get(previous,"modified_at_ms")));
    if(!record||!put(m,m->records,name,record)||!put(m,record,"deleted",yyjson_mut_bool(m->output,remove_record!=0))){return BC_NO_MEMORY;}
    yyjson_mut_val *target=yyjson_mut_obj_get(record,"fields");
    int changed=!previous||deleted(previous)!=(remove_record!=0);
    if(remove_record){
        if(!put(m,record,"fields",yyjson_mut_obj(m->output))){return BC_NO_MEMORY;}
    }else{
        size_t i,n;yyjson_val *key,*value;
        yyjson_obj_foreach(updates,i,n,key,value){
            const char *field=yyjson_get_str(key);
            if(!equal(value,yyjson_obj_get(fields(previous),field)))changed=1;
            if(!put(m,target,field,yyjson_val_mut_copy(m->output,value))){return BC_NO_MEMORY;}
        }
        if(yyjson_mut_obj_size(target)>FIELD_LIMIT){return BC_LIMIT_EXCEEDED;}
    }
    uint64_t before=yyjson_get_uint(yyjson_obj_get(previous,"modified_at_ms"));
    if(changed&&!put(m,record,"modified_at_ms",yyjson_mut_uint(m->output,timestamp>before?timestamp:before))){return BC_NO_MEMORY;}
    return BC_OK;
}
static bc_status snapshot_open(bc_bytes snapshot,bc_vault_merge **out) {
    if(!snapshot.data||!snapshot.length||snapshot.length>INPUT_LIMIT)return BC_LIMIT_EXCEEDED;
    bc_vault_merge *m=calloc(1,sizeof(*m));if(!m)return BC_NO_MEMORY;
    m->allocator=(yyjson_alc){allocate,resize,release,&m->memory};
    m->inputs[0]=yyjson_read_opts((char *)(void *)snapshot.data,(size_t)snapshot.length,0,&m->allocator,NULL);
    if(!m->inputs[0]||!validate(yyjson_doc_get_root(m->inputs[0]))){
        bc_status status=m->memory.limited?BC_LIMIT_EXCEEDED:BC_PROTOCOL_ERROR;bc_vault_merge_destroy(m);return status;
    }
    *out=m;return BC_OK;
}
static bc_status patch_open(bc_bytes snapshot,bc_bytes patch,uint32_t limit,unsigned depth,bc_vault_merge **out) {
    if(!patch.data||!patch.length||patch.length>INPUT_LIMIT)return BC_LIMIT_EXCEEDED;
    bc_vault_merge *m=NULL;bc_status opened=snapshot_open(snapshot,&m);if(opened!=BC_OK)return opened;
    m->inputs[1]=yyjson_read_opts((char *)(void *)patch.data,(size_t)patch.length,0,&m->allocator,NULL);
    yyjson_val *updates=yyjson_doc_get_root(m->inputs[1]);
    if(!yyjson_is_obj(updates)||yyjson_obj_size(updates)>limit||!valid_tree(updates,depth)){
        bc_status status=m->memory.limited?BC_LIMIT_EXCEEDED:BC_PROTOCOL_ERROR;bc_vault_merge_destroy(m);return status;
    }
    m->output=yyjson_doc_mut_copy(m->inputs[0],&m->allocator);
    if(!m->output){bc_vault_merge_destroy(m);return BC_NO_MEMORY;}
    m->records=yyjson_mut_obj_get(yyjson_mut_doc_get_root(m->output),"records");*out=m;return BC_OK;
}
static bc_status media_state(bc_vault_media_scope *scope,yyjson_val *root,int *known,int *pending,int *canonical,const char **claim) {
    *known=0;*pending=0;*canonical=0;
    *claim=NULL;
    const char *vault=yyjson_get_str(yyjson_obj_get(root,"vault_id"));
    if(scope->vault_id[0]&&strcmp(scope->vault_id,vault))return BC_INVALID_ARGUMENT;
    memcpy(scope->vault_id,vault,33);
    yyjson_val *records=yyjson_obj_get(root,"records");
    for(unsigned i=0;i<scope->count;++i){
        yyjson_val *record=yyjson_obj_get(records,scope->ids[i]);if(!record)continue;
        *known=1;if(!i)*canonical=1;
        int value=0;
        if(!yyjson_is_true(yyjson_obj_get(record,"deleted"))){
            yyjson_val *state=yyjson_obj_get(fields(record),"recovery");
            if(state&&!yyjson_is_obj(state))return BC_PROTOCOL_ERROR;
            if(!state)state=fields(record);
            yyjson_val *flag=yyjson_obj_get(state,"pending");if(!yyjson_is_bool(flag))return BC_PROTOCOL_ERROR;
            yyjson_val *operation=yyjson_obj_get(state,"operation_id");
            if(operation&&!valid_id(operation))return BC_PROTOCOL_ERROR;
            if(!i&&operation)*claim=yyjson_get_str(operation);
            value=yyjson_get_bool(flag);
        }
        *pending|=value;if(!i)break;
    }
    return BC_OK;
}
bc_status bc_vault_media_scope_read(bc_vault_media_scope *scope,bc_bytes snapshot,int *known,int *pending) {
    if(known)*known=0;
    if(pending)*pending=0;
    if(!scope||!scope->count||!known||!pending)return BC_INVALID_ARGUMENT;
    bc_vault_merge *m=NULL;bc_status status=snapshot_open(snapshot,&m);if(status!=BC_OK)return status;
    int canonical=0;const char *claim=NULL;status=media_state(scope,yyjson_doc_get_root(m->inputs[0]),known,pending,&canonical,&claim);
    if(status==BC_OK){
        scope->observed_pending=*pending;scope->observed_legacy=*pending&&!claim;
        scope->observed[0]=0;if(claim)memcpy(scope->observed,claim,33);
    }
    if(status!=BC_OK){*known=0;*pending=0;}
    bc_vault_merge_destroy(m);return status;
}
bc_status bc_vault_media_scope_observe(const bc_vault_media_scope *scope,bc_bytes snapshot,bc_vault_media_scope **out,int *known,int *pending) {
    if(out)*out=NULL;
    if(known)*known=0;
    if(pending)*pending=0;
    if(!scope||!scope->count||!out||!known||!pending)return BC_INVALID_ARGUMENT;
    bc_vault_media_scope *observer=calloc(1,sizeof(*observer));if(!observer)return BC_NO_MEMORY;
    memcpy(observer->ids,scope->ids,sizeof(observer->ids));observer->count=scope->count;
    memcpy(observer->vault_id,scope->vault_id,sizeof(observer->vault_id));
    bc_status status=bc_vault_media_scope_read(observer,snapshot,known,pending);
    if(status!=BC_OK){bc_vault_media_scope_destroy(observer);return status;}
    *out=observer;return BC_OK;
}
static bc_status remote_blocks_local(const bc_vault_media_scope *,yyjson_val *,int *);
static bc_status media_patch_apply(bc_vault_media_scope *scope,bc_vault_merge *m,uint32_t operation,uint64_t timestamp) {
    const char *off="{\"recovery\":{\"pending\":false}}";
    int known=0,pending=0,canonical=0;const char *claim=NULL;yyjson_val *root=yyjson_doc_get_root(m->inputs[0]);
    bc_status status=media_state(scope,root,&known,&pending,&canonical,&claim);
    if(status==BC_OK&&operation==BC_VAULT_MEDIA_BEGIN&&pending)status=BC_CONFIRMATION_REQUIRED;
    if(status==BC_OK&&operation==BC_VAULT_MEDIA_BEGIN){int blocked=0;
        status=remote_blocks_local(scope,root,&blocked);if(status==BC_OK&&blocked)status=BC_CONFIRMATION_REQUIRED;
    }
    if(status==BC_OK&&(operation==BC_VAULT_MEDIA_CLEAR||operation==BC_VAULT_MEDIA_CLEAR_OBSERVED)&&pending){
        int matches=operation==BC_VAULT_MEDIA_CLEAR&&scope->owned[0]?(claim&&!strcmp(scope->owned,claim)):
            scope->observed_pending&&(claim?!strcmp(scope->observed,claim):scope->observed_legacy);
        if(!matches)status=BC_CONFIRMATION_REQUIRED;
    }
    char created[33]={0};
    yyjson_val *existing=yyjson_obj_get(yyjson_obj_get(root,"records"),scope->ids[0]);
    int imported_current=operation==BC_VAULT_MEDIA_IMPORT_PENDING&&canonical&&
        (yyjson_obj_get(fields(existing),"recovery")||deleted(existing));
    if(status==BC_OK&&!imported_current){
        int value=operation==BC_VAULT_MEDIA_BEGIN||(operation==BC_VAULT_MEDIA_IMPORT_PENDING&&(!known||pending));
        char body[96];const char *json=off;
        if(value&&(operation==BC_VAULT_MEDIA_BEGIN||!claim)){
            unsigned char random[16];
            if(RAND_bytes(random,sizeof(random))!=1)status=BC_IO_ERROR;
            else {static const char digits[]="0123456789abcdef";for(unsigned i=0;i<16;++i){created[i*2]=digits[random[i]>>4];created[i*2+1]=digits[random[i]&15];}
            }
            OPENSSL_cleanse(random,sizeof(random));
        }
        if(created[0]||claim){
            snprintf(body,sizeof(body),"{\"recovery\":{\"pending\":%s,\"operation_id\":\"%s\"}}",value?"true":"false",created[0]?created:claim);json=body;
        }
        if(status!=BC_OK){return status;}
        yyjson_doc *patch=yyjson_read_opts((char *)(void *)json,strlen(json),0,&m->allocator,NULL);
        if(!patch)status=m->memory.limited?BC_LIMIT_EXCEEDED:BC_NO_MEMORY;
        else {status=patch_apply(m,root,scope->ids[0],yyjson_doc_get_root(patch),0,timestamp);yyjson_doc_free(patch);}
    }
    if(status!=BC_OK){return status;}
    if(operation==BC_VAULT_MEDIA_BEGIN)memcpy(scope->owned,created,sizeof(created));
    else if(operation==BC_VAULT_MEDIA_CLEAR||operation==BC_VAULT_MEDIA_ACKNOWLEDGE||operation==BC_VAULT_MEDIA_CLEAR_OBSERVED){scope->owned[0]=0;scope->observed[0]=0;scope->observed_pending=0;scope->observed_legacy=0;}
    return BC_OK;
}
bc_status bc_vault_media_scope_patch(bc_vault_media_scope *scope,bc_bytes snapshot,uint32_t operation,uint64_t timestamp,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;
    if(!scope||!scope->count||operation<BC_VAULT_MEDIA_BEGIN||operation>BC_VAULT_MEDIA_CLEAR_OBSERVED||timestamp>253402300799999ull)return BC_INVALID_ARGUMENT;
    bc_vault_merge *m=NULL;bc_status status=patch_open(snapshot,(bc_bytes){(const uint8_t *)"{}",2},FIELD_LIMIT,2,&m);
    if(status!=BC_OK)return status;
    status=media_patch_apply(scope,m,operation,timestamp);
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    *out=m;return BC_OK;
}
bc_status bc_vault_media_import_pending(bc_bytes snapshot,const bc_string *ids,uint32_t count,uint64_t timestamp,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;
    if((!ids&&count)||count>RECORD_LIMIT||timestamp>253402300799999ull)return BC_INVALID_ARGUMENT;
    bc_vault_merge *m=NULL;bc_status status=patch_open(snapshot,(bc_bytes){(const uint8_t *)"{}",2},FIELD_LIMIT,2,&m);
    if(status!=BC_OK)return status;
    yyjson_mut_val *processed=yyjson_mut_obj(m->output);
    if(!processed){bc_vault_merge_destroy(m);return BC_NO_MEMORY;}
    for(uint32_t i=0;i<count&&status==BC_OK;++i){
        if(!ids[i].data||ids[i].length!=76||memcmp(ids[i].data,"state:media:",12)){status=BC_INVALID_ARGUMENT;break;}
        for(unsigned j=12;j<76;++j)if(!((ids[i].data[j]>='0'&&ids[i].data[j]<='9')||(ids[i].data[j]>='a'&&ids[i].data[j]<='f'))){status=BC_INVALID_ARGUMENT;break;}
        if(status!=BC_OK)break;
        bc_vault_media_scope scope={0};memcpy(scope.ids[0],ids[i].data,76);scope.count=1;
        if(yyjson_mut_obj_get(processed,scope.ids[0]))continue;
        if(!put(m,processed,scope.ids[0],yyjson_mut_bool(m->output,1))){status=BC_NO_MEMORY;break;}
        status=media_patch_apply(&scope,m,BC_VAULT_MEDIA_IMPORT_PENDING,timestamp);
    }
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    *out=m;return BC_OK;
}

bc_status bc_vault_record_patch(bc_bytes snapshot,bc_string id,bc_bytes patch,int remove_record,uint64_t timestamp,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;
    if(id.length>128||!record_name_valid(id.data,(size_t)id.length)||!(remove_record==0||remove_record==1)||timestamp>253402300799999ull)return BC_INVALID_ARGUMENT;
    bc_vault_merge *m=NULL;bc_status status=patch_open(snapshot,patch,FIELD_LIMIT,2,&m);if(status!=BC_OK)return status;
    char name[129];memcpy(name,id.data,(size_t)id.length);name[id.length]=0;
    status=patch_apply(m,yyjson_doc_get_root(m->inputs[0]),name,yyjson_doc_get_root(m->inputs[1]),remove_record,timestamp);
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    *out=m;return BC_OK;
}
bc_status bc_vault_records_patch(bc_bytes snapshot,bc_bytes patch,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;bc_vault_merge *m=NULL;bc_status status=patch_open(snapshot,patch,RECORD_LIMIT,1,&m);if(status!=BC_OK)return status;
    yyjson_val *updates=yyjson_doc_get_root(m->inputs[1]);
    size_t i,n;yyjson_val *key,*record;
    yyjson_obj_foreach(updates,i,n,key,record){
        yyjson_val *data=fields(record),*time=yyjson_obj_get(record,"modified_at_ms"),*removed=yyjson_obj_get(record,"deleted");
        if(!record_name_valid(yyjson_get_str(key),yyjson_get_len(key))||!yyjson_is_obj(record)||yyjson_obj_size(record)!=3||
            !yyjson_is_obj(data)||yyjson_obj_size(data)>FIELD_LIMIT||!yyjson_is_uint(time)||yyjson_get_uint(time)>253402300799999ull||!yyjson_is_bool(removed)){
            status=BC_PROTOCOL_ERROR;break;
        }
        status=patch_apply(m,yyjson_doc_get_root(m->inputs[0]),yyjson_get_str(key),data,yyjson_get_bool(removed),yyjson_get_uint(time));
        if(status!=BC_OK)break;
    }
    if(status==BC_OK&&yyjson_mut_obj_size(m->records)>RECORD_LIMIT)status=BC_LIMIT_EXCEEDED;
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    *out=m;return BC_OK;
}
uint32_t bc_vault_merge_conflicts(const bc_vault_merge *m){return m?m->count:0;}
uint32_t bc_vault_merge_pending(const bc_vault_merge *m){return m?m->pending:0;}
static void clear_cache(bc_vault_merge *m){release(&m->memory,m->cached);m->cached=NULL;m->cached_size=0;}
bc_status bc_vault_merge_conflict(bc_vault_merge *m,uint32_t index,bc_bytes *out) {
    if(!m||!out||index>=m->count)return BC_INVALID_ARGUMENT;
    *out=(bc_bytes){NULL,0};conflict *c=&m->conflicts[index];if(c->resolved)return BC_BUSY;
    clear_cache(m);yyjson_mut_doc *doc=yyjson_mut_doc_new(&m->allocator);if(!doc)return BC_NO_MEMORY;
    yyjson_mut_val *root=yyjson_mut_obj(doc);int ok=root&&yyjson_mut_obj_add_strcpy(doc,root,"record",c->record)&&
        yyjson_mut_obj_add_strcpy(doc,root,"field",c->field?c->field:"");
    const char *names[3]={"base","local","remote"};
    for(unsigned i=0;i<3&&ok;++i){yyjson_mut_val *variant=yyjson_mut_obj(doc);
        ok=variant&&yyjson_mut_obj_add_bool(doc,variant,"present",c->values[i]!=NULL)&&
            yyjson_mut_obj_add_val(doc,variant,"value",c->values[i]?yyjson_val_mut_copy(doc,c->values[i]):yyjson_mut_null(doc))&&
            yyjson_mut_obj_add_val(doc,root,names[i],variant);
    }
    if(ok){yyjson_mut_doc_set_root(doc,root);m->cached=yyjson_mut_write_opts(doc,0,&m->allocator,&m->cached_size,NULL);}
    yyjson_mut_doc_free(doc);if(!m->cached)return BC_NO_MEMORY;
    *out=(bc_bytes){(const uint8_t *)m->cached,m->cached_size};return BC_OK;
}
bc_status bc_vault_merge_resolve(bc_vault_merge *m,uint32_t index,uint32_t choice) {
    if(!m||index>=m->count||choice<1||choice>3)return BC_INVALID_ARGUMENT;
    conflict *c=&m->conflicts[index];if(c->resolved)return BC_BUSY;
    yyjson_val *selected=c->values[choice-1];
    if(!c->field){if(!put(m,c->target,c->record,record_copy(m,selected,c->timestamp)))return BC_NO_MEMORY;}
    else if(selected){
        if(yyjson_mut_obj_size(c->target)>=FIELD_LIMIT&&!yyjson_mut_obj_get(c->target,c->field))return BC_LIMIT_EXCEEDED;
        if(!put(m,c->target,c->field,yyjson_val_mut_copy(m->output,selected)))return BC_NO_MEMORY;
    }
    else yyjson_mut_obj_remove_key(c->target,c->field);
    c->resolved=1;--m->pending;clear_cache(m);return BC_OK;
}
bc_status bc_vault_merge_export(bc_vault_merge *m,uint8_t *out,uint32_t capacity,uint32_t *written) {
    if(!m||!written)return BC_INVALID_ARGUMENT;
    *written=0;if(m->pending)return BC_CONFIRMATION_REQUIRED;
    clear_cache(m);m->cached=yyjson_mut_write_opts(m->output,0,&m->allocator,&m->cached_size,NULL);
    if(!m->cached)return m->memory.limited?BC_LIMIT_EXCEEDED:BC_NO_MEMORY;
    if(m->cached_size>INPUT_LIMIT)return BC_LIMIT_EXCEEDED;
    *written=(uint32_t)m->cached_size;if(!out||capacity<*written)return BC_LIMIT_EXCEEDED;
    memcpy(out,m->cached,*written);return BC_OK;
}
void bc_vault_merge_destroy(bc_vault_merge *m) {
    if(!m)return;
    clear_cache(m);for(unsigned i=0;i<3;++i)yyjson_doc_free(m->inputs[i]);
    yyjson_mut_doc_free(m->output);release(&m->memory,m->conflicts);OPENSSL_cleanse(m,sizeof(*m));free(m);
}

static int remote_key(const bc_vault_media_scope *scope,bc_string uri,char id[78]) {
    if(!uri.data||!uri.length||uri.length>1023||uri.data[0]!='/'||
       (uri.length>1&&uri.data[1]=='/'))return 0;
    for(size_t i=0;i<(size_t)uri.length;++i){unsigned char c=(unsigned char)uri.data[i];if(c<=32||c>=127||c=='#'||c=='\\')return 0;}
    unsigned char hash[32];unsigned length=0;EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx)return 0;
    int ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)&&EVP_DigestUpdate(ctx,scope->ids[0],76)&&
        EVP_DigestUpdate(ctx,"",1)&&EVP_DigestUpdate(ctx,uri.data,(size_t)uri.length)&&EVP_DigestFinal_ex(ctx,hash,&length);
    EVP_MD_CTX_free(ctx);if(!ok||length!=32){OPENSSL_cleanse(hash,sizeof(hash));return 0;}
    memcpy(id,"state:remote:",13);static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<32;++i){id[13+i*2]=hex[hash[i]>>4];id[14+i*2]=hex[hash[i]&15];}id[77]=0;
    OPENSSL_cleanse(hash,sizeof(hash));return 1;
}
static int source_digest_valid(yyjson_val *value) {
    if(!yyjson_is_str(value)||yyjson_get_len(value)!=64)return 0;
    const char *text=yyjson_get_str(value);
    for(unsigned i=0;i<64;++i)if(!((text[i]>='0'&&text[i]<='9')||(text[i]>='a'&&text[i]<='f')))return 0;
    return 1;
}
static bc_status source_digest(bc_string source,char text[65]) {
    if(!source.data||!source.length||source.length>8192||memchr(source.data,0,(size_t)source.length))return BC_INVALID_ARGUMENT;
    unsigned char hash[32];unsigned length=0;
    if(!EVP_Digest(source.data,(size_t)source.length,hash,&length,EVP_sha256(),NULL)||length!=32){OPENSSL_cleanse(hash,sizeof(hash));return BC_IO_ERROR;}
    static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<32;++i){text[i*2]=hex[hash[i]>>4];text[i*2+1]=hex[hash[i]&15];}text[64]=0;
    OPENSSL_cleanse(hash,sizeof(hash));return BC_OK;
}
static int remote_value_valid(yyjson_val *value) {
    uint64_t action=yyjson_get_uint(yyjson_obj_get(value,"action")),phase=yyjson_get_uint(yyjson_obj_get(value,"phase"));
    yyjson_val *uri=yyjson_obj_get(value,"media_uri"),*reference=yyjson_obj_get(value,"reference");
    return yyjson_is_obj(value)&&yyjson_is_uint(yyjson_obj_get(value,"action"))&&yyjson_is_uint(yyjson_obj_get(value,"phase"))&&valid_id(yyjson_obj_get(value,"operation_id"))&&
        yyjson_is_str(yyjson_obj_get(value,"scope_id"))&&yyjson_get_len(yyjson_obj_get(value,"scope_id"))==76&&
        strlen(yyjson_get_str(yyjson_obj_get(value,"scope_id")))==76&&yyjson_is_str(uri)&&strlen(yyjson_get_str(uri))==yyjson_get_len(uri)&&
        action>=BC_VAULT_REMOTE_INSERT&&action<=BC_VAULT_REMOTE_EJECT&&phase>=BC_VAULT_REMOTE_SUBMITTING&&phase<=BC_VAULT_REMOTE_CLEARED&&
        !(action==BC_VAULT_REMOTE_EJECT&&phase==BC_VAULT_REMOTE_SETTLED)&&
        (!reference||(yyjson_is_str(reference)&&yyjson_get_len(reference)<=10924))&&
        (!yyjson_obj_get(value,"write_complete")||yyjson_is_bool(yyjson_obj_get(value,"write_complete")))&&
        (!yyjson_obj_get(value,"source_digest")||source_digest_valid(yyjson_obj_get(value,"source_digest")))&&
        (!yyjson_obj_get(value,"source_verification")||(yyjson_is_uint(yyjson_obj_get(value,"source_verification"))&&
            yyjson_get_uint(yyjson_obj_get(value,"source_verification"))<=BC_VAULT_SOURCE_MISMATCH))&&
        ((yyjson_get_uint(yyjson_obj_get(value,"source_verification"))!=BC_VAULT_SOURCE_VERIFIED&&
          yyjson_get_uint(yyjson_obj_get(value,"source_verification"))!=BC_VAULT_SOURCE_MISMATCH)||
         source_digest_valid(yyjson_obj_get(value,"source_digest")));
}
static int remote_valid(yyjson_val *value) {
    if(!remote_value_valid(value))return 0;
    yyjson_val *prior=yyjson_obj_get(value,"previous_insert");
    return !prior||(yyjson_get_uint(yyjson_obj_get(value,"action"))==BC_VAULT_REMOTE_EJECT&&
        yyjson_get_uint(yyjson_obj_get(value,"phase"))==BC_VAULT_REMOTE_SUBMITTING&&remote_value_valid(prior)&&
        !yyjson_obj_get(prior,"previous_insert")&&yyjson_get_uint(yyjson_obj_get(prior,"action"))==BC_VAULT_REMOTE_INSERT&&
        (yyjson_get_uint(yyjson_obj_get(prior,"phase"))==BC_VAULT_REMOTE_SETTLED||yyjson_is_true(yyjson_obj_get(prior,"write_complete")))&&
        yyjson_get_uint(yyjson_obj_get(prior,"phase"))!=BC_VAULT_REMOTE_CLEARED&&
        equal(yyjson_obj_get(value,"scope_id"),yyjson_obj_get(prior,"scope_id"))&&
        equal(yyjson_obj_get(value,"media_uri"),yyjson_obj_get(prior,"media_uri")));
}
static bc_status remote_blocks_local(const bc_vault_media_scope *scope,yyjson_val *root,int *blocked) {
    *blocked=0;yyjson_val *records=yyjson_obj_get(root,"records");size_t i,n;yyjson_val *key,*record;
    yyjson_obj_foreach(records,i,n,key,record){
        if(strncmp(yyjson_get_str(key),"state:remote:",13)||deleted(record))continue;
        yyjson_val *value=yyjson_obj_get(fields(record),"operation"),*identity=yyjson_obj_get(value,"scope_id");
        if(!yyjson_is_str(identity)||strcmp(yyjson_get_str(identity),scope->ids[0]))continue;
        yyjson_val *uri=yyjson_obj_get(value,"media_uri");char id[78];
        if(!remote_valid(value)||!remote_key(scope,(bc_string){yyjson_get_str(uri),yyjson_get_len(uri)},id)||strcmp(id,yyjson_get_str(key)))return BC_PROTOCOL_ERROR;
        if(yyjson_get_uint(yyjson_obj_get(value,"phase"))!=BC_VAULT_REMOTE_CLEARED)*blocked=1;
    }
    return BC_OK;
}
static bc_status remote_generation(char generation[33]) {
    unsigned char random[16];
    if(RAND_bytes(random,sizeof(random))!=1){OPENSSL_cleanse(random,sizeof(random));return BC_IO_ERROR;}
    static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<16;++i){generation[i*2]=hex[random[i]>>4];generation[i*2+1]=hex[random[i]&15];}
    generation[32]=0;OPENSSL_cleanse(random,sizeof(random));return BC_OK;
}
static bc_status remote_open(bc_vault_media_scope *scope,bc_bytes snapshot,bc_vault_merge **out) {
    if(!scope||!scope->count)return BC_INVALID_ARGUMENT;
    bc_vault_merge *m=NULL;bc_status status=snapshot_open(snapshot,&m);if(status!=BC_OK)return status;
    yyjson_val *root=yyjson_doc_get_root(m->inputs[0]);int known,pending,canonical;const char *claim;
    status=media_state(scope,root,&known,&pending,&canonical,&claim);
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    *out=m;return BC_OK;
}
bc_status bc_vault_media_remote_list(bc_vault_media_scope *scope,bc_bytes snapshot,unsigned char *output,uint32_t capacity,uint32_t *written) {
    if(written)*written=0;
    if(output&&capacity)output[0]=0;
    if(!written||(!output&&capacity))return BC_INVALID_ARGUMENT;
    bc_vault_merge *m=NULL;bc_status status=remote_open(scope,snapshot,&m);if(status!=BC_OK)return status;
    m->output=yyjson_mut_doc_new(&m->allocator);yyjson_mut_val *array=m->output?yyjson_mut_arr(m->output):NULL;
    if(!array){bc_vault_merge_destroy(m);return BC_NO_MEMORY;}yyjson_mut_doc_set_root(m->output,array);
    yyjson_val *records=yyjson_obj_get(yyjson_doc_get_root(m->inputs[0]),"records");size_t i,n;yyjson_val *key,*record;
    yyjson_obj_foreach(records,i,n,key,record){
        if(strncmp(yyjson_get_str(key),"state:remote:",13)||deleted(record))continue;
        yyjson_val *value=yyjson_obj_get(fields(record),"operation"),*identity=yyjson_obj_get(value,"scope_id");
        if(!yyjson_is_str(identity)||strcmp(yyjson_get_str(identity),scope->ids[0]))continue;
        yyjson_val *uri=yyjson_obj_get(value,"media_uri");char id[78];
        if(!remote_valid(value)||!remote_key(scope,(bc_string){yyjson_get_str(uri),yyjson_get_len(uri)},id)||strcmp(id,yyjson_get_str(key))){status=BC_PROTOCOL_ERROR;break;}
        if(yyjson_get_uint(yyjson_obj_get(value,"phase"))==BC_VAULT_REMOTE_CLEARED)continue;
        yyjson_mut_val *copy=yyjson_val_mut_copy(m->output,value);
        if(copy)yyjson_mut_obj_remove_key(copy,"previous_insert");
        if(!copy||!yyjson_mut_arr_append(array,copy)){status=BC_NO_MEMORY;break;}
    }
    if(status==BC_OK){size_t length=0;char *data=yyjson_mut_write_opts(m->output,0,&m->allocator,&length,NULL);
        if(!data)status=m->memory.limited?BC_LIMIT_EXCEEDED:BC_NO_MEMORY;
        else{*written=(uint32_t)length;if(length>capacity)status=BC_LIMIT_EXCEEDED;else if(length)memcpy(output,data,length);release(&m->memory,data);}}
    bc_vault_merge_destroy(m);return status;
}
bc_status bc_vault_media_remote_patch(bc_vault_media_scope *scope,bc_bytes snapshot,bc_string uri,bc_string expected,
    uint32_t action,uint32_t phase,bc_bytes reference,uint64_t timestamp,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;char id[78];
    if(!scope||!scope->count||!remote_key(scope,uri,id)||(!expected.data&&expected.length)||(expected.length&&expected.length!=32)||
       action<BC_VAULT_REMOTE_INSERT||action>BC_VAULT_REMOTE_EJECT||phase<BC_VAULT_REMOTE_SUBMITTING||phase>BC_VAULT_REMOTE_CLEARED||
       (action==BC_VAULT_REMOTE_EJECT&&phase==BC_VAULT_REMOTE_SETTLED)||reference.length>8192||(!reference.data&&reference.length)||timestamp>253402300799999ull)return BC_INVALID_ARGUMENT;
    bc_vault_merge *m=NULL;bc_status status=remote_open(scope,snapshot,&m);if(status!=BC_OK)return status;
    yyjson_val *root=yyjson_doc_get_root(m->inputs[0]),*record=yyjson_obj_get(yyjson_obj_get(root,"records"),id);
    yyjson_val *previous=deleted(record)?NULL:yyjson_obj_get(fields(record),"operation");
    if(previous&&(!remote_valid(previous)||strcmp(yyjson_get_str(yyjson_obj_get(previous,"scope_id")),scope->ids[0])||
       yyjson_get_len(yyjson_obj_get(previous,"media_uri"))!=uri.length||memcmp(yyjson_get_str(yyjson_obj_get(previous,"media_uri")),uri.data,(size_t)uri.length)))status=BC_PROTOCOL_ERROR;
    if(status==BC_OK&&phase==BC_VAULT_REMOTE_SUBMITTING&&action==BC_VAULT_REMOTE_INSERT){int known,pending,canonical;const char *local_claim;
        status=media_state(scope,root,&known,&pending,&canonical,&local_claim);
        if(status==BC_OK&&pending)status=BC_CONFIRMATION_REQUIRED;
    }
    const char *claim=yyjson_get_str(yyjson_obj_get(previous,"operation_id"));
    uint64_t prior=yyjson_get_uint(yyjson_obj_get(previous,"phase"));
    int fresh_clear=phase==BC_VAULT_REMOTE_SUBMITTING&&prior==BC_VAULT_REMOTE_CLEARED&&!expected.length;
    if(status==BC_OK&&!fresh_clear&&((claim?32u:0u)!=expected.length||(claim&&memcmp(claim,expected.data,32))))status=BC_CONFIRMATION_REQUIRED;
    if(status==BC_OK&&phase==BC_VAULT_REMOTE_SUBMITTING&&previous&&
       (prior!=BC_VAULT_REMOTE_CLEARED&&!(action==BC_VAULT_REMOTE_EJECT&&(prior==BC_VAULT_REMOTE_SETTLED||yyjson_is_true(yyjson_obj_get(previous,"write_complete"))))))status=BC_CONFIRMATION_REQUIRED;
    if(status==BC_OK&&phase!=BC_VAULT_REMOTE_SUBMITTING&&(!previous||
       yyjson_get_uint(yyjson_obj_get(previous,"action"))!=action||
       (phase!=BC_VAULT_REMOTE_CLEARED&&phase<prior)))status=BC_CONFIRMATION_REQUIRED;
    if(status==BC_OK&&phase==BC_VAULT_REMOTE_SETTLED&&yyjson_get_uint(yyjson_obj_get(previous,"source_verification"))==BC_VAULT_SOURCE_MISMATCH)status=BC_CONFIRMATION_REQUIRED;
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    char generation[33];if(phase==BC_VAULT_REMOTE_SUBMITTING){
        status=remote_generation(generation);if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    }else memcpy(generation,claim,33);
    m->output=yyjson_doc_mut_copy(m->inputs[0],&m->allocator);
    if(!m->output){bc_vault_merge_destroy(m);return BC_NO_MEMORY;}
    m->records=yyjson_mut_obj_get(yyjson_mut_doc_get_root(m->output),"records");
    yyjson_mut_val *updated=record_copy(m,record,timestamp),*value=yyjson_mut_obj(m->output);
    int ok=updated&&value&&put(m,m->records,id,updated)&&put(m,updated,"deleted",yyjson_mut_bool(m->output,0));
    if(ok)ok=yyjson_mut_obj_add_strcpy(m->output,value,"scope_id",scope->ids[0])&&
        yyjson_mut_obj_add_strncpy(m->output,value,"media_uri",uri.data,(size_t)uri.length)&&
        yyjson_mut_obj_add_strcpy(m->output,value,"operation_id",generation)&&
        yyjson_mut_obj_add_uint(m->output,value,"action",action)&&yyjson_mut_obj_add_uint(m->output,value,"phase",phase);
    if(ok&&reference.length&&phase!=BC_VAULT_REMOTE_CLEARED){unsigned char encoded[10925];int length=EVP_EncodeBlock(encoded,reference.data,(int)reference.length);
        ok=length>=0&&yyjson_mut_obj_add_strncpy(m->output,value,"reference",(char *)encoded,(size_t)length);OPENSSL_cleanse(encoded,sizeof(encoded));
    }else if(ok&&phase!=BC_VAULT_REMOTE_SUBMITTING&&phase!=BC_VAULT_REMOTE_CLEARED){yyjson_val *saved=yyjson_obj_get(previous,"reference");if(saved)ok=put(m,value,"reference",yyjson_val_mut_copy(m->output,saved));}
    if(ok&&phase!=BC_VAULT_REMOTE_SUBMITTING&&phase!=BC_VAULT_REMOTE_CLEARED){
        const char *keys[]={"source_digest","source_verification","write_complete"};
        for(unsigned i=0;ok&&i<3;++i){yyjson_val *saved=yyjson_obj_get(previous,keys[i]);if(saved)ok=put(m,value,keys[i],yyjson_val_mut_copy(m->output,saved));}
    }
    if(ok&&phase==BC_VAULT_REMOTE_SUBMITTING&&action==BC_VAULT_REMOTE_EJECT&&previous&&
       yyjson_get_uint(yyjson_obj_get(previous,"action"))==BC_VAULT_REMOTE_INSERT&&prior!=BC_VAULT_REMOTE_CLEARED)
        ok=put(m,value,"previous_insert",yyjson_val_mut_copy(m->output,previous));
    if(ok)ok=put(m,yyjson_mut_obj_get(updated,"fields"),"operation",value)&&
        put(m,updated,"modified_at_ms",yyjson_mut_uint(m->output,timestamp>yyjson_get_uint(yyjson_obj_get(record,"modified_at_ms"))?timestamp:yyjson_get_uint(yyjson_obj_get(record,"modified_at_ms"))));
    OPENSSL_cleanse(generation,sizeof(generation));
    if(!ok||yyjson_mut_obj_size(m->records)>RECORD_LIMIT){status=ok?BC_LIMIT_EXCEEDED:BC_NO_MEMORY;bc_vault_merge_destroy(m);return status;}
    *out=m;return BC_OK;
}

bc_status bc_vault_media_remote_reject(bc_vault_media_scope *scope,bc_bytes snapshot,bc_string uri,bc_string expected,
    uint64_t timestamp,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;char id[78],generation[33];
    if(!scope||!scope->count||!remote_key(scope,uri,id)||!expected.data||expected.length!=32||timestamp>253402300799999ull)return BC_INVALID_ARGUMENT;
    bc_vault_merge *m=NULL;bc_status status=remote_open(scope,snapshot,&m);if(status!=BC_OK)return status;
    yyjson_val *record=yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(m->inputs[0]),"records"),id);
    yyjson_val *current=deleted(record)?NULL:yyjson_obj_get(fields(record),"operation");
    if(!current)status=BC_CONFIRMATION_REQUIRED;
    else if(!remote_valid(current)||strcmp(yyjson_get_str(yyjson_obj_get(current,"scope_id")),scope->ids[0])||
       yyjson_get_len(yyjson_obj_get(current,"media_uri"))!=uri.length||memcmp(yyjson_get_str(yyjson_obj_get(current,"media_uri")),uri.data,(size_t)uri.length))status=BC_PROTOCOL_ERROR;
    else if(memcmp(yyjson_get_str(yyjson_obj_get(current,"operation_id")),expected.data,32)||
       yyjson_get_uint(yyjson_obj_get(current,"phase"))!=BC_VAULT_REMOTE_SUBMITTING||
       yyjson_is_true(yyjson_obj_get(current,"write_complete"))||yyjson_obj_get(current,"reference"))status=BC_CONFIRMATION_REQUIRED;
    if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    yyjson_val *prior=yyjson_obj_get(current,"previous_insert");
    if(!prior){
        uint32_t action=(uint32_t)yyjson_get_uint(yyjson_obj_get(current,"action"));bc_vault_merge_destroy(m);
        return bc_vault_media_remote_patch(scope,snapshot,uri,expected,action,BC_VAULT_REMOTE_CLEARED,(bc_bytes){0},timestamp,out);
    }
    status=remote_generation(generation);if(status!=BC_OK){bc_vault_merge_destroy(m);return status;}
    m->output=yyjson_doc_mut_copy(m->inputs[0],&m->allocator);
    if(!m->output){OPENSSL_cleanse(generation,sizeof(generation));bc_vault_merge_destroy(m);return BC_NO_MEMORY;}
    m->records=yyjson_mut_obj_get(yyjson_mut_doc_get_root(m->output),"records");
    yyjson_mut_val *updated=yyjson_mut_obj_get(m->records,id),*value=yyjson_val_mut_copy(m->output,prior);
    uint64_t before=yyjson_get_uint(yyjson_obj_get(record,"modified_at_ms"));
    int ok=value&&put(m,value,"operation_id",yyjson_mut_strcpy(m->output,generation))&&
        put(m,yyjson_mut_obj_get(updated,"fields"),"operation",value)&&
        put(m,updated,"modified_at_ms",yyjson_mut_uint(m->output,timestamp>before?timestamp:before));
    OPENSSL_cleanse(generation,sizeof(generation));if(!ok){bc_vault_merge_destroy(m);return BC_NO_MEMORY;}
    *out=m;return BC_OK;
}

bc_status bc_vault_media_remote_begin(bc_vault_media_scope *scope,bc_bytes snapshot,bc_string uri,bc_string expected,
    uint32_t action,bc_string source,uint64_t timestamp,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;char digest[65]={0},id[78];bc_status status=BC_OK;
    if(action==BC_VAULT_REMOTE_INSERT)status=source_digest(source,digest);
    else if(source.length)status=BC_INVALID_ARGUMENT;
    if(status!=BC_OK)return status;
    bc_vault_merge *m=NULL;status=bc_vault_media_remote_patch(scope,snapshot,uri,expected,action,BC_VAULT_REMOTE_SUBMITTING,(bc_bytes){0},timestamp,&m);
    if(status!=BC_OK){OPENSSL_cleanse(digest,sizeof(digest));return status;}
    if(action==BC_VAULT_REMOTE_INSERT){
        if(!remote_key(scope,uri,id)){bc_vault_merge_destroy(m);OPENSSL_cleanse(digest,sizeof(digest));return BC_IO_ERROR;}
        yyjson_mut_val *record=yyjson_mut_obj_get(m->records,id),*value=yyjson_mut_obj_get(yyjson_mut_obj_get(record,"fields"),"operation");
        int ok=put(m,value,"source_digest",yyjson_mut_strcpy(m->output,digest))&&
            put(m,value,"source_verification",yyjson_mut_uint(m->output,BC_VAULT_SOURCE_UNKNOWN));
        if(!ok){bc_vault_merge_destroy(m);OPENSSL_cleanse(digest,sizeof(digest));return BC_NO_MEMORY;}
    }
    OPENSSL_cleanse(digest,sizeof(digest));*out=m;return BC_OK;
}
bc_status bc_vault_media_remote_observe_source(bc_vault_media_scope *scope,bc_bytes snapshot,bc_string uri,bc_string expected,
    bc_string reported,uint32_t completed,uint32_t inserted,uint64_t timestamp,bc_vault_merge **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;char id[78],digest[65]={0};
    if(!scope||!scope->count||!remote_key(scope,uri,id)||!expected.data||expected.length!=32||completed>1||inserted>1||
       (!reported.data&&reported.length)||reported.length>8192||timestamp>253402300799999ull)return BC_INVALID_ARGUMENT;
    if(reported.length&&inserted){bc_status status=source_digest(reported,digest);if(status!=BC_OK)return status;}
    bc_vault_merge *m=NULL;bc_status status=remote_open(scope,snapshot,&m);if(status!=BC_OK){OPENSSL_cleanse(digest,sizeof(digest));return status;}
    yyjson_val *record=yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(m->inputs[0]),"records"),id);
    yyjson_val *previous=deleted(record)?NULL:yyjson_obj_get(fields(record),"operation");
    if(!previous)status=BC_CONFIRMATION_REQUIRED;
    else if(!remote_valid(previous)||strcmp(yyjson_get_str(yyjson_obj_get(previous,"scope_id")),scope->ids[0])||
       yyjson_get_len(yyjson_obj_get(previous,"media_uri"))!=uri.length||memcmp(yyjson_get_str(yyjson_obj_get(previous,"media_uri")),uri.data,(size_t)uri.length))status=BC_PROTOCOL_ERROR;
    else if(memcmp(yyjson_get_str(yyjson_obj_get(previous,"operation_id")),expected.data,32)||
       yyjson_get_uint(yyjson_obj_get(previous,"action"))!=BC_VAULT_REMOTE_INSERT||
       yyjson_get_uint(yyjson_obj_get(previous,"phase"))==BC_VAULT_REMOTE_CLEARED)status=BC_CONFIRMATION_REQUIRED;
    if(status!=BC_OK){bc_vault_merge_destroy(m);OPENSSL_cleanse(digest,sizeof(digest));return status;}
    const char *requested=yyjson_get_str(yyjson_obj_get(previous,"source_digest"));
    uint32_t verification=!inserted?(uint32_t)yyjson_get_uint(yyjson_obj_get(previous,"source_verification")):
        !requested||!reported.length?BC_VAULT_SOURCE_UNVERIFIED:
        !CRYPTO_memcmp(requested,digest,64)?BC_VAULT_SOURCE_VERIFIED:BC_VAULT_SOURCE_MISMATCH;
    uint64_t prior=yyjson_get_uint(yyjson_obj_get(previous,"phase"));
    int finished=completed||yyjson_is_true(yyjson_obj_get(previous,"write_complete"))||prior==BC_VAULT_REMOTE_SETTLED;
    uint64_t phase=verification==BC_VAULT_SOURCE_MISMATCH?BC_VAULT_REMOTE_ACCEPTED:finished&&inserted?BC_VAULT_REMOTE_SETTLED:prior;
    m->output=yyjson_doc_mut_copy(m->inputs[0],&m->allocator);
    if(!m->output){bc_vault_merge_destroy(m);OPENSSL_cleanse(digest,sizeof(digest));return BC_NO_MEMORY;}
    m->records=yyjson_mut_obj_get(yyjson_mut_doc_get_root(m->output),"records");
    yyjson_mut_val *updated=yyjson_mut_obj_get(m->records,id),*value=yyjson_mut_obj_get(yyjson_mut_obj_get(updated,"fields"),"operation");
    int ok=put(m,value,"source_verification",yyjson_mut_uint(m->output,verification))&&put(m,value,"phase",yyjson_mut_uint(m->output,phase))&&
        put(m,value,"write_complete",yyjson_mut_bool(m->output,finished));
    yyjson_val *old=yyjson_obj_get(previous,"source_verification");
    if(ok&&(!old||yyjson_get_uint(old)!=verification||prior!=phase||!yyjson_is_bool(yyjson_obj_get(previous,"write_complete"))||
       yyjson_get_bool(yyjson_obj_get(previous,"write_complete"))!=finished)){
        uint64_t before=yyjson_get_uint(yyjson_obj_get(record,"modified_at_ms"));
        ok=put(m,updated,"modified_at_ms",yyjson_mut_uint(m->output,timestamp>before?timestamp:before));
    }
    OPENSSL_cleanse(digest,sizeof(digest));if(!ok){bc_vault_merge_destroy(m);return BC_NO_MEMORY;}
    *out=m;return BC_OK;
}

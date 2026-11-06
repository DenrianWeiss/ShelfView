#define _POSIX_C_SOURCE 200809L
#include "../core/vault/system_internal.h"
#include <openssl/crypto.h>
#include <dlfcn.h>
#include <string.h>
typedef unsigned (*hash_fn)(const void *);
typedef int (*equal_fn)(const void *, const void *);
typedef struct {
    void *secret, *glib, *schema, *attributes;
    void *(*hash_new)(hash_fn,equal_fn);
    void (*hash_insert)(void *,void *,void *);
    void (*hash_unref)(void *);
    hash_fn hash;equal_fn equal;
    void *(*schema_new)(const char *,int,void *);
    void (*schema_unref)(void *);
    int (*store)(const void *,void *,const char *,const char *,const char *,void *,void **);
    char *(*lookup)(const void *,void *,void *,void **);
    int (*clear)(const void *,void *,void *,void **);
    void (*password_free)(char *);
    void (*error_free)(void *);
} secret_api;
static void close_api(secret_api *a) {
    if(a->schema)a->schema_unref(a->schema);
    if(a->attributes)a->hash_unref(a->attributes);
    if(a->secret)dlclose(a->secret);
    if(a->glib)dlclose(a->glib);
}
#define LOAD(handle,field,symbol_name) do { \
    void *symbol=dlsym((handle),(symbol_name)); \
    if(!symbol||sizeof(a->field)!=sizeof(symbol)){close_api(a);return BC_UNSUPPORTED;} \
    memcpy(&a->field,&symbol,sizeof(symbol)); \
} while(0)
static bc_status open_api(secret_api *a, const char *reference, int legacy) {
    memset(a,0,sizeof(*a));a->secret=dlopen("libsecret-1.so.0",RTLD_NOW|RTLD_LOCAL);
    a->glib=dlopen("libglib-2.0.so.0",RTLD_NOW|RTLD_LOCAL);
    if(!a->secret||!a->glib){close_api(a);return BC_UNSUPPORTED;}
    LOAD(a->glib,hash_new,"g_hash_table_new");LOAD(a->glib,hash_insert,"g_hash_table_insert");
    LOAD(a->glib,hash_unref,"g_hash_table_unref");LOAD(a->glib,hash,"g_str_hash");LOAD(a->glib,equal,"g_str_equal");
    LOAD(a->glib,error_free,"g_error_free");LOAD(a->secret,schema_new,"secret_schema_newv");
    LOAD(a->secret,schema_unref,"secret_schema_unref");LOAD(a->secret,store,"secret_password_storev_sync");
    LOAD(a->secret,lookup,"secret_password_lookupv_sync");LOAD(a->secret,clear,"secret_password_clearv_sync");
    LOAD(a->secret,password_free,"secret_password_free");
    void *types=a->hash_new(a->hash,a->equal);
    if(!types){close_api(a);return BC_NO_MEMORY;}
    a->hash_insert(types,(void *)"vault-key",NULL);
    a->schema=a->schema_new(legacy?"org.bcontrol.VaultKey":"work.permutation.shelfview.VaultKey",0,types);a->hash_unref(types);
    a->attributes=a->hash_new(a->hash,a->equal);
    if(!a->schema||!a->attributes){close_api(a);return BC_NO_MEMORY;}
    a->hash_insert(a->attributes,(void *)"vault-key",(void *)reference);return BC_OK;
}
static int nibble(char c) { return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1; }
bc_status vault_system_read(const char reference[65], int legacy, uint8_t key[32], int *found, uint32_t *flags) {
    secret_api api;bc_status status=open_api(&api,reference,legacy);if(status!=BC_OK)return status;
    void *error=NULL;char *password=api.lookup(api.schema,api.attributes,NULL,&error);
    if(error){api.error_free(error);status=BC_IO_ERROR;}
    else if(password){
        if(strnlen(password,65)!=64)status=BC_PROTOCOL_ERROR;
        else for(unsigned i=0;i<32;++i){int high=nibble(password[i*2]),low=nibble(password[i*2+1]);if(high<0||low<0){status=BC_PROTOCOL_ERROR;break;}key[i]=(uint8_t)(high*16+low);}
        if(status==BC_OK){*found=1;*flags=BC_VAULT_KEY_LOCAL;}
    }
    if(password)api.password_free(password);
    close_api(&api);return status;
}
bc_status vault_system_store(const char reference[65], const uint8_t key[32], int roaming, uint32_t *flags) {
    (void)roaming;secret_api api;bc_status status=open_api(&api,reference,0);if(status!=BC_OK)return status;
    const char alphabet[]="0123456789abcdef";char password[65];
    for(unsigned i=0;i<32;++i){password[i*2]=alphabet[key[i]>>4];password[i*2+1]=alphabet[key[i]&15];}password[64]=0;
    void *error=NULL;int ok=api.store(api.schema,api.attributes,NULL,"ShelfView Vault",password,NULL,&error);
    OPENSSL_cleanse(password,sizeof(password));
    if(error){api.error_free(error);status=BC_IO_ERROR;}else if(!ok)status=BC_IO_ERROR;
    if(status==BC_OK)*flags=BC_VAULT_KEY_LOCAL;
    close_api(&api);return status;
}
bc_status vault_system_delete(const char reference[65], int legacy) {
    secret_api api;bc_status status=open_api(&api,reference,legacy);if(status!=BC_OK)return status;
    void *error=NULL;api.clear(api.schema,api.attributes,NULL,&error);
    if(error){api.error_free(error);status=BC_IO_ERROR;}close_api(&api);return status;
}

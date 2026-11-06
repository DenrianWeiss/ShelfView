#include "bcontrol/aten.h"
#include "jar.h"
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>
struct bc_aten_identity { bc_jar_entry entries[2]; };
static int no_password(char *p,int n,int writing,void *user) {
    (void)p;(void)n;(void)writing;(void)user;return 0;
}
bc_status bc_aten_identity_extract(const uint8_t *jar,uint32_t size,bc_aten_identity **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;
    static const char *const names[]={"res/client.crt","res/client.key"};
    bc_aten_identity *identity=calloc(1,sizeof(*identity));if(!identity)return BC_NO_MEMORY;
    bc_status status=bc_jar_extract(jar,size,names,2,identity->entries);
    if(status==BC_OK) {
        bc_jar_entry *e=identity->entries;
        if(e[0].length>65536 || e[1].length>65536)status=BC_LIMIT_EXCEEDED;
        else {
            BIO *cb=BIO_new_mem_buf(e[0].data,(int)e[0].length),*kb=BIO_new_mem_buf(e[1].data,(int)e[1].length);
            X509 *cert=cb?PEM_read_bio_X509(cb,NULL,NULL,NULL):NULL;
            EVP_PKEY *key=kb?PEM_read_bio_PrivateKey(kb,NULL,no_password,NULL):NULL;
            if(!cert || !key || X509_check_private_key(cert,key)!=1)status=BC_PROTOCOL_ERROR;
            X509_free(cert);EVP_PKEY_free(key);BIO_free(cb);BIO_free(kb);ERR_clear_error();
        }
    }
    if(status==BC_OK)*out=identity;else bc_aten_identity_destroy(identity);
    return status;
}
bc_string bc_aten_identity_certificate(const bc_aten_identity *identity) {
    return identity?(bc_string){(const char *)identity->entries[0].data,identity->entries[0].length}:(bc_string){0};
}
bc_string bc_aten_identity_private_key(const bc_aten_identity *identity) {
    return identity?(bc_string){(const char *)identity->entries[1].data,identity->entries[1].length}:(bc_string){0};
}
void bc_aten_identity_destroy(bc_aten_identity *identity) {
    if(identity){bc_jar_entries_clear(identity->entries,2);free(identity);}
}

bc_status bc_aten_native_jar_media_layout(const uint8_t *jar,uint32_t size,uint32_t *out) {
    if(!out)return BC_INVALID_ARGUMENT;*out=0;
    static const char *const names[]={"libSharedLibrary64.so"};bc_jar_entry entry={0};
    bc_status status=bc_jar_extract(jar,size,names,1,&entry);
    if(status==BC_OK)status=bc_aten_native_media_layout(entry.data,entry.length,out);
    bc_jar_entries_clear(&entry,1);return status;
}

bc_status bc_aten_native_jar_mouse_bytes(const uint8_t *jar,uint32_t size,uint32_t *out) {
    if(!out)return BC_INVALID_ARGUMENT;*out=0;
    static const char *const names[]={"libiKVM64.so"};bc_jar_entry entry={0};
    bc_status status=bc_jar_extract(jar,size,names,1,&entry);
    if(status==BC_OK)status=bc_aten_native_mouse_bytes(entry.data,entry.length,out);
    bc_jar_entries_clear(&entry,1);return status;
}
bc_status bc_aten_native_jar_mouse_cipher(const uint8_t *jar,uint32_t size,uint32_t *out) {
    if(!out)return BC_INVALID_ARGUMENT;*out=0;
    static const char *const names[]={"libiKVM64.so"};bc_jar_entry entry={0};
    bc_status status=bc_jar_extract(jar,size,names,1,&entry);
    if(status==BC_OK)status=bc_aten_native_mouse_cipher(entry.data,entry.length,out);
    bc_jar_entries_clear(&entry,1);return status;
}

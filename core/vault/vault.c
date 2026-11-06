#include "vault_internal.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#define HEADER 224u
#define SLOT_TAG 208u
#define SALT 96u
#define WRAP_NONCE 112u
#define WRAPPED_KEY 124u
#define WRAP_TAG 156u
#define DATA_NONCE 172u
#define DATA_SIZE 184u
#define DATA_TAG 192u
#define KDF_LOG_N 17u
#define KDF_MAX_LOG_N 18u
#define KDF_MAX_MEMORY (320ull * 1024ull * 1024ull)
struct bc_vault {
    uint8_t header[HEADER], key[32];
    uint8_t *data, *cipher;
    uint32_t size;
    int dirty;
};
static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void write32(uint8_t *p, uint32_t value) {
    for (unsigned i=0;i<4;++i) p[i]=(uint8_t)(value>>(8*i));
}
static void write64(uint8_t *p, uint64_t value) {
    for (unsigned i=0;i<8;++i) p[i]=(uint8_t)(value>>(8*i));
}
static int bytes_valid(bc_bytes bytes) { return bytes.length<=BC_VAULT_MAX_BYTES && (!bytes.length || bytes.data); }
static void release_bytes(uint8_t *p, uint32_t size) { if(p){OPENSSL_cleanse(p,size);free(p);} }
static bc_status random_bytes(uint8_t *p, int size) { return RAND_bytes(p,size)==1 ? BC_OK : BC_IO_ERROR; }
static bc_status derive(const uint8_t *header, bc_string password, uint8_t key[32]) {
    if (!password.data || !password.length || password.length>4096) return BC_INVALID_ARGUMENT;
    uint32_t log_n=read32(header+80), r=read32(header+84), p=read32(header+88);
    if (log_n<15 || log_n>KDF_MAX_LOG_N || r!=8 || p!=1 || read32(header+92)) return BC_LIMIT_EXCEEDED;
    return EVP_PBE_scrypt(password.data,(size_t)password.length,header+SALT,16,1ull<<log_n,r,p,
        KDF_MAX_MEMORY,key,32)==1 ? BC_OK : BC_IO_ERROR;
}
static bc_status crypt(int encrypt, const uint8_t key[32], const uint8_t *nonce,
    const uint8_t *aad1, uint32_t aad1_size, const uint8_t *aad2, uint32_t aad2_size,
    const uint8_t *input, uint32_t size, uint8_t *output, uint8_t tag[16]) {
    EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new();
    if (!context) return BC_NO_MEMORY;
    int count=0, final=0;
    int ok=EVP_CipherInit_ex(context,EVP_aes_256_gcm(),NULL,NULL,NULL,encrypt)==1 &&
        EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_GCM_SET_IVLEN,12,NULL)==1 &&
        EVP_CipherInit_ex(context,NULL,NULL,key,nonce,encrypt)==1 &&
        EVP_CipherUpdate(context,NULL,&count,aad1,(int)aad1_size)==1 &&
        EVP_CipherUpdate(context,NULL,&count,aad2,(int)aad2_size)==1;
    if (ok && size) ok=EVP_CipherUpdate(context,output,&count,input,(int)size)==1 && count==(int)size;
    if (ok && !encrypt) ok=EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_GCM_SET_TAG,16,tag)==1;
    if (ok) ok=EVP_CipherFinal_ex(context,output+size,&final)==1 && final==0;
    if (ok && encrypt) ok=EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_GCM_GET_TAG,16,tag)==1;
    EVP_CIPHER_CTX_free(context);
    if (!ok) { OPENSSL_cleanse(output,size); return encrypt ? BC_IO_ERROR : BC_AUTHENTICATION_FAILED; }
    return BC_OK;
}
static bc_status slot_tag(const uint8_t header[HEADER], const uint8_t key[32], uint8_t tag[16]) {
    uint8_t input[140], digest[EVP_MAX_MD_SIZE];unsigned length=0;
    memcpy(input,header,48);memcpy(input+48,header+80,92);
    int ok=HMAC(EVP_sha256(),key,32,input,sizeof(input),digest,&length)!=NULL && length>=16;
    if(ok)memcpy(tag,digest,16);
    OPENSSL_cleanse(digest,sizeof(digest));OPENSSL_cleanse(input,sizeof(input));
    return ok?BC_OK:BC_IO_ERROR;
}
static bc_status wrap(uint8_t header[HEADER], const uint8_t data_key[32], bc_string password) {
    uint8_t derived[32]={0};
    bc_status status=random_bytes(header+SALT,16);
    if(status==BC_OK) status=random_bytes(header+WRAP_NONCE,12);
    write32(header+80,KDF_LOG_N);write32(header+84,8);write32(header+88,1);write32(header+92,0);
    if(status==BC_OK) status=derive(header,password,derived);
    if(status==BC_OK) status=crypt(1,derived,header+WRAP_NONCE,header,48,header+80,44,
        data_key,32,header+WRAPPED_KEY,header+WRAP_TAG);
    if(status==BC_OK)status=slot_tag(header,data_key,header+SLOT_TAG);
    OPENSSL_cleanse(derived,sizeof(derived));return status;
}
static bc_status allocate(uint32_t size, bc_vault **out) {
    bc_vault *v=calloc(1,sizeof(*v));if(!v)return BC_NO_MEMORY;
    v->size=size;v->data=malloc(size?size:1);v->cipher=malloc(size?size:1);
    if(!v->data||!v->cipher){bc_vault_destroy(v);return BC_NO_MEMORY;}
    *out=v;return BC_OK;
}
bc_status bc_vault_create(bc_bytes data, bc_string password, bc_vault **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;
    if(!bytes_valid(data))return BC_INVALID_ARGUMENT;
    bc_vault *v=NULL;bc_status status=allocate((uint32_t)data.length,&v);
    if(status!=BC_OK)return status;
    memcpy(v->header,"BCVAULT1",8);write32(v->header+8,1);write32(v->header+12,HEADER);
    status=random_bytes(v->header+16,48);
    if(status==BC_OK)status=random_bytes(v->key,32);
    if(status==BC_OK)status=wrap(v->header,v->key,password);
    if(status!=BC_OK){bc_vault_destroy(v);return status;}
    if(data.length)memcpy(v->data,data.data,(size_t)data.length);
    write64(v->header+DATA_SIZE,data.length);v->dirty=1;*out=v;return BC_OK;
}
static bc_status file_validate(bc_bytes file) {
    if(!file.data || file.length<HEADER || file.length>HEADER+(uint64_t)BC_VAULT_MAX_BYTES)return BC_INVALID_ARGUMENT;
    if(memcmp(file.data,"BCVAULT1",8)||read32(file.data+8)!=1)return BC_UNSUPPORTED;
    if(read32(file.data+12)!=HEADER || read32(file.data+DATA_SIZE+4) ||
        read32(file.data+DATA_SIZE)!=file.length-HEADER)return BC_PROTOCOL_ERROR;
    return BC_OK;
}
static void info_copy(const uint8_t *header, uint32_t size, bc_vault_info *out) {
    out->version=1;memcpy(out->vault_id,header+16,16);memcpy(out->key_id,header+32,16);
    memcpy(out->revision,header+48,16);memcpy(out->parent_revision,header+64,16);out->data_size=size;
}
bc_status bc_vault_file_info(bc_bytes file, bc_vault_info *out) {
    if(!out||out->struct_size!=sizeof(*out))return BC_INVALID_ARGUMENT;
    bc_status status=file_validate(file);if(status!=BC_OK)return status;
    info_copy(file.data,(uint32_t)(file.length-HEADER),out);return BC_OK;
}
static bc_status open_file(bc_bytes file, bc_bytes key, bc_string password, int use_password, bc_vault **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;
    bc_status validated=file_validate(file);if(validated!=BC_OK)return validated;
    if(!use_password && (!key.data||key.length!=32))return BC_INVALID_ARGUMENT;
    bc_vault *v=NULL;bc_status status=allocate((uint32_t)(file.length-HEADER),&v);
    if(status!=BC_OK)return status;
    memcpy(v->header,file.data,HEADER);
    if(use_password){
        uint8_t derived[32]={0};status=derive(v->header,password,derived);
        if(status==BC_OK)status=crypt(0,derived,v->header+WRAP_NONCE,v->header,48,v->header+80,44,
            v->header+WRAPPED_KEY,32,v->key,v->header+WRAP_TAG);
        OPENSSL_cleanse(derived,sizeof(derived));
    } else memcpy(v->key,key.data,32);
    if(status==BC_OK){
        uint8_t tag[16];status=slot_tag(v->header,v->key,tag);
        if(status==BC_OK && CRYPTO_memcmp(tag,v->header+SLOT_TAG,16))status=BC_AUTHENTICATION_FAILED;
        OPENSSL_cleanse(tag,sizeof(tag));
    }
    if(status==BC_OK)status=crypt(0,v->key,v->header+DATA_NONCE,v->header,80,v->header+DATA_NONCE,20,
        file.data+HEADER,v->size,v->data,v->header+DATA_TAG);
    if(status!=BC_OK){bc_vault_destroy(v);return status;}
    if(v->size)memcpy(v->cipher,file.data+HEADER,v->size);
    *out=v;return BC_OK;
}
bc_status bc_vault_open_password(bc_bytes file, bc_string password, bc_vault **out) {
    return open_file(file,(bc_bytes){NULL,0},password,1,out);
}
bc_status bc_vault_open_key(bc_bytes file, bc_bytes key, bc_vault **out) {
    return open_file(file,key,(bc_string){NULL,0},0,out);
}
int vault_direct_child(const bc_vault *a,const bc_vault *b) {
    return a&&b&&!CRYPTO_memcmp(a->header+16,b->header+16,32)&&
        !CRYPTO_memcmp(a->header+48,b->header+64,16)&&CRYPTO_memcmp(a->header+48,b->header+48,16)&&
        !CRYPTO_memcmp(a->header+SLOT_TAG,b->header+SLOT_TAG,16);
}
bc_status vault_replace_selected(bc_vault *target,const bc_vault *source) {
    if(!target||!source||CRYPTO_memcmp(target->header+16,source->header+16,32)||CRYPTO_memcmp(target->key,source->key,32))return BC_INVALID_ARGUMENT;
    bc_status status=bc_vault_replace(target,bc_vault_data(source));
    if(status==BC_OK&&target!=source){memcpy(target->header+80,source->header+80,92);memcpy(target->header+SLOT_TAG,source->header+SLOT_TAG,16);}
    return status;
}
bc_status bc_vault_file_direct_child(bc_bytes parent,bc_bytes child,bc_bytes key,int *direct) {
    if(!direct)return BC_INVALID_ARGUMENT;
    *direct=0;bc_vault *a=NULL,*b=NULL;
    bc_status status=bc_vault_open_key(parent,key,&a);
    if(status==BC_OK)status=bc_vault_open_key(child,key,&b);
    if(status==BC_OK)*direct=vault_direct_child(a,b);
    bc_vault_destroy(a);bc_vault_destroy(b);return status;
}
bc_status bc_vault_info_get(const bc_vault *v, bc_vault_info *out) {
    if(!v||!out||out->struct_size!=sizeof(*out))return BC_INVALID_ARGUMENT;
    info_copy(v->header,v->size,out);return BC_OK;
}
bc_bytes bc_vault_data(const bc_vault *v) { return v?(bc_bytes){v->data,v->size}:(bc_bytes){NULL,0}; }
bc_status bc_vault_key_copy(const bc_vault *v, uint8_t *out, uint32_t capacity) {
    if(!v||!out)return BC_INVALID_ARGUMENT;
    if(capacity<32)return BC_LIMIT_EXCEEDED;
    memcpy(out,v->key,32);return BC_OK;
}
bc_status bc_vault_replace(bc_vault *v, bc_bytes data) {
    if(!v||!bytes_valid(data))return BC_INVALID_ARGUMENT;
    uint8_t revision[16];bc_status status=random_bytes(revision,16);if(status!=BC_OK)return status;
    uint8_t *plain=malloc(data.length?(size_t)data.length:1),*cipher=malloc(data.length?(size_t)data.length:1);
    if(!plain||!cipher){free(plain);free(cipher);return BC_NO_MEMORY;}
    if(data.length)memcpy(plain,data.data,(size_t)data.length);
    release_bytes(v->data,v->size);release_bytes(v->cipher,v->size);
    v->data=plain;v->cipher=cipher;v->size=(uint32_t)data.length;v->dirty=1;
    memcpy(v->header+64,v->header+48,16);memcpy(v->header+48,revision,16);write64(v->header+DATA_SIZE,data.length);return BC_OK;
}
bc_status bc_vault_change_password(bc_vault *v, bc_string password) {
    if(!v)return BC_INVALID_ARGUMENT;
    uint8_t header[HEADER];memcpy(header,v->header,HEADER);
    bc_status status=wrap(header,v->key,password);
    if(status==BC_OK)memcpy(v->header,header,HEADER);
    OPENSSL_cleanse(header,sizeof(header));return status;
}
bc_status bc_vault_export(bc_vault *v, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if(!v||!written)return BC_INVALID_ARGUMENT;
    *written=HEADER+v->size;
    if(!out||capacity<*written)return BC_LIMIT_EXCEEDED;
    if(v->dirty){
        bc_status status=random_bytes(v->header+DATA_NONCE,12);
        if(status==BC_OK)status=crypt(1,v->key,v->header+DATA_NONCE,v->header,80,v->header+DATA_NONCE,20,
            v->data,v->size,v->cipher,v->header+DATA_TAG);
        if(status!=BC_OK){*written=0;return status;}
        v->dirty=0;
    }
    memcpy(out,v->header,HEADER);if(v->size)memcpy(out+HEADER,v->cipher,v->size);return BC_OK;
}
void bc_vault_destroy(bc_vault *v) {
    if(!v)return;
    release_bytes(v->data,v->size);release_bytes(v->cipher,v->size);OPENSSL_cleanse(v,sizeof(*v));free(v);
}

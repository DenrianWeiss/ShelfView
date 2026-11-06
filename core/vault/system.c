#include "system_internal.h"
#include <openssl/crypto.h>
#include <string.h>
static int reference_copy(bc_string input, char output[65]) {
    if(!input.data||input.length!=64)return 0;
    for(unsigned i=0;i<64;++i){char c=input.data[i];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return 0;output[i]=c;}
    output[64]=0;return 1;
}
bc_status bc_vault_system_key_read(bc_string reference, uint8_t *key, uint32_t capacity, int *found, uint32_t *flags) {
    if(found)*found=0;
    if(flags)*flags=0;
    if(!key||!found||!flags)return BC_INVALID_ARGUMENT;
    if(capacity<32)return BC_LIMIT_EXCEEDED;
    memset(key,0,32);char name[65];if(!reference_copy(reference,name))return BC_INVALID_ARGUMENT;
    uint8_t temporary[32]={0};int present=0;uint32_t mode=0;
    bc_status status=vault_system_read(name,0,temporary,&present,&mode);
    if(status==BC_OK&&!present){
        status=vault_system_read(name,1,temporary,&present,&mode);
        if(status==BC_OK&&present){
            // Keep the original available for rollback and retry if the new store is unavailable.
            uint32_t migrated=0;
            if(bc_vault_system_key_store(reference,(bc_bytes){temporary,32},
                    !!(mode&BC_VAULT_KEY_ROAMING_ELIGIBLE),&migrated)==BC_OK)
                mode=migrated;
        }
    }
    if(status==BC_OK&&present){memcpy(key,temporary,32);*found=1;*flags=mode;}
    OPENSSL_cleanse(temporary,sizeof(temporary));return status;
}
bc_status bc_vault_system_key_store(bc_string reference, bc_bytes key, int roaming, uint32_t *flags) {
    if(flags)*flags=0;
    char name[65];if(!flags||!key.data||key.length!=32||!(roaming==0||roaming==1)||!reference_copy(reference,name))return BC_INVALID_ARGUMENT;
    uint32_t stored=0;bc_status status=vault_system_store(name,key.data,roaming,&stored);
    uint8_t readback[32]={0};int found=0;uint32_t observed=0;
    if(status==BC_OK){
        status=vault_system_read(name,0,readback,&found,&observed);
        if(status==BC_OK&&(!found||CRYPTO_memcmp(key.data,readback,32)))status=BC_OUTCOME_UNKNOWN;
    }
    OPENSSL_cleanse(readback,sizeof(readback));if(status==BC_OK)*flags=observed;
    return status;
}
bc_status bc_vault_system_key_delete(bc_string reference) {
    char name[65];if(!reference_copy(reference,name))return BC_INVALID_ARGUMENT;
    bc_status legacy=vault_system_delete(name,1);
    if(legacy!=BC_OK)return legacy;
    return vault_system_delete(name,0);
}

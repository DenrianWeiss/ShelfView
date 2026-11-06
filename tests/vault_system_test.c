#include "bcontrol/vault_system.h"
#include <assert.h>
#include <string.h>
static uint8_t saved[2][32];static int present[2],corrupt,write_blocked;static unsigned reads;
bc_status vault_system_read(const char reference[65],int legacy,uint8_t key[32],int *found,uint32_t *flags) {
    (void)reference;++reads;*found=present[legacy];if(*found){memcpy(key,saved[legacy],32);if(corrupt)key[0]^=1;*flags=BC_VAULT_KEY_LOCAL;}return BC_OK;
}
bc_status vault_system_store(const char reference[65],const uint8_t key[32],int roaming,uint32_t *flags) {
    (void)reference;(void)roaming;if(write_blocked)return BC_BUSY;
    memcpy(saved[0],key,32);present[0]=1;*flags=BC_VAULT_KEY_LOCAL;return BC_OK;
}
bc_status vault_system_delete(const char reference[65],int legacy){(void)reference;present[legacy]=0;return BC_OK;}
int main(void) {
    const char *name="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    bc_string reference={name,64};uint8_t key[32]={9},out[32];int found=1;uint32_t flags=99;
    assert(bc_vault_system_key_read(reference,out,32,&found,&flags)==BC_OK&&!found&&!flags);
    memcpy(saved[1],key,32);present[1]=1;write_blocked=1;
    assert(bc_vault_system_key_read(reference,out,32,&found,&flags)==BC_OK&&found&&!memcmp(key,out,32)&&!present[0]);
    write_blocked=0;
    assert(bc_vault_system_key_read(reference,out,32,&found,&flags)==BC_OK&&found&&present[0]&&present[1]);
    saved[1][0]^=1;
    assert(bc_vault_system_key_store(reference,(bc_bytes){key,32},1,&flags)==BC_OK&&flags==BC_VAULT_KEY_LOCAL);
    assert(bc_vault_system_key_read(reference,out,32,&found,&flags)==BC_OK&&found&&!memcmp(key,out,32));
    corrupt=1;assert(bc_vault_system_key_store(reference,(bc_bytes){key,32},1,&flags)==BC_OUTCOME_UNKNOWN&&!flags);
    unsigned before=reads;
    assert(bc_vault_system_key_read((bc_string){"../invalid",10},out,32,&found,&flags)==BC_INVALID_ARGUMENT&&!found&&!flags&&reads==before);
    assert(bc_vault_system_key_delete(reference)==BC_OK&&!present[0]&&!present[1]);
    return 0;
}

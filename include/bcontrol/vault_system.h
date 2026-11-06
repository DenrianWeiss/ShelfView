#ifndef BCONTROL_VAULT_SYSTEM_H
#define BCONTROL_VAULT_SYSTEM_H
#include "vault.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_VAULT_KEY_LOCAL 1u
/* The item permits native roaming. This does not attest account sync state. */
#define BC_VAULT_KEY_ROAMING_ELIGIBLE 2u
/* reference is the 64 lowercase hex digits of vault_id followed by key_id.
 * These calls may invoke system authorization; schedule off the UI thread.
 * Missing items return OK/found=0; unavailable providers return UNSUPPORTED. */
BC_VAULT_API bc_status bc_vault_system_key_read(bc_string reference, uint8_t *key, uint32_t capacity,
    int *found, uint32_t *flags);
BC_VAULT_API bc_status bc_vault_system_key_store(bc_string reference, bc_bytes key, int allow_roaming, uint32_t *flags);
BC_VAULT_API bc_status bc_vault_system_key_delete(bc_string reference);
#ifdef __cplusplus
}
#endif
#endif

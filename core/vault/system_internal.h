#ifndef BC_VAULT_SYSTEM_INTERNAL_H
#define BC_VAULT_SYSTEM_INTERNAL_H
#include "bcontrol/vault_system.h"
bc_status vault_system_read(const char reference[65], int legacy, uint8_t key[32], int *found, uint32_t *flags);
bc_status vault_system_store(const char reference[65], const uint8_t key[32], int roaming, uint32_t *flags);
bc_status vault_system_delete(const char reference[65], int legacy);
#endif

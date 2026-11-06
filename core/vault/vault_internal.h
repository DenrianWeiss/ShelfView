#ifndef BC_VAULT_INTERNAL_H
#define BC_VAULT_INTERNAL_H
#include "bcontrol/vault.h"
int vault_direct_child(const bc_vault *, const bc_vault *);
bc_status vault_replace_selected(bc_vault *, const bc_vault *);
#endif

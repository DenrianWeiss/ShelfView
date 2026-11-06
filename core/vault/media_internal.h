#ifndef BCONTROL_VAULT_MEDIA_INTERNAL_H
#define BCONTROL_VAULT_MEDIA_INTERNAL_H
#include "bcontrol/vault_media.h"
#define VAULT_MEDIA_ALIASES 8u
struct bc_vault_media_scope {
    char ids[VAULT_MEDIA_ALIASES][77]; unsigned count;
    char vault_id[33];
    char owned[33],observed[33]; int observed_pending,observed_legacy;
};
#endif

#ifndef BCONTROL_VAULT_H
#define BCONTROL_VAULT_H
#include "bcontrol.h"
#if defined(_WIN32)
# ifdef BC_VAULT_BUILD
#  define BC_VAULT_API __declspec(dllexport)
# else
#  define BC_VAULT_API __declspec(dllimport)
# endif
#else
# define BC_VAULT_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define BC_VAULT_KEY_BYTES 32u
#define BC_VAULT_ID_BYTES 16u
#define BC_VAULT_MAX_BYTES (64u * 1024u * 1024u)
typedef struct bc_vault bc_vault;
typedef struct {
    uint32_t struct_size, version;
    uint8_t vault_id[16], key_id[16], revision[16], parent_revision[16];
    uint64_t data_size;
} bc_vault_info;
/* Platform code owns file coordination and system key storage. These calls do
 * no I/O. Serialize access to a handle; all returned views expire on mutation. */
BC_VAULT_API bc_status bc_vault_create(bc_bytes data, bc_string master_password, bc_vault **);
BC_VAULT_API bc_status bc_vault_open_password(bc_bytes file, bc_string master_password, bc_vault **);
BC_VAULT_API bc_status bc_vault_open_key(bc_bytes file, bc_bytes key, bc_vault **);
/* Unauthenticated identifiers for locating a system key, never authorization.
 * A successful open still must verify the complete encrypted document. */
BC_VAULT_API bc_status bc_vault_file_info(bc_bytes file, bc_vault_info *);
BC_VAULT_API bc_status bc_vault_info_get(const bc_vault *, bc_vault_info *);
/* Authenticates both files with the data key. Only a payload revision whose
 * parent is exactly the supplied revision and whose unlock slot is unchanged
 * qualifies. A password rewrap or unrelated version returns direct=0. */
BC_VAULT_API bc_status bc_vault_file_direct_child(bc_bytes parent, bc_bytes child,
    bc_bytes data_key, int *direct);
BC_VAULT_API bc_bytes bc_vault_data(const bc_vault *);
/* Copies the data key only for the platform's protected key-store adapter. */
BC_VAULT_API bc_status bc_vault_key_copy(const bc_vault *, uint8_t *, uint32_t capacity);
BC_VAULT_API bc_status bc_vault_replace(bc_vault *, bc_bytes data);
/* Rewraps the existing data key. Unchanged payload ciphertext is preserved. */
BC_VAULT_API bc_status bc_vault_change_password(bc_vault *, bc_string master_password);
/* Query size with NULL/0. No partial file is returned on failure. The platform
 * commits encrypted output atomically and checks its expected disk revision. */
BC_VAULT_API bc_status bc_vault_export(bc_vault *, uint8_t *, uint32_t capacity, uint32_t *written);
BC_VAULT_API void bc_vault_destroy(bc_vault *);
#ifdef __cplusplus
}
#endif
#endif

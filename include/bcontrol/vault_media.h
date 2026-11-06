#ifndef BCONTROL_VAULT_MEDIA_H
#define BCONTROL_VAULT_MEDIA_H
#include "vault_merge.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_vault_media_scope bc_vault_media_scope;
#define BC_VAULT_MEDIA_BEGIN 1u
#define BC_VAULT_MEDIA_CLEAR 2u
#define BC_VAULT_MEDIA_IMPORT_PENDING 3u
#define BC_VAULT_MEDIA_ACKNOWLEDGE 4u
#define BC_VAULT_MEDIA_CLEAR_OBSERVED 5u
/* Identity is bound to management origin and exact username. Legacy textual
 * origin aliases are read only until a canonical record has been committed. */
BC_VAULT_API bc_status bc_vault_media_scope_create(bc_string address, bc_string username, bc_vault_media_scope **);
BC_VAULT_API bc_string bc_vault_media_scope_id(const bc_vault_media_scope *);
BC_VAULT_API void bc_vault_media_scope_destroy(bc_vault_media_scope *);
BC_VAULT_API bc_status bc_vault_media_scope_read(bc_vault_media_scope *, bc_bytes snapshot, int *known, int *pending);
/* Independent observation for one readback; other scope reads cannot replace
 * its expected operation while the platform awaits a network response. */
BC_VAULT_API bc_status bc_vault_media_scope_observe(const bc_vault_media_scope *, bc_bytes snapshot,
    bc_vault_media_scope **observation, int *known, int *pending);
/* BEGIN rejects pending local recovery and all uncleared remote records in the
 * same scope, including settled mounts. CLEAR requires confirmed removal;
 * ACKNOWLEDGE is explicit operator confirmation. IMPORT preserves decisions.
 * The recovery object is atomic during field merging; its random operation ID
 * prevents a stale clear from erasing a later mount, independent of clocks. */
/* CLEAR_OBSERVED requires a complete empty-device readback after scope_read,
 * without a local source. It checks the observed operation, not an old owner. */
/* Scope reads remember the observed operation; BEGIN owns a fresh operation.
 * CLEAR refuses to erase a replacement. ACKNOWLEDGE is explicit human input.
 * First use binds the scope to its Vault ID. Use one scope on its owner lane,
 * and discard it with its storage session. */
BC_VAULT_API bc_status bc_vault_media_scope_patch(bc_vault_media_scope *, bc_bytes snapshot,
    uint32_t operation, uint64_t modified_at_ms, bc_vault_merge **);
/* Batch legacy identities; duplicate IDs are harmless, decisions and tombstones
 * are retained, and no partially prepared result is returned on failure. */
BC_VAULT_API bc_status bc_vault_media_import_pending(bc_bytes snapshot, const bc_string *record_ids,
    uint32_t count, uint64_t modified_at_ms, bc_vault_merge **);
/* Remote writes are one atomic record per scope and slot. A random operation
 * ID is required for every update, so a late result cannot replace a new write.
 * References are opaque bytes (base64 in the exported JSON). List omits cleared
 * entries. SETTLED insertion remains recorded across application shutdown. */
#define BC_VAULT_REMOTE_INSERT 1u
#define BC_VAULT_REMOTE_EJECT 2u
#define BC_VAULT_REMOTE_SUBMITTING 1u
#define BC_VAULT_REMOTE_ACCEPTED 2u
#define BC_VAULT_REMOTE_SETTLED 3u
#define BC_VAULT_REMOTE_CLEARED 4u
BC_VAULT_API bc_status bc_vault_media_remote_list(bc_vault_media_scope *, bc_bytes snapshot,
    unsigned char *output, uint32_t capacity, uint32_t *written);
/* Insertion is fenced by local recovery. Ejection remains available for explicit
 * cleanup, without clearing the local recovery marker.
 * SUBMITTING starts a fresh generation and refuses unresolved remote writes. Other
 * phases compare expected_operation_id. CLEARED requires confirmed removal or
 * a definitive failure before submission; time alone is never sufficient. */
BC_VAULT_API bc_status bc_vault_media_remote_patch(bc_vault_media_scope *, bc_bytes snapshot,
    bc_string media_uri, bc_string expected_operation_id, uint32_t action, uint32_t phase,
    bc_bytes reference, uint64_t modified_at_ms, bc_vault_merge **);
/* Only for a definitive rejection or failure before submission, while still
 * SUBMITTING. Restores an ejected insertion with a fresh generation, including
 * its source/task evidence; otherwise clears the rejected operation. */
BC_VAULT_API bc_status bc_vault_media_remote_reject(bc_vault_media_scope *, bc_bytes snapshot,
    bc_string media_uri, bc_string expected_operation_id, uint64_t modified_at_ms, bc_vault_merge **);
#define BC_VAULT_SOURCE_UNKNOWN 0u
#define BC_VAULT_SOURCE_VERIFIED 1u
#define BC_VAULT_SOURCE_UNVERIFIED 2u
#define BC_VAULT_SOURCE_MISMATCH 3u
/* Persist only a digest of the requested source, together with the new generation. */
BC_VAULT_API bc_status bc_vault_media_remote_begin(bc_vault_media_scope *, bc_bytes snapshot,
    bc_string media_uri, bc_string expected_operation_id, uint32_t action, bc_string source_uri,
    uint64_t modified_at_ms, bc_vault_merge **);
/* inserted is 1 only after an explicit inserted readback; 0 is not removal
 * proof. completed is 1 only after a synchronous acknowledgement or a verified
 * successful terminal task. The acknowledgement survives delayed readback. Missing
 * source metadata is unverified; a differing source never settles the operation.
 * Rechecks the generation and refuses cleared records. No source URL is saved. */
BC_VAULT_API bc_status bc_vault_media_remote_observe_source(bc_vault_media_scope *, bc_bytes snapshot,
    bc_string media_uri, bc_string expected_operation_id, bc_string reported_source, uint32_t completed, uint32_t inserted,
    uint64_t modified_at_ms, bc_vault_merge **);
#ifdef __cplusplus
}
#endif
#endif

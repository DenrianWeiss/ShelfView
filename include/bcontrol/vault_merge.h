#ifndef BCONTROL_VAULT_MERGE_H
#define BCONTROL_VAULT_MERGE_H
#include "vault.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_vault_merge bc_vault_merge;
#define BC_VAULT_MERGE_BASE 1u
#define BC_VAULT_MERGE_LOCAL 2u
#define BC_VAULT_MERGE_REMOTE 3u
/* Three authenticated snapshots sharing an explicitly established common base.
 * Schema: {version:1,vault_id:hex32,records:{id:{fields:{...},deleted:bool,
 * modified_at_ms:uint}}}. Nested field values are atomic (e.g. credentials).
 * Timestamps are display hints and never select a winning value. */
/* Patch only supplied fields, preserving fields owned by other frontends.
 * Delete clears the record's fields and retains a timestamped tombstone. */
/* Batch patches use {record_id:{fields,deleted,modified_at_ms},...}. */
BC_VAULT_API bc_status bc_vault_records_patch(bc_bytes snapshot, bc_bytes patches, bc_vault_merge **);
BC_VAULT_API bc_status bc_vault_record_patch(bc_bytes snapshot, bc_string record_id, bc_bytes fields,
    int deleted, uint64_t modified_at_ms, bc_vault_merge **);
BC_VAULT_API bc_status bc_vault_merge_create(bc_bytes base, bc_bytes local, bc_bytes remote, bc_vault_merge **);
BC_VAULT_API uint32_t bc_vault_merge_conflicts(const bc_vault_merge *);
BC_VAULT_API uint32_t bc_vault_merge_pending(const bc_vault_merge *);
/* Borrowed JSON with record/field and present/value variants. Read only on the
 * owner lane; invalidated by the next conflict query, resolution or destroy. */
BC_VAULT_API bc_status bc_vault_merge_conflict(bc_vault_merge *, uint32_t index, bc_bytes *);
BC_VAULT_API bc_status bc_vault_merge_resolve(bc_vault_merge *, uint32_t index, uint32_t choice);
/* No result can be committed while any conflict remains unresolved. */
BC_VAULT_API bc_status bc_vault_merge_export(bc_vault_merge *, uint8_t *, uint32_t capacity, uint32_t *written);
BC_VAULT_API void bc_vault_merge_destroy(bc_vault_merge *);
/* Conflict review owns authenticated versions. Only direct children with the
 * same unlock slot allow per-field choices. Other versions require a complete
 * local/current selection. The platform commits against the exact current file
 * used here, after stopping dependent sessions. */
typedef struct bc_vault_conflict bc_vault_conflict;
BC_VAULT_API bc_status bc_vault_conflict_create(bc_bytes base, bc_bytes local, bc_bytes current,
    bc_bytes data_key, bc_vault_conflict **);
BC_VAULT_API int bc_vault_conflict_fields(const bc_vault_conflict *);
BC_VAULT_API uint32_t bc_vault_conflict_count(const bc_vault_conflict *);
/* Borrowed presentation JSON. Secret variants and compound values are masked;
 * kinds: 0 absent, 1 scalar text, 2 secret, 3 compound, 4 deleted record. */
BC_VAULT_API bc_status bc_vault_conflict_field(bc_vault_conflict *, uint32_t index, bc_bytes *);
BC_VAULT_API bc_status bc_vault_conflict_resolve(bc_vault_conflict *, uint32_t index, uint32_t choice);
BC_VAULT_API bc_status bc_vault_conflict_select(bc_vault_conflict *, uint32_t choice);
BC_VAULT_API bc_status bc_vault_conflict_export(bc_vault_conflict *, uint8_t *, uint32_t, uint32_t *);
BC_VAULT_API void bc_vault_conflict_destroy(bc_vault_conflict *);
#ifdef __cplusplus
}
#endif
#endif

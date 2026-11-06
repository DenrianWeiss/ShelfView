#ifndef BCONTROL_IPMI_SEL_H
#define BCONTROL_IPMI_SEL_H
#include "ipmi_session.h"
#ifdef __cplusplus
extern "C" {
#endif

#define BC_IPMI_SEL_RECORD_MAX 16u
#define BC_IPMI_MAX_SEL_ENTRIES 128u
#define BC_IPMI_SEL_TRUNCATED 1u
#define BC_IPMI_SEL_ENTRY_TIMESTAMP_PRESENT 1u

typedef struct {
    uint32_t struct_size, abi_version;
    uint8_t version;
    uint32_t record_count;
    uint32_t free_space;
    uint32_t addition_timestamp;
    uint32_t erase_timestamp;
    uint8_t operation_support;
    uint8_t reserve_supported;
    uint8_t overflow;
    uint8_t reserved[5];
} bc_ipmi_sel_info;

typedef struct {
    uint32_t struct_size, abi_version;
    bc_status status;
    uint16_t record_id;
    uint8_t record_type;
    uint8_t flags;
    uint32_t timestamp;
    uint8_t raw_length;
    uint8_t reserved[3];
    uint8_t raw[BC_IPMI_SEL_RECORD_MAX];
} bc_ipmi_sel_entry;

typedef struct {
    uint32_t struct_size, abi_version;
    bc_status status;
    uint32_t flags;
    bc_ipmi_sel_info info;
    uint32_t count;
    bc_ipmi_sel_entry entries[BC_IPMI_MAX_SEL_ENTRIES];
} bc_ipmi_sel_log;

/* Parse a raw Get SEL Info response (15 data bytes). */
BC_IPMI_API bc_status bc_ipmi_sel_info_parse(bc_bytes response, bc_ipmi_sel_info *);
/* Parse one complete SEL record (record ID included, up to 16 bytes).
 * Undecodable content is preserved in raw with an explicit status; no event meaning is inferred. */
BC_IPMI_API bc_status bc_ipmi_sel_entry_parse(bc_bytes record, bc_ipmi_sel_entry *);
BC_IPMI_API bc_status bc_ipmi_sel_info_get(bc_ipmi_session *, bc_ipmi_sel_info *);
/* Read-only whole-log traversal with reservation recovery. Per-entry errors stay in
 * entries[].status and valid records already read are preserved. Timestamps are raw
 * IPMI minutes since 1995-01-01, present for system event and timestamped OEM records.
 * The log is a plain copyable value; no destroy. Serialize session use across threads. */
BC_IPMI_API bc_status bc_ipmi_sel_log_get(bc_ipmi_session *, bc_ipmi_sel_log *);
#ifdef __cplusplus
}
#endif
#endif

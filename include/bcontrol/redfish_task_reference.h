#ifndef BCONTROL_REDFISH_TASK_REFERENCE_H
#define BCONTROL_REDFISH_TASK_REFERENCE_H
#include "redfish.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_REDFISH_TASK_REFERENCE_MAX 8192u
#define BC_REDFISH_TASK_REFERENCE_INSERT 1u
#define BC_REDFISH_TASK_REFERENCE_EJECT 2u
/* Identity metadata only. Matching is not a guarantee of identity across service
 * resets; callers must not use it alone to clear an unresolved write. */
typedef struct {
    uint32_t struct_size;
    uint32_t action;
    uint32_t http_method;
    uint32_t reserved;
    bc_string endpoint_id;
    bc_string address_digest;
    bc_string collection_uri;
    bc_string media_uri;
    bc_string target_uri;
} bc_redfish_task_binding;
typedef struct {
    uint32_t struct_size;
    uint32_t action;
    uint32_t http_method;
    uint32_t reserved;
    char endpoint_id[37];
    char address_digest[65];
    char collection_uri[1024];
    char media_uri[1024];
    char target_uri[1024];
    char task_uri[1024];
    char task_id[129];
    char start_time[65];
} bc_redfish_task_reference;
BC_REDFISH_API bc_status bc_redfish_task_reference_export(bc_bytes task_json, const bc_redfish_task_binding *, unsigned char *, uint32_t, uint32_t *);
BC_REDFISH_API bc_status bc_redfish_task_reference_import(bc_bytes saved_json, const bc_redfish_task_binding *, bc_redfish_task_reference *);
BC_REDFISH_API bc_status bc_redfish_task_reference_match(const bc_redfish_task_reference *, bc_bytes task_json, uint32_t *task_flags);
/* Both operations must be completed on the same current endpoint revision.
 * The discovery operation must follow the advertised Root/TaskService chain. */
BC_REDFISH_API bc_status bc_redfish_task_reference_export_operation(const bc_redfish_operation *media_write, const bc_redfish_operation *task_discovery, bc_string endpoint_id, bc_string address_digest, unsigned char *, uint32_t, uint32_t *);
BC_REDFISH_API bc_status bc_redfish_task_reference_capture_operation(const bc_redfish_operation *media_write, const bc_redfish_operation *task_discovery, bc_string endpoint_id, bc_string address_digest, bc_redfish_task_reference *, unsigned char *, uint32_t, uint32_t *);
BC_REDFISH_API bc_status bc_redfish_task_reference_restore_operation(bc_bytes saved, const bc_redfish_operation *media_read, const bc_redfish_operation *task_discovery, bc_string endpoint_id, bc_string address_digest, uint32_t action, bc_redfish_task_reference *);
BC_REDFISH_API bc_status bc_redfish_task_reference_match_operation(const bc_redfish_task_reference *, const bc_redfish_operation *task_read, const bc_redfish_operation *task_discovery, bc_string endpoint_id, bc_string address_digest, uint32_t *task_flags);
#ifdef __cplusplus
}
#endif
#endif

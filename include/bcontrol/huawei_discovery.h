#ifndef BCONTROL_HUAWEI_DISCOVERY_H
#define BCONTROL_HUAWEI_DISCOVERY_H
#include "console_discovery.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_HUAWEI_MODE_SHARED 1u
#define BC_HUAWEI_MODE_PRIVATE 2u
#define BC_HUAWEI_SESSIONS_PRESENT 1u
#define BC_HUAWEI_SESSION_LIMIT_PRESENT 2u
#define BC_HUAWEI_SESSION_MODE_PRESENT 4u
#define BC_HUAWEI_AUTO_LOCK_PRESENT 8u
#define BC_HUAWEI_PARAMETER_MODE 1u
#define BC_HUAWEI_PARAMETER_TYPE 2u
#define BC_HUAWEI_PARAMETER_CONTENT 4u
typedef struct {
    uint32_t struct_size, flags, sessions, session_limit, session_mode, auto_lock;
    char export_uri[1025], action_info_uri[1025];
} bc_huawei_kvm_resource;
typedef struct {
    uint32_t struct_size, parameters, required, modes;
} bc_huawei_kvm_action_info;
typedef struct {
    uint32_t struct_size;
    char uri[1025], action_info_uri[1025];
} bc_huawei_download_action;
/* Reads only Actions.Oem.Huawei.#Manager.GeneralDownload advertised by this
 * Manager; an absent action is UNSUPPORTED. It does not submit a request. */
BC_DISCOVERY_API bc_status bc_huawei_manager_download_parse(const uint8_t *, uint32_t,
    bc_string manager_uri, bc_huawei_download_action *);
/* Metadata only: no authentication, launch, profile evidence or protocol selection.
 * Caller binds these snapshots to the original endpoint and connection generation. */
BC_DISCOVERY_API bc_status bc_huawei_kvm_resource_parse(const uint8_t *, uint32_t,
    bc_string resource_uri, bc_huawei_kvm_resource *);
BC_DISCOVERY_API bc_status bc_huawei_kvm_action_info_parse(const uint8_t *, uint32_t,
    bc_huawei_kvm_action_info *);
#ifdef __cplusplus
}
#endif
#endif

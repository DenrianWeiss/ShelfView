#ifndef BCONTROL_LOG_H
#define BCONTROL_LOG_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Runtime levels are cumulative: DEBUG includes ERROR/WARN/INFO. VERBOSE is
 * an explicit request-detail level for sanitized Redfish bodies and IPMI
 * selected read-only command bytes; it is not enabled by DEBUG or TRACE.
 * Unknown or mutating IPMI payloads are omitted. */
#define BC_LOG_LEVEL_OFF 0u
#define BC_LOG_LEVEL_ERROR 1u
#define BC_LOG_LEVEL_WARN 2u
#define BC_LOG_LEVEL_INFO 3u
#define BC_LOG_LEVEL_DEBUG 4u
#define BC_LOG_LEVEL_TRACE 5u
#define BC_LOG_LEVEL_VERBOSE 6u

#define BC_LOG_CATEGORY_LIFECYCLE 1u
#define BC_LOG_CATEGORY_HTTP 2u
#define BC_LOG_CATEGORY_TLS 4u
#define BC_LOG_CATEGORY_REDFISH 8u
#define BC_LOG_CATEGORY_IPMI 16u
#define BC_LOG_CATEGORY_KVM 32u
#define BC_LOG_CATEGORY_MEDIA 64u
#define BC_LOG_CATEGORY_VENDOR 128u
#define BC_LOG_CATEGORY_ALL 0xffffffffu

typedef struct {
    uint32_t struct_size;
    uint32_t level;
    uint32_t category;
    bc_string event;
    bc_string detail;
} bc_log_record;

/* Called synchronously on the logging thread. event/detail are borrowed only
 * for the duration of the call. A sink must not reconfigure logging or call
 * back into the core. */
typedef void (*bc_log_sink)(void *userdata, const bc_log_record *record);

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t level;
    uint32_t categories;
    bc_log_sink sink;
    void *userdata;
    uint32_t reserved;
} bc_log_options;

/* Process-wide and disabled by default. Configure before creating contexts,
 * endpoints or sessions. Reconfiguration is not synchronized with in-flight
 * events; set it once from the owner thread. Level OFF ignores sink. */
BC_API bc_status bc_log_configure(const bc_log_options *options);

#ifdef __cplusplus
}
#endif
#endif

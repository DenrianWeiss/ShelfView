#ifndef BCONTROL_MEDIA_SESSION_H
#define BCONTROL_MEDIA_SESSION_H
#include "bcontrol.h"
#include "console.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_MEDIA_CONNECTED 1u
/* Local protocol source binding, not proof of a device-side mount. */
#define BC_MEDIA_SOURCE_ATTACHED 2u
#define BC_MEDIA_MOUNT_CONFIRMED 4u
#define BC_MEDIA_REMOVAL_CONFIRMED 8u
#define BC_MEDIA_BYTES_READ_VALID 16u
#define BC_MEDIA_READY 32u
#define BC_MEDIA_EJECTING 64u
#define BC_MEDIA_REMOVAL_UNCONFIRMED 128u
#define BC_MEDIA_FAILED 256u
#define BC_MEDIA_CONTROL_START 4u
#define BC_MEDIA_CONTROL_EJECT 1u
#define BC_MEDIA_CONTROL_KEEPALIVE 2u
#define BC_MEDIA_CONTROL_CLOSE 3u
typedef struct bc_media_session bc_media_session;
typedef struct {
    uint32_t struct_size;
    void *userdata;
    uint64_t size;
    bc_status (*read)(void *, uint64_t, uint32_t, uint8_t *);
} bc_media_source;
typedef struct {
    uint32_t struct_size, flags;
    /* Available only with BC_MEDIA_BYTES_READ_VALID. */
    uint64_t bytes_read;
    uint32_t state, status, device_code, heartbeat_interval_ms;
    uint64_t packets, requests;
    /* Protocol response payload bytes, including synthesized SCSI replies. */
    uint64_t bytes_served;
} bc_media_session_info;
/* One owner serializes these calls. Feed preserves complete message boundaries;
 * poll is for adapters that drive caller-provided transport callbacks instead.
 * Successful control means submission, not confirmed remote removal. Missing
 * confirmation flags mean unknown; platform readback may supply further evidence. */
BC_API bc_status bc_media_session_feed(bc_media_session *, bc_bytes);
BC_API bc_status bc_media_session_poll(bc_media_session *, uint32_t timeout_ms);
BC_API bc_status bc_media_session_control(bc_media_session *, uint32_t command);
BC_API bc_status bc_media_session_info_get(const bc_media_session *, bc_media_session_info *);
/* One complete output message; BUSY means empty. Insufficient capacity reports
 * the required size without consuming the message. Only buffered factories. */
BC_API bc_status bc_media_session_output(bc_media_session *, uint8_t *, uint32_t, uint32_t *);
BC_API bc_status bc_media_session_attach(bc_media_session *, const bc_media_source *);
/* Device readback evidence; local socket closure never implies removal. */
BC_API bc_status bc_media_session_observe_mount(bc_media_session *, int inserted);
BC_API bc_status bc_media_session_tick(bc_media_session *, uint64_t now_ms);
BC_API const bc_service_profile *bc_media_session_profile_get(const bc_media_session *);
BC_API const bc_console_failure *bc_media_session_failure_get(const bc_media_session *);
/* Factory sessions own their protocol. Wrapped sessions borrow it. Source and
 * transport callbacks outlive either form. Destroy does not perform network I/O. */
BC_API void bc_media_session_destroy(bc_media_session *);
#ifdef __cplusplus
}
#endif
#endif

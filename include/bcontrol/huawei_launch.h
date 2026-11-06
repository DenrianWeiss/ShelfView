#ifndef BCONTROL_HUAWEI_LAUNCH_H
#define BCONTROL_HUAWEI_LAUNCH_H
#include "huawei_discovery.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_HUAWEI_LAUNCH_EXPORT_DOWNLOAD 1u
#define BC_HUAWEI_LAUNCH_EXPORT_DIRECT 2u
#define BC_HUAWEI_LAUNCH_EXPORT_SENT 1u
#define BC_HUAWEI_LAUNCH_EXPORT_CONFIRMED 2u
#define BC_HUAWEI_LAUNCH_SHARED_MODE_REJECTED 4u
/* Metadata only. Selects a request shape from a complete ActionInfo snapshot;
 * it grants no launch/handshake permission or download target. Outputs clear
 * on failure. The parent still binds targets, endpoint and generation. */
BC_DISCOVERY_API bc_status bc_huawei_launch_request_format(const uint8_t *, uint32_t,
    uint32_t *format, uint32_t *modes);
BC_DISCOVERY_API bc_status bc_huawei_launch_targets_validate(bc_string export_uri,
    bc_string download_uri, uint32_t format);
/* Only a complete, standard Shared-value rejection without a generated ticket
 * qualifies. The parent retains the same authenticated owner, revalidates current
 * ActionInfo and obtains fresh confirmation before a single Private attempt. */
BC_DISCOVERY_API int bc_huawei_launch_private_eligible(const bc_console_failure *,
    uint32_t flags, uint32_t modes, int private_attempted);
typedef struct bc_huawei_launch bc_huawei_launch;
typedef struct {
    uint32_t struct_size, abi_version, contract, timeout_ms, modes;
    bc_string export_uri, download_uri;
    /* Two-step contract only: fresh random 32 hexadecimal digits. */
    bc_string nonce;
    uint64_t generation;
    uint64_t (*clock_ms)(void *user);
    void *clock_user;
} bc_huawei_launch_options;
typedef struct {
    uint32_t struct_size, flags;
    bc_status status;
    uint32_t http_status;
    bc_console_failure failure;
    /* Borrowed secrets, valid until launch cancellation/release. */
    const bc_console_discovery_result *descriptor;
} bc_huawei_launch_result;
typedef void (*bc_huawei_launch_completion)(bc_huawei_launch *, void *);
/* Uses an authenticated endpoint and caller-confirmed contract/targets/modes
 * from this connection. Always requests Shared; no automatic mode/contract
 * fallback, POST replay, endpoint logout or local file writes. A two-step
 * request may return JNLP directly; it is validated without downloading. Parent owns
 * remote cleanup, including after cancellation or an uncertain POST outcome. */
BC_DISCOVERY_API bc_status bc_huawei_launch_start(bc_endpoint *, const bc_huawei_launch_options *,
    bc_huawei_launch_completion, void *, bc_huawei_launch **);
/* Separate explicit entry for a single user-confirmed Private attempt. A caller
 * must prompt again for each invocation; never persist confirmation. Without
 * confirmation returns BC_CONFIRMATION_REQUIRED and submits nothing. Parent
 * recovery still enforces eligibility, remaining budget and prior cleanup. */
BC_DISCOVERY_API bc_status bc_huawei_launch_start_private(bc_endpoint *, const bc_huawei_launch_options *,
    int confirmed, bc_huawei_launch_completion, void *, bc_huawei_launch **);
BC_DISCOVERY_API const bc_huawei_launch_result *bc_huawei_launch_result_get(
    const bc_huawei_launch *, const bc_endpoint *, uint64_t generation);
BC_DISCOVERY_API bc_status bc_huawei_launch_cancel(bc_huawei_launch *);
BC_DISCOVERY_API void bc_huawei_launch_release(bc_huawei_launch *);
#ifdef __cplusplus
}
#endif
#endif

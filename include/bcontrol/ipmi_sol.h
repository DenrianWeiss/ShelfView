#ifndef BCONTROL_IPMI_SOL_H
#define BCONTROL_IPMI_SOL_H
#include "ipmi_session.h"
#include "serial.h"
#ifdef __cplusplus
extern "C" {
#endif

/* enabled: 0 disabled, 1 enabled, 2 advertised payload with unknown configuration. */
#define BC_IPMI_SOL_ENABLED_UNKNOWN 2u

#define BC_IPMI_SOL_ACTIVE 1u
#define BC_IPMI_SOL_CLOSED 2u
#define BC_IPMI_SOL_FAILED 3u
#define BC_IPMI_SOL_OUTCOME_UNKNOWN 4u
#define BC_IPMI_SOL_OVERRUN 1u
#define BC_IPMI_SOL_BREAK_DETECTED 2u
#define BC_IPMI_SOL_TRANSFER_UNAVAILABLE 4u
#define BC_IPMI_SOL_DATA_LOSS 8u
#define BC_IPMI_SOL_INPUT_PENDING 16u

typedef struct bc_ipmi_sol bc_ipmi_sol;
BC_IPMI_API bc_status bc_ipmi_sol_stream(bc_ipmi_sol *, bc_serial_stream **);
typedef struct {
    uint32_t struct_size, abi_version;
    uint32_t receive_capacity, send_capacity;
    uint32_t retry_interval_ms, retries, keepalive_ms;
    uint16_t session_port;
    uint8_t instance, reserved;
} bc_ipmi_sol_options;
typedef struct {
    uint32_t struct_size, state, flags;
    uint32_t receive_pending, send_pending;
    bc_status status, cleanup_status;
    uint16_t port, inbound_payload_size, outbound_payload_size;
    uint8_t instance, completion_code;
} bc_ipmi_sol_info;
typedef struct {
    uint32_t struct_size;
    uint8_t enabled, force_authentication, force_encryption, privilege;
    uint8_t volatile_bit_rate, nonvolatile_bit_rate, payload_channel, payload_version;
    uint16_t payload_port, reserved2;
} bc_ipmi_sol_config;

BC_IPMI_API bc_status bc_ipmi_sol_config_get(bc_ipmi_session *, bc_ipmi_sol_config *, uint8_t *completion);
/* All operations are serialized with the parent session. The parent outlives sol.
 * now_ms is a caller-supplied monotonic clock. No terminal or thread is created.
 * A failed open may return a non-NULL object: close/destroy it for cleanup. */
BC_IPMI_API bc_status bc_ipmi_sol_open(bc_ipmi_session *, const bc_ipmi_sol_options *, uint64_t now_ms, bc_ipmi_sol **);
BC_IPMI_API bc_status bc_ipmi_sol_poll(bc_ipmi_sol *, uint64_t now_ms, uint32_t timeout_ms);
/* accepted bytes enter a bounded queue; they are not yet confirmed by the BMC. */
BC_IPMI_API bc_status bc_ipmi_sol_write(bc_ipmi_sol *, bc_bytes, uint32_t *accepted);
BC_IPMI_API bc_status bc_ipmi_sol_read(bc_ipmi_sol *, uint8_t *, uint32_t capacity, uint32_t *length);
BC_IPMI_API bc_status bc_ipmi_sol_break(bc_ipmi_sol *);
#define BC_IPMI_SOL_FLUSH_TO_BMC 1u
#define BC_IPMI_SOL_FLUSH_FROM_BMC 2u
/* Explicit flush; returns BUSY while queued input is awaiting confirmation. */
BC_IPMI_API bc_status bc_ipmi_sol_flush(bc_ipmi_sol *, uint32_t directions);
BC_IPMI_API bc_status bc_ipmi_sol_info_get(const bc_ipmi_sol *, bc_ipmi_sol_info *);
/* Checks ownership before deactivation. Returns operation status after cleanup;
 * inspect info.cleanup_status separately, including after a failed open. */
BC_IPMI_API bc_status bc_ipmi_sol_close(bc_ipmi_sol *);
/* No network I/O. Close explicitly before destroy; then close the parent session. */
BC_IPMI_API void bc_ipmi_sol_destroy(bc_ipmi_sol *);
#ifdef __cplusplus
}
#endif
#endif

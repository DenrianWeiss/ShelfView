#ifndef BCONTROL_SERIAL_H
#define BCONTROL_SERIAL_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_SERIAL_READ 1u
#define BC_SERIAL_WRITE 2u
#define BC_SERIAL_BREAK 4u
#define BC_SERIAL_BUFFERED_INPUT 8u
#define BC_SERIAL_ACTIVE 1u
#define BC_SERIAL_CLOSED 2u
#define BC_SERIAL_FAILED 3u
#define BC_SERIAL_CONTROL_BREAK 1u

typedef struct bc_serial_stream bc_serial_stream;
typedef struct {
    uint32_t struct_size, state, capabilities;
    bc_status status, cleanup_status;
    uint32_t receive_pending, send_pending, protocol_flags, remote_port;
} bc_serial_info;

/* The connection owner serializes calls and keeps its protocol handle alive.
 * read drives protocol progress, including acknowledgements and keepalive.
 * accepted bytes are queued/submitted, not a promise of delivery to the host. */
BC_API bc_status bc_serial_read(bc_serial_stream *, uint64_t now_ms, uint32_t timeout_ms,
    uint8_t *, uint32_t capacity, uint32_t *length);
BC_API bc_status bc_serial_write(bc_serial_stream *, bc_bytes, uint32_t *accepted);
BC_API bc_status bc_serial_control(bc_serial_stream *, uint32_t command);
BC_API bc_status bc_serial_info_get(const bc_serial_stream *, bc_serial_info *);
BC_API bc_status bc_serial_close(bc_serial_stream *);
/* Factory streams own their protocol; wrapped streams borrow it. Close the
 * service explicitly before destroy when a cleanup result is needed. */
BC_API void bc_serial_destroy(bc_serial_stream *);
#ifdef __cplusplus
}
#endif
#endif

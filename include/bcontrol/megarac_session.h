#ifndef BCONTROL_MEGARAC_SESSION_H
#define BCONTROL_MEGARAC_SESSION_H
#include "megarac.h"
#include "console_session.h"
#include "decode_job.h"
#ifdef __cplusplus
extern "C" {
#endif
BC_MEGARAC_API uint32_t bc_megarac_session_media_flags(const bc_megarac_session *);
BC_MEGARAC_API bc_status bc_megarac_session_media_offer(const bc_megarac_session *, bc_media_offer **);
/* Protocol session belongs to the transport/input lane. The platform updates
 * the borrowed decoded frame on the display lane, retaining pixels through ack.
 * No display callback reads the protocol session or compressed-frame assembler. */
BC_MEGARAC_API bc_status bc_megarac_console_wrap(bc_megarac_session *, bc_kvm_frame *, bc_console_session **);
/* Owns video decoders and pixels; protocol remains borrowed. Stop feeding and
 * drain all submitted jobs before destroying this session. */
BC_MEGARAC_API bc_status bc_megarac_console_video_wrap(bc_megarac_session *, bc_decode_submit, void *, bc_console_session **);
/* Owns protocol, compressed buffer and video resources; frame_buffer is ignored,
 * frame_capacity defines the allocation. Drain jobs before destruction. */
BC_MEGARAC_API bc_status bc_megarac_console_create(const bc_megarac_session_options *, uint32_t keyboard_mode,
    bc_decode_submit, void *, bc_console_session **);
#ifdef __cplusplus
}
#endif
#endif

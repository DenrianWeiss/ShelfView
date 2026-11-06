#ifndef BCONTROL_HUAWEI_SESSION_H
#define BCONTROL_HUAWEI_SESSION_H
#include "huawei_kvm.h"
#include "console_session.h"
#include "decode_job.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Borrowed protocol handle belongs to the input/transport lane. The decoded
 * frame and its pixels belong to the independent display lane until ack. */
BC_HUAWEI_API bc_status bc_huawei_console_wrap(bc_huawei_kvm_session *, bc_kvm_frame *, bc_console_session **);
/* Owns the display decoder. Quiesce protocol callbacks and drain jobs before
 * destruction; protocol and framebuffer remain borrowed. */
BC_HUAWEI_API bc_status bc_huawei_console_video_wrap(bc_huawei_kvm_session *, uint8_t *, uint32_t,
    bc_decode_submit, void *, bc_console_session **);
/* Owns protocol and pixels. options.frame_buffer is ignored; capacity is used
 * for core allocation. Transport callbacks remain borrowed through destruction. */
BC_HUAWEI_API bc_status bc_huawei_console_create(const bc_huawei_kvm_params *, const bc_huawei_io *,
    const bc_huawei_kvm_options *, bc_decode_submit, void *, bc_console_session **);
/* Compatibility bridge for already negotiated protocol metadata. Copies credentials. */
BC_HUAWEI_API bc_status bc_huawei_media_offer_create(const bc_huawei_vmm_info *, bc_media_offer **);
/* Transitional media constructor; credential bytes remain inside the core. */
BC_HUAWEI_API bc_status bc_huawei_media_create_offer(const bc_media_offer *, const bc_huawei_media_options *,
    const bc_huawei_io *, bc_huawei_media **);
#ifdef __cplusplus
}
#endif
#endif

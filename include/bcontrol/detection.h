#ifndef BCONTROL_DETECTION_H
#define BCONTROL_DETECTION_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_FEATURE_KVM 1u
#define BC_FEATURE_LOCAL_MEDIA 2u
#define BC_FEATURE_REMOTE_MEDIA 3u
#define BC_FEATURE_SERIAL 4u
#define BC_FEATURE_TEMPERATURE 5u
#define BC_FEATURE_POWER 6u
#define BC_DETECTION_UNKNOWN 0u
#define BC_DETECTION_ATTEMPTABLE 1u
#define BC_DETECTION_VERIFIED 2u
#define BC_DETECTION_UNSUPPORTED 3u
#define BC_DETECTION_FAILED 4u
#define BC_DETECTION_HINT 1u
#define BC_DETECTION_DESCRIPTOR 2u
#define BC_DETECTION_HANDSHAKE 4u
#define BC_DETECTION_MANUAL 8u

typedef struct {
    uint32_t struct_size, feature, state, evidence;
    bc_status status, cleanup_status;
} bc_detection_result;
/* Evidence and status must belong to this feature's own probe. Successful
 * detection with hints alone remains unknown. Transport/authentication errors
 * are failures, never proof that the device does not support a feature. */
BC_API bc_status bc_detection_result_set(bc_detection_result *, uint32_t feature,
    uint32_t evidence, bc_status status, bc_status cleanup_status);
#ifdef __cplusplus
}
#endif
#endif

#include "bcontrol/detection.h"

bc_status bc_detection_result_set(bc_detection_result *out, uint32_t feature,
    uint32_t evidence, bc_status status, bc_status cleanup) {
    if (!out || out->struct_size != sizeof(*out) || feature < BC_FEATURE_KVM ||
        feature > BC_FEATURE_POWER || (evidence & ~15u)) return BC_INVALID_ARGUMENT;
    uint32_t state = BC_DETECTION_UNKNOWN;
    if (status == BC_UNSUPPORTED) state = BC_DETECTION_UNSUPPORTED;
    else if (status != BC_OK) state = BC_DETECTION_FAILED;
    else if (evidence & BC_DETECTION_HANDSHAKE) state = BC_DETECTION_VERIFIED;
    else if (evidence & (BC_DETECTION_DESCRIPTOR | BC_DETECTION_MANUAL)) state = BC_DETECTION_ATTEMPTABLE;
    *out = (bc_detection_result){sizeof(*out), feature, state, evidence, status, cleanup};
    return BC_OK;
}

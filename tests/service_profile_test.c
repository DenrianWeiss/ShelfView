#include "bcontrol/service_profile.h"
#include <assert.h>
#include <stddef.h>

int main(void) {
    bc_service_profile profiles[] = {
        {sizeof(bc_service_profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC,
            BC_SERVICE_MEGARAC_KVM_H5_438, BC_SERVICE_EVIDENCE_HINT},
        {sizeof(bc_service_profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_IDRAC,
            BC_SERVICE_IDRAC_KVM_EHTML5, BC_SERVICE_EVIDENCE_DESCRIPTOR},
        {sizeof(bc_service_profile), BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_MEGARAC,
            BC_SERVICE_MEGARAC_MEDIA_IUSB_CD, BC_SERVICE_EVIDENCE_HANDSHAKE},
        {sizeof(bc_service_profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_HUAWEI,
            BC_SERVICE_HUAWEI_KVM_NEGOTIATED, BC_SERVICE_EVIDENCE_MANUAL},
        {sizeof(bc_service_profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC,
            BC_SERVICE_MEGARAC_KVM_JVIEWER_195, BC_SERVICE_EVIDENCE_DESCRIPTOR}
    };
    bc_detection_result result = {0}; result.struct_size = sizeof(result);
    assert(bc_service_profile_detection(profiles, BC_SERVICE_KVM, &result) == BC_OK);
    assert(result.state == BC_DETECTION_UNKNOWN);
    assert(bc_service_profile_detection(profiles + 1, BC_SERVICE_KVM, &result) == BC_OK);
    assert(result.state == BC_DETECTION_ATTEMPTABLE);
    assert(bc_service_profile_detection(profiles + 2, BC_SERVICE_KVM, &result) == BC_OK);
    assert(result.state == BC_DETECTION_UNKNOWN);
    assert(bc_detection_result_set(&result, BC_FEATURE_SERIAL, BC_DETECTION_HANDSHAKE, BC_TIMEOUT, BC_OUTCOME_UNKNOWN) == BC_OK);
    assert(result.state == BC_DETECTION_FAILED && result.cleanup_status == BC_OUTCOME_UNKNOWN);
    assert(bc_detection_result_set(&result, BC_FEATURE_POWER, 0, BC_UNSUPPORTED, BC_OK) == BC_OK);
    assert(result.state == BC_DETECTION_UNSUPPORTED);
    assert(bc_detection_result_set(&result, BC_FEATURE_TEMPERATURE, BC_DETECTION_HANDSHAKE, BC_OK, BC_OK) == BC_OK);
    assert(result.state == BC_DETECTION_VERIFIED);
    uint32_t selected = 0;
    assert(bc_service_profile_select(profiles, 5, BC_SERVICE_KVM, NULL, &selected) == BC_OK && selected == 1);
    assert(bc_service_profile_select(profiles, 5, BC_SERVICE_KVM, profiles + 4, &selected) == BC_OK && selected == 4);
    profiles[3].evidence |= BC_SERVICE_EVIDENCE_HANDSHAKE;
    assert(bc_service_profile_select(profiles, 5, BC_SERVICE_KVM, profiles + 4, &selected) == BC_OK && selected == 3);
    assert(bc_service_profile_select(profiles, 5, BC_SERVICE_LOCAL_MEDIA, NULL, &selected) == BC_OK && selected == 2);
    assert(bc_service_profile_select(profiles, 5, BC_SERVICE_SENSOR_FALLBACK, NULL, &selected) == BC_UNSUPPORTED);
    assert(selected == UINT32_MAX);
    /* A known brand/family with an unimplemented variant remains unknown. */
    profiles[3].variant = 200;
    profiles[4].variant = 0;
    profiles[1].evidence = 0;
    assert(bc_service_profile_select(profiles, 5, BC_SERVICE_KVM, profiles, &selected) == BC_UNSUPPORTED);
    assert(selected == UINT32_MAX);
    profiles[0].evidence = BC_SERVICE_EVIDENCE_HANDSHAKE;
    assert(bc_service_profile_select(profiles, 5, BC_SERVICE_KVM, NULL, &selected) == BC_OK && selected == 0);
    profiles[0].struct_size = 0;
    assert(bc_service_profile_select(profiles, 5, BC_SERVICE_KVM, NULL, &selected) == BC_UNSUPPORTED);
    assert(bc_service_profile_select(NULL, 0, BC_SERVICE_KVM, NULL, &selected) == BC_UNSUPPORTED);
    assert(bc_service_profile_select(NULL, 1, BC_SERVICE_KVM, NULL, &selected) == BC_INVALID_ARGUMENT);
    assert(bc_service_profile_select(profiles, 257, BC_SERVICE_KVM, NULL, &selected) == BC_INVALID_ARGUMENT);
    return 0;
}

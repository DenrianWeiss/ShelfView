#ifndef BCONTROL_SERVICE_PROFILE_H
#define BCONTROL_SERVICE_PROFILE_H
#include "bcontrol.h"
#include "detection.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_SERVICE_KVM 1u
#define BC_SERVICE_LOCAL_MEDIA 2u
#define BC_SERVICE_SENSOR_FALLBACK 3u
#define BC_SERVICE_FAMILY_MEGARAC 1u
#define BC_SERVICE_FAMILY_IDRAC 2u
#define BC_SERVICE_FAMILY_HUAWEI 3u
#define BC_SERVICE_FAMILY_ILO 4u
#define BC_SERVICE_FAMILY_AVOCENT 5u
#define BC_SERVICE_FAMILY_ATEN 6u
#define BC_SERVICE_ATEN_KVM_HERMON 1u
#define BC_SERVICE_ATEN_KVM_AST 2u
#define BC_SERVICE_ATEN_MEDIA_CD_4 1u
#define BC_SERVICE_ATEN_MEDIA_CD_3 2u
#define BC_SERVICE_EVIDENCE_HINT 1u
#define BC_SERVICE_EVIDENCE_DESCRIPTOR 2u
#define BC_SERVICE_EVIDENCE_HANDSHAKE 4u
#define BC_SERVICE_EVIDENCE_MANUAL 8u
/* Variants are scoped by both service and family. Zero is unconfirmed. */
#define BC_SERVICE_MEGARAC_KVM_H5_438 1u
#define BC_SERVICE_MEGARAC_KVM_H5_373 4u
#define BC_SERVICE_MEGARAC_KVM_JVIEWER_373 2u
#define BC_SERVICE_MEGARAC_KVM_JVIEWER_195 3u
#define BC_SERVICE_MEGARAC_MEDIA_IUSB_CD 1u
#define BC_SERVICE_IDRAC_KVM_EHTML5 1u
#define BC_SERVICE_IDRAC_MEDIA_EHTML5 1u
#define BC_SERVICE_HUAWEI_KVM_NEGOTIATED 1u
#define BC_SERVICE_HUAWEI_MEDIA_VMM 1u
#define BC_SERVICE_AVOCENT_MEDIA_AVMP_CD 1u
typedef struct {
    uint32_t struct_size;
    uint32_t service, family, variant, evidence;
} bc_service_profile;
/* A descriptor permits a handshake attempt, not a claim of a working service.
 * Every feature needs independent evidence; a KVM profile cannot gate media. */
BC_API int bc_service_profile_can_attempt(const bc_service_profile *, uint32_t service);
BC_API bc_status bc_service_profile_detection(const bc_service_profile *, uint32_t service, bc_detection_result *);
BC_API int bc_service_profile_verified(const bc_service_profile *, uint32_t service);
/* Selects by protocol evidence, never by brand. The preferred
 * profile only breaks ties; explicit user overrides remain separate. On failure
 * selected is UINT32_MAX. At most 256 candidates per discovery operation. */
BC_API bc_status bc_service_profile_select(const bc_service_profile *, uint32_t count,
    uint32_t service, const bc_service_profile *preferred, uint32_t *selected);
#ifdef __cplusplus
}
#endif
#endif

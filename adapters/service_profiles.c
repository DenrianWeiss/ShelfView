#include "bcontrol/service_profile.h"

static int implemented(const bc_service_profile *p) {
    switch (p->service) {
    case BC_SERVICE_KVM:
        switch (p->family) {
        case BC_SERVICE_FAMILY_MEGARAC:
            return p->variant == BC_SERVICE_MEGARAC_KVM_H5_438 ||
                p->variant == BC_SERVICE_MEGARAC_KVM_H5_373 ||
                p->variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_373 ||
                p->variant == BC_SERVICE_MEGARAC_KVM_JVIEWER_195;
        case BC_SERVICE_FAMILY_OPENBMC: return p->variant == BC_SERVICE_OPENBMC_KVM_RFB;
        case BC_SERVICE_FAMILY_IDRAC: return p->variant == BC_SERVICE_IDRAC_KVM_EHTML5;
        case BC_SERVICE_FAMILY_ATEN: return (p->variant == BC_SERVICE_ATEN_KVM_HERMON || p->variant == BC_SERVICE_ATEN_KVM_AST);
        case BC_SERVICE_FAMILY_HUAWEI: return p->variant == BC_SERVICE_HUAWEI_KVM_NEGOTIATED;
        case BC_SERVICE_FAMILY_AVOCENT: return p->variant == BC_SERVICE_AVOCENT_KVM_WEBSOCKET_241;
        default: return 0;
        }
    case BC_SERVICE_LOCAL_MEDIA:
        switch (p->family) {
        case BC_SERVICE_FAMILY_MEGARAC: return p->variant == BC_SERVICE_MEGARAC_MEDIA_IUSB_CD;
        case BC_SERVICE_FAMILY_OPENBMC: return p->variant == BC_SERVICE_OPENBMC_MEDIA_NBD;
        case BC_SERVICE_FAMILY_IDRAC: return p->variant == BC_SERVICE_IDRAC_MEDIA_EHTML5;
        case BC_SERVICE_FAMILY_HUAWEI: return p->variant == BC_SERVICE_HUAWEI_MEDIA_VMM;
        case BC_SERVICE_FAMILY_AVOCENT: return p->variant == BC_SERVICE_AVOCENT_MEDIA_AVMP_CD ||
            p->variant == BC_SERVICE_AVOCENT_MEDIA_WEBSOCKET_114;
        case BC_SERVICE_FAMILY_ATEN: return p->variant == BC_SERVICE_ATEN_MEDIA_CD_4 ||
            p->variant == BC_SERVICE_ATEN_MEDIA_CD_3 || p->variant == BC_SERVICE_ATEN_MEDIA_CD_3_HMAC ||
            p->variant == BC_SERVICE_ATEN_MEDIA_HTML5;
        default: return 0;
        }
    default: return 0;
    }
}
bc_status bc_service_profile_detection(const bc_service_profile *p, uint32_t service, bc_detection_result *out) {
    uint32_t feature;
    if (service == BC_SERVICE_KVM) feature = BC_FEATURE_KVM;
    else if (service == BC_SERVICE_LOCAL_MEDIA) feature = BC_FEATURE_LOCAL_MEDIA;
    else if (service == BC_SERVICE_SENSOR_FALLBACK) feature = BC_FEATURE_TEMPERATURE;
    else return BC_INVALID_ARGUMENT;
    uint32_t evidence = p && p->struct_size == sizeof(*p) && p->service == service && implemented(p) ? p->evidence & 15u : 0;
    return bc_detection_result_set(out, feature, evidence, BC_OK, BC_OK);
}
int bc_service_profile_can_attempt(const bc_service_profile *p, uint32_t service) {
    bc_detection_result result = {0}; result.struct_size = sizeof(result);
    return bc_service_profile_detection(p, service, &result) == BC_OK &&
        (result.state == BC_DETECTION_ATTEMPTABLE || result.state == BC_DETECTION_VERIFIED);
}
int bc_service_profile_verified(const bc_service_profile *p, uint32_t service) {
    bc_detection_result result = {0}; result.struct_size = sizeof(result);
    return bc_service_profile_detection(p, service, &result) == BC_OK && result.state == BC_DETECTION_VERIFIED;
}

static int same(const bc_service_profile *a, const bc_service_profile *b) {
    return b && b->struct_size == sizeof(*b) && a->service == b->service &&
        a->family == b->family && a->variant == b->variant;
}
bc_status bc_service_profile_select(const bc_service_profile *profiles, uint32_t count,
    uint32_t service, const bc_service_profile *preferred, uint32_t *selected) {
    if (!selected) return BC_INVALID_ARGUMENT;
    *selected = UINT32_MAX;
    if ((!profiles && count) || count > 256) return BC_INVALID_ARGUMENT;
    uint32_t best = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const bc_service_profile *p = profiles + i;
        if (!bc_service_profile_can_attempt(p, service)) continue;
        uint32_t rank = (p->evidence & BC_SERVICE_EVIDENCE_HANDSHAKE) ? 3u :
            (p->evidence & BC_SERVICE_EVIDENCE_DESCRIPTOR) ? 2u : 1u;
        if (*selected == UINT32_MAX || rank > best ||
            (rank == best && same(p, preferred) && !same(profiles + *selected, preferred))) {
            *selected = i; best = rank;
        }
    }
    return *selected == UINT32_MAX ? BC_UNSUPPORTED : BC_OK;
}

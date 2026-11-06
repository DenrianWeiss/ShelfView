#ifndef BCONTROL_ZTE_H
#define BCONTROL_ZTE_H
#include "megarac.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Identification permits probing the OEM resource, never enables a console. */
BC_MEGARAC_API int bc_zte_service_root_matches(const uint8_t *, uint32_t);
/* Parses a current authenticated KvmService response. Only same-origin HTTPS
 * viewer token URLs are accepted; output is secret and must not be persisted. */
BC_MEGARAC_API bc_status bc_zte_kvm_token(const uint8_t *, uint32_t, bc_string origin,
    char *, uint32_t capacity);
/* Use a fresh anonymous cookie-jar endpoint with the same origin/TLS as the
 * authenticated Redfish read. Shares MegaRAC configuration and owned logout. */
BC_MEGARAC_API bc_status bc_zte_kvm_probe_start(bc_endpoint *, const bc_megarac_probe_options *,
    const uint8_t *, uint32_t, bc_megarac_probe_completion, void *, bc_megarac_probe **);
#ifdef __cplusplus
}
#endif
#endif

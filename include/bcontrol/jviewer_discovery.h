#ifndef BCONTROL_JVIEWER_DISCOVERY_H
#define BCONTROL_JVIEWER_DISCOVERY_H
#include "console_discovery.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_jviewer_artifact bc_jviewer_artifact;
typedef struct {
    uint32_t struct_size, abi_version, timeout_ms;
    uint64_t generation;
    /* Monotonic for the operation lifetime. Regression/expiry invalidates resource getters. */
    uint64_t (*clock_ms)(void *);
    void *clock_user;
    const bc_string *headers;
    uint32_t header_count;
} bc_jviewer_artifact_options;
typedef struct {
    uint32_t struct_size;
    bc_status status;
    uint32_t http_status;
    uint64_t endpoint_revision, generation;
    bc_service_profile hint;
    bc_console_failure failure;
} bc_jviewer_artifact_result;
typedef void (*bc_jviewer_artifact_completion)(bc_jviewer_artifact *, void *);
/* Follow only a validated JNLP's advertised same-origin resource. The original
 * completed request must belong to this exact endpoint. One GET, no replay,
 * Java execution, file writes, authentication or profile promotion. */
BC_DISCOVERY_API bc_status bc_jviewer_artifact_start(bc_endpoint *, bc_request *, const bc_jviewer_artifact_options *,
    bc_jviewer_artifact_completion, void *, bc_jviewer_artifact **);
BC_DISCOVERY_API const bc_jviewer_artifact_result *bc_jviewer_artifact_result_get(
    const bc_jviewer_artifact *, const bc_endpoint *, uint64_t generation);
#define BC_JVIEWER_ASSET_STARTUP 1u
#define BC_JVIEWER_ASSET_JAR 2u
/* Borrow only an already-completed successful response on this exact endpoint,
 * revision and generation before expiry/cancellation. Unknown JAR layout does
 * not hide its bytes for explicit diagnostics. No extra I/O or permission.
 * Sensitive: never log/persist raw startup; use diagnostic JNLP redaction.
 * Raw binary JAR export requires the user's explicit export choice. */
BC_DISCOVERY_API bc_request *bc_jviewer_artifact_asset_request_get(bc_jviewer_artifact *,
    const bc_endpoint *, uint64_t generation, uint32_t kind);
/* Combine the original strict launch descriptor with its scoped resource's
 * recognized layout. Copies short-lived secrets; no handshake/media evidence. */
BC_DISCOVERY_API bc_status bc_jviewer_artifact_resolve(bc_jviewer_artifact *, const bc_endpoint *, uint64_t generation,
    bc_megarac_kvm_info *, bc_service_profile *);
/* Copy launch inputs, filling an absent token type only from this operation's
 * recognized initializer metadata, independently of KVM layout recognition.
 * Does not produce a media service profile. */
BC_DISCOVERY_API bc_status bc_jviewer_artifact_media_parameters(bc_jviewer_artifact *, const bc_endpoint *,
    uint64_t generation, bc_megarac_media_parameters *);
/* Independent same-resource media HINT, even when the KVM layout is unknown.
 * Exact endpoint/generation, completion, cancellation and budget still apply.
 * This is not a media service permission or authentication profile. */
BC_DISCOVERY_API bc_status bc_jviewer_artifact_media_hint(bc_jviewer_artifact *, const bc_endpoint *,
    uint64_t generation, bc_service_profile *);
/* Independent multi-port IUSB CD/WEB0 candidate, combining the same archive's
 * complete media wire evidence with this launch's declared/resource-bound
 * inputs. Does not depend on KVM layout recognition. Permits one handshake,
 * not a claim of successful authentication, a mount or a verified service.
 * SSI, single-port mode and incomplete/conflicting inputs remain unsupported. */
BC_DISCOVERY_API bc_status bc_jviewer_artifact_media_resolve(bc_jviewer_artifact *, const bc_endpoint *,
    uint64_t generation, bc_service_profile *, bc_megarac_media_parameters *);
BC_DISCOVERY_API bc_status bc_jviewer_artifact_cancel(bc_jviewer_artifact *);
BC_DISCOVERY_API void bc_jviewer_artifact_release(bc_jviewer_artifact *);
#ifdef __cplusplus
}
#endif
#endif

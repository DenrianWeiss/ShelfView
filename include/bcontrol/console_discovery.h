#ifndef BCONTROL_CONSOLE_DISCOVERY_H
#define BCONTROL_CONSOLE_DISCOVERY_H
#include "megarac.h"
#include "huawei_kvm.h"
#include "idrac_kvm.h"
#include "avocent.h"
#include "aten.h"
#if defined(_WIN32)
# ifdef BC_DISCOVERY_BUILD
#  define BC_DISCOVERY_API __declspec(dllexport)
# else
#  define BC_DISCOVERY_API __declspec(dllimport)
# endif
#else
# define BC_DISCOVERY_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define BC_CONSOLE_DESCRIPTOR_JVIEWER 1u
#define BC_CONSOLE_DESCRIPTOR_H5 2u
#define BC_CONSOLE_DESCRIPTOR_HUAWEI 3u
#define BC_CONSOLE_DESCRIPTOR_IDRAC 4u
#define BC_CONSOLE_DESCRIPTOR_AVOCENT 5u
#define BC_CONSOLE_DESCRIPTOR_ATEN 6u
#define BC_CONSOLE_DISCOVERY_READY 1u
#define BC_CONSOLE_DISCOVERY_NEEDS_URI 2u
#define BC_CONSOLE_DISCOVERY_FAILED 3u
typedef struct bc_console_discovery bc_console_discovery;
typedef struct {
    uint32_t struct_size, abi_version;
    bc_string path;
    uint64_t generation;
    uint32_t timeout_ms;
    /* Optional session/CSRF headers, validated and copied by the HTTP core. */
    const bc_string *headers;
    uint32_t header_count;
} bc_console_discovery_options;
/* Contains short-lived secrets. Borrow only on the serialized context queue;
 * never log, reflect or persist. Destroy the operation after consuming it. */
typedef struct {
    uint32_t struct_size, state, format;
    bc_status status;
    uint32_t http_status;
    uint64_t endpoint_revision, generation;
    bc_service_profile profile;
    bc_console_failure failure;
    bc_megarac_kvm_info megarac;
    bc_huawei_kvm_params huawei;
    bc_idrac_console_launch idrac;
    bc_string location;
} bc_console_discovery_result;
typedef void (*bc_console_discovery_completion)(bc_console_discovery *, void *);
/* Fetch one caller-selected launch link on an already authenticated endpoint.
 * No login, scan, redirect-following or automatic second request is performed. */
BC_DISCOVERY_API bc_status bc_console_discovery_start(bc_endpoint *, const bc_console_discovery_options *,
    bc_console_discovery_completion, void *, bc_console_discovery **);
/* Interpret a completed, caller-owned launch/download request without replaying
 * it. Retains request/endpoint; no callback or I/O. BUSY if not complete. */
BC_DISCOVERY_API bc_status bc_console_discovery_from_request(bc_endpoint *, uint64_t generation,
    bc_request *, bc_console_discovery **);
/* Exact endpoint object and caller generation must match, even across contexts
 * with colliding revision numbers. NULL before completion or on scope mismatch. */
BC_DISCOVERY_API const bc_console_discovery_result *bc_console_discovery_result_get(
    const bc_console_discovery *, const bc_endpoint *, uint64_t generation);
/* NEEDS_URI: platform resolves Location relative to bc_endpoint_origin(endpoint),
 * then supplies components and host/port parsed from that original HTTPS origin. */
BC_DISCOVERY_API bc_status bc_console_discovery_resolve_idrac(bc_console_discovery *, const bc_endpoint *,
    uint64_t generation, const bc_idrac_launch_uri *, bc_string origin_host, uint32_t origin_port);
/* Parsed descriptor only; does not authorize an unimplemented service backend.
 * Same endpoint/generation and a successful, non-cancelled result are required. */
BC_DISCOVERY_API const bc_avocent_launch *bc_console_discovery_avocent_get(
    const bc_console_discovery *, const bc_endpoint *, uint64_t generation);
BC_DISCOVERY_API const bc_aten_launch *bc_console_discovery_aten_get(
    const bc_console_discovery *, const bc_endpoint *, uint64_t generation);
BC_DISCOVERY_API bc_status bc_console_discovery_cancel(bc_console_discovery *);
BC_DISCOVERY_API void bc_console_discovery_release(bc_console_discovery *);
#define BC_CONSOLE_METADATA_KVM 1u
#define BC_CONSOLE_METADATA_ATTRIBUTES 2u
typedef struct {
    uint32_t kind;
    char uri[1025];
} bc_console_metadata_link;
/* Read-only metadata relationships advertised by a Manager. No auth/profile
 * inference; caller binds response to its endpoint/generation. At most 32 links. */
BC_DISCOVERY_API bc_status bc_console_manager_metadata_links(const uint8_t *, uint32_t,
    bc_string manager_uri, bc_console_metadata_link *, uint32_t capacity, uint32_t *written);
#ifdef __cplusplus
}
#endif
#endif

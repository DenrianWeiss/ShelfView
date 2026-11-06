#ifndef BCONTROL_IDRAC_HTTP_H
#define BCONTROL_IDRAC_HTTP_H
#include "idrac_kvm.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Adapter operations on an isolated, credential-free endpoint with a cookie jar.
 * The context owns HTTP/TLS/proxy execution. Requests copy all inputs. */
BC_IDRAC_API bc_status bc_idrac_http_login(bc_endpoint *, bc_string username, bc_string password,
    uint32_t timeout_ms, bc_completion, void *, bc_request **);
BC_IDRAC_API bc_status bc_idrac_http_login_status(const bc_request *);
#define BC_IDRAC_HTTP_LAUNCH 1u
#define BC_IDRAC_HTTP_LOGOUT 2u
/* Keeps the XSRF token inside the core. Login must belong to this endpoint.
 * Logout may clean up a rejected login that nevertheless issued a token. */
BC_IDRAC_API bc_status bc_idrac_http_submit(bc_endpoint *, const bc_request *login,
    uint32_t operation, uint32_t timeout_ms, bc_completion, void *, bc_request **);
#ifdef __cplusplus
}
#endif
#endif

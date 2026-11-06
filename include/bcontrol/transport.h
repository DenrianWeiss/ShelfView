#ifndef BCONTROL_TRANSPORT_H
#define BCONTROL_TRANSPORT_H
#include "bcontrol.h"
#include "socks5.h"
#if defined(_WIN32)
# ifdef BC_CURL_BUILD
#  define BC_CURL_API __declspec(dllexport)
# else
#  define BC_CURL_API __declspec(dllimport)
# endif
#else
# define BC_CURL_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

typedef void (*bc_transport_done)(void *, const bc_response *);
/* Optional completion extension: pass &base with base.struct_size set to
 * sizeof(bc_transport_response). All views remain valid through done(). */
typedef struct {
    bc_response base;
    bc_http_metadata metadata;
} bc_transport_response;
typedef struct {
    bc_transport_response response;
    bc_string auth_token;
} bc_transport_auth_response;
/* Cookie header assembled from the endpoint's cookie jar, when enabled. */
typedef struct {
    bc_transport_auth_response auth;
    bc_string cookie_header;
} bc_transport_cookie_response;
typedef struct {
    bc_transport_cookie_response cookie;
    bc_string csrf_token;
} bc_transport_session_response;
/* Token endpoints extend the original endpoint config, preserving its prefix. */
typedef struct {
    bc_endpoint_options base;
    bc_string auth_token;
} bc_transport_endpoint_config;
/* A transport copies/retains inputs through completion. submit never calls done.
 * cancel removes an operation synchronously and never calls done for it.
 * poll calls done only on the context's polling thread. */
struct bc_transport {
    uint32_t struct_size;
    uint32_t abi_version;
    void *userdata;
    bc_status (*endpoint_open)(void *, const bc_endpoint_options *, void **);
    void (*endpoint_close)(void *, void *);
    bc_status (*submit)(void *, void *, const bc_http_options *, uint64_t, bc_transport_done, void *, void **);
    void (*cancel)(void *, void *);
    bc_status (*poll)(void *, uint32_t);
    /* Optional extension; earlier transports may end before this member. */
    bc_status (*cookie_set)(void *, void *, bc_string name, bc_string value);
};

/* Optional proxy-aware extension, preserving both previous transport layouts. */
typedef struct {
    bc_transport base;
    bc_status (*endpoint_open_proxy)(void *, const bc_endpoint_options *, const bc_socks5_proxy *, void **);
} bc_transport_proxy;

/* Backend outlives its context and must be destroyed after that context.
 * Global backend initialization is serialized by the transport implementation. */
BC_CURL_API bc_status bc_curl_transport_create(bc_transport **);
BC_CURL_API bc_status bc_curl_transport_destroy(bc_transport *);
#ifdef __cplusplus
}
#endif
#endif

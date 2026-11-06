#ifndef BCONTROL_IPMI_PLATFORM_H
#define BCONTROL_IPMI_PLATFORM_H
#include "ipmi_session.h"
#include "socks5.h"
#if defined(_WIN32)
# ifdef BC_IPMI_PLATFORM_BUILD
#  define BC_IPMI_PLATFORM_API __declspec(dllexport)
# else
#  define BC_IPMI_PLATFORM_API __declspec(dllimport)
# endif
#else
# define BC_IPMI_PLATFORM_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

/* OpenSSL 3 RAKP HMAC, AES-CBC-128 and random primitives. */
BC_IPMI_PLATFORM_API bc_status bc_ipmi_openssl_crypto_create(bc_ipmi_crypto **);
BC_IPMI_PLATFORM_API void bc_ipmi_openssl_crypto_destroy(bc_ipmi_crypto *);
/* SOCKS5 UDP association; destroy with the matching socks5 function. */
BC_IPMI_PLATFORM_API bc_status bc_ipmi_socks5_create(bc_string, uint16_t, const bc_socks5_proxy *, uint32_t timeout_ms, bc_ipmi_io **);
BC_IPMI_PLATFORM_API void bc_ipmi_socks5_destroy(bc_ipmi_io *);
/* Connected UDP datagram transport. host may be a name or address. */
BC_IPMI_PLATFORM_API bc_status bc_ipmi_udp_create(bc_string host, uint16_t port, bc_ipmi_io **);
BC_IPMI_PLATFORM_API bc_status bc_ipmi_udp_create_timeout(bc_string host, uint16_t port, uint32_t timeout_ms, bc_ipmi_io **);
BC_IPMI_PLATFORM_API void bc_ipmi_udp_destroy(bc_ipmi_io *);
#ifdef __cplusplus
}
#endif
#endif

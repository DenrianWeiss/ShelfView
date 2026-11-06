#ifndef BC_PLATFORM_RESOLVER_H
#define BC_PLATFORM_RESOLVER_H
#include "bcontrol/bcontrol.h"
#if defined(BC_KVM_NET_BUILD) || defined(BC_IPMI_SOCKS5_NET)
#include "bcontrol/kvm_transport.h"
#define BC_RESOLVER_API BC_KVM_NET_API
#else
#define BC_RESOLVER_API
#endif
struct addrinfo;
/* At most 16 system resolver calls remain outstanding. Timed-out callers never
 * receive a late result. A still-running timed-out hostname is not resubmitted.
 * Successful lists are owned by the caller (freeaddrinfo). */
BC_RESOLVER_API bc_status bc_net_resolve(const char *host, const char *service,
    const struct addrinfo *hints, uint32_t timeout_ms, struct addrinfo **out);
#endif

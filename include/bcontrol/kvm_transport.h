#ifndef BCONTROL_KVM_TRANSPORT_H
#define BCONTROL_KVM_TRANSPORT_H
#include "bcontrol/bcontrol.h"
#include "bcontrol/socks5.h"
#if defined(_WIN32)
# ifdef BC_KVM_NET_BUILD
#  define BC_KVM_NET_API __declspec(dllexport)
# else
#  define BC_KVM_NET_API __declspec(dllimport)
# endif
#else
# define BC_KVM_NET_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define BC_KVM_TRANSPORT_TCP 1u
#define BC_KVM_TRANSPORT_TLS 2u
#define BC_KVM_TRANSPORT_WS 3u
#define BC_KVM_TRANSPORT_WSS 4u
#define BC_KVM_TRANSPORT_DEFLATE 1u
#define BC_KVM_TRANSPORT_LEGACY_TLS 2u
#define BC_KVM_TRANSPORT_BINARY_ONLY 4u
#define BC_KVM_TRANSPORT_NO_DHE 8u
#define BC_KVM_TRANSPORT_SUBPROTOCOL_NONE 0u
#define BC_KVM_TRANSPORT_SUBPROTOCOL_BINARY 1u
#define BC_KVM_TRANSPORT_SUBPROTOCOL_BASE64 2u

typedef struct bc_kvm_transport bc_kvm_transport;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    bc_string url;
    bc_string ca_file;
    bc_string username;
    bc_string password;
    const bc_string *headers;
    uint32_t header_count;
    uint32_t cert_policy;
    uint32_t tls_min;
    uint32_t tls_max;
    uint32_t timeout_ms;
    uint32_t flags;
    bc_string subprotocols;
    uint32_t reserved;
} bc_kvm_transport_options;

typedef struct {
    uint32_t struct_size, abi_version, trusted, reserved;
    char version[32], cipher[128], subject[1024], issuer[1024];
    char sha256[65], not_before[21], not_after[21];
} bc_tls_peer_info;
/* Copies peer metadata and independently checks the native trust store, server
 * purpose, validity and target identity. Does not change connection policy. */
BC_KVM_NET_API bc_status bc_kvm_transport_peer_info(const bc_kvm_transport *, bc_tls_peer_info *);

BC_KVM_NET_API bc_status bc_kvm_transport_connect_proxy(const bc_kvm_transport_options *, const bc_socks5_proxy *, bc_kvm_transport **);
BC_KVM_NET_API bc_status bc_kvm_transport_connect(const bc_kvm_transport_options *, bc_kvm_transport **);
typedef struct {
    uint32_t struct_size, abi_version, cert_policy, tls_min, tls_max, timeout_ms, flags;
    bc_string ca_file;
} bc_kvm_tls_options;
/* Upgrades an established plain TCP connection in place, preserving target and
 * proxy binding. No concurrent I/O; caller must consume all pre-TLS bytes first.
 * Only LEGACY_TLS is accepted. Handshake failure closes the connection; it must
 * never be reused as plaintext. Validation failures leave it unchanged. */
BC_KVM_NET_API bc_status bc_kvm_transport_start_tls(bc_kvm_transport *, const bc_kvm_tls_options *);
/* PEM identity is parsed in memory; encrypted private keys are not accepted.
 * Invalid or mismatched material leaves the plain connection unchanged. */
BC_KVM_NET_API bc_status bc_kvm_transport_start_tls_identity(bc_kvm_transport *, const bc_kvm_tls_options *, bc_string certificate_pem, bc_string private_key_pem);
/* Authenticates the TLS peer using an exact PEM certificate from the caller's
 * authenticated startup exchange. The transport never sends application data
 * until the certificate matches. */
BC_KVM_NET_API bc_status bc_kvm_transport_start_tls_pinned(bc_kvm_transport *, const bc_kvm_tls_options *, bc_string peer_pem);
BC_KVM_NET_API bc_status bc_kvm_transport_recv(bc_kvm_transport *, uint8_t *, uint32_t capacity, uint32_t *received, uint32_t timeout_ms);
BC_KVM_NET_API bc_status bc_kvm_transport_send(bc_kvm_transport *, const uint8_t *, uint32_t);
BC_KVM_NET_API bc_status bc_kvm_transport_local_address(const bc_kvm_transport *, char *out, uint32_t capacity);
BC_KVM_NET_API uint32_t bc_kvm_transport_kind(const bc_kvm_transport *);
BC_KVM_NET_API uint32_t bc_kvm_transport_subprotocol(const bc_kvm_transport *);
/* Interrupt I/O without touching TLS state or freeing memory. May run during
 * send/recv; caller must exclude concurrent close/destroy and retain transport. */
BC_KVM_NET_API void bc_kvm_transport_interrupt(bc_kvm_transport *);
BC_KVM_NET_API void bc_kvm_transport_close(bc_kvm_transport *);
BC_KVM_NET_API void bc_kvm_transport_destroy(bc_kvm_transport *);
#ifdef __cplusplus
}
#endif
#endif

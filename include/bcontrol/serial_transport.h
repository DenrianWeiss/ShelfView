#ifndef BCONTROL_SERIAL_TRANSPORT_H
#define BCONTROL_SERIAL_TRANSPORT_H
#include "kvm_transport.h"
#include "serial.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t struct_size, abi_version;
    bc_string host, username, password, ca_file;
    uint32_t cert_policy, tls_min, tls_max, timeout_ms;
    const bc_socks5_proxy *proxy;
} bc_serial_open_options;
/* The caller first confirms an advertised alternate serial service and explicit
 * SOL absence/disablement. Service addresses and handshake stay in the core. */
BC_KVM_NET_API int bc_serial_fallback_allowed(bc_status, uint8_t completion_code);
BC_KVM_NET_API bc_status bc_serial_open(const bc_serial_open_options *, bc_serial_stream **);
#ifdef __cplusplus
}
#endif
#endif

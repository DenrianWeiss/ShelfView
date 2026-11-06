#ifndef BCONTROL_ILOM_H
#define BCONTROL_ILOM_H
#include "kvm_transport.h"
#include "serial.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct bc_ilom_serial bc_ilom_serial;
BC_KVM_NET_API bc_status bc_ilom_serial_stream(bc_ilom_serial *, bc_serial_stream **);
/* Only explicit SOL absence/disablement permits trying another serial protocol. */
BC_KVM_NET_API int bc_ilom_serial_fallback_allowed(bc_status status, uint8_t completion_code);
/* url is the selected endpoint's tls://host:5556 authentication service.
 * serial_url must name the same host's tcp://host:7579 serial service. */
BC_KVM_NET_API bc_status bc_ilom_serial_open_proxy(const bc_kvm_transport_options *, bc_string serial_url, const bc_socks5_proxy *, bc_ilom_serial **);
BC_KVM_NET_API bc_status bc_ilom_serial_open(const bc_kvm_transport_options *, bc_string serial_url, bc_ilom_serial **);
BC_KVM_NET_API bc_status bc_ilom_serial_read(bc_ilom_serial *, uint8_t *, uint32_t, uint32_t *, uint32_t);
BC_KVM_NET_API bc_status bc_ilom_serial_write(bc_ilom_serial *, const uint8_t *, uint32_t);
BC_KVM_NET_API int bc_ilom_serial_writable(const bc_ilom_serial *);
BC_KVM_NET_API bc_status bc_ilom_serial_close(bc_ilom_serial *);
BC_KVM_NET_API void bc_ilom_serial_destroy(bc_ilom_serial *);
#ifdef __cplusplus
}
#endif
#endif

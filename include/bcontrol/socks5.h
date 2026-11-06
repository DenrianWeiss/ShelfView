#ifndef BCONTROL_SOCKS5_H
#define BCONTROL_SOCKS5_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_SOCKS5_CONNECT 1u
#define BC_SOCKS5_UDP_ASSOCIATE 3u
#define BC_SOCKS5_IPV4 1u
#define BC_SOCKS5_DOMAIN 3u
#define BC_SOCKS5_IPV6 4u
typedef struct {
    uint8_t type, length;
    uint8_t address[255];
    uint16_t port;
} bc_socks5_address;
typedef struct {
    uint32_t struct_size;
    bc_string host, username, password;
    uint32_t port;
} bc_socks5_proxy;
BC_API bc_status bc_endpoint_create_proxy(bc_context *, const bc_endpoint_options *, const bc_socks5_proxy *, bc_endpoint **);
/* Callbacks transfer exactly length bytes, honoring the caller's deadline and
 * cancellation. They must not retain buffers, which can contain credentials. */
typedef bc_status (*bc_socks5_read_fn)(void *, uint8_t *, uint32_t);
typedef bc_status (*bc_socks5_write_fn)(void *, const uint8_t *, uint32_t);
BC_API bc_status bc_socks5_negotiate(uint8_t command, const bc_socks5_address *,
    bc_string username, bc_string password, bc_socks5_read_fn, bc_socks5_write_fn,
    void *userdata, bc_socks5_address *bound, uint8_t *reply);
/* Address bytes are network order; domains are wire-format ASCII without NUL.
 * Parsers set consumed=0 for an incomplete response and never retain input. */
BC_API bc_status bc_socks5_request(uint8_t command, const bc_socks5_address *, uint8_t *, uint32_t, uint32_t *);
BC_API bc_status bc_socks5_reply(const uint8_t *, uint32_t, bc_socks5_address *, uint8_t *reply, uint32_t *consumed);
BC_API bc_status bc_socks5_auth(bc_string user, bc_string password, uint8_t *, uint32_t, uint32_t *);
BC_API bc_status bc_socks5_udp_header(const bc_socks5_address *, uint8_t *, uint32_t, uint32_t *);
BC_API bc_status bc_socks5_udp_parse(const uint8_t *, uint32_t, bc_socks5_address *, uint32_t *payload_offset);
#ifdef __cplusplus
}
#endif
#endif

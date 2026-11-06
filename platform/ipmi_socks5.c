#define _POSIX_C_SOURCE 200809L
#include "bcontrol/ipmi_platform.h"
#include <stddef.h>
#ifdef BC_IPMI_SOCKS5_NET
#include "bcontrol/kvm_transport.h"
#include "bcontrol/socks5.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "monotonic.h"

typedef struct {
    bc_ipmi_io api;
    bc_ipmi_io *relay;
    bc_kvm_transport *control;
    bc_socks5_address target;
    uint32_t timeout;
    uint64_t deadline;
    uint8_t packet[65536];
} socks_udp;
static bc_status control_read(void *user, uint8_t *data, uint32_t size) {
    socks_udp *s = user;
    while (size) {
        uint32_t received = 0;
        uint64_t now = bc_monotonic_ms();
        if (now >= s->deadline) return BC_TIMEOUT;
        bc_status status = bc_kvm_transport_recv(s->control,data,size,&received,(uint32_t)(s->deadline-now));
        if (status != BC_OK) return status;
        if (!received) return BC_IO_ERROR;
        data += received; size -= received;
    }
    return BC_OK;
}
static bc_status control_write(void *user, const uint8_t *data, uint32_t size) {
    socks_udp *s = user;
    if (bc_monotonic_ms() >= s->deadline) return BC_TIMEOUT;
    return bc_kvm_transport_send(s->control,data,size);
}
static bc_status control_alive(socks_udp *s) {
    uint8_t data; uint32_t n=0;
    bc_status status=bc_kvm_transport_recv(s->control,&data,1,&n,0);
    return status==BC_TIMEOUT ? BC_OK : BC_IO_ERROR;
}
static bc_status proxy_send(void *user, const uint8_t *data, uint32_t size) {
    socks_udp *s=user;
    if (!data || !size) return BC_INVALID_ARGUMENT;
    bc_status status=control_alive(s);
    if (status!=BC_OK) return status;
    uint32_t prefix=0;
    status=bc_socks5_udp_header(&s->target,s->packet,sizeof(s->packet),&prefix);
    if (status!=BC_OK) return status;
    if (size>65507-prefix) return BC_LIMIT_EXCEEDED;
    memcpy(s->packet+prefix,data,size);
    return s->relay->send(s->relay->userdata,s->packet,prefix+size);
}
static bc_status proxy_receive(void *user, uint8_t *data, uint32_t capacity, uint32_t *size, uint32_t timeout) {
    socks_udp *s=user;
    if (!data || !capacity || !size) return BC_INVALID_ARGUMENT;
    *size=0;
    bc_status status=control_alive(s);
    if (status!=BC_OK) return status;
    uint32_t received=0;
    uint64_t deadline = bc_monotonic_ms() + timeout;
    do {
        uint64_t now = bc_monotonic_ms();
        uint32_t remaining = now < deadline ? (uint32_t)(deadline-now) : 0;
        status=s->relay->receive(s->relay->userdata,s->packet,sizeof(s->packet),&received,remaining>50?50:remaining);
        if (control_alive(s)!=BC_OK) return BC_IO_ERROR;
    } while (status==BC_TIMEOUT && bc_monotonic_ms()<deadline);
    if (status!=BC_OK) return status;
    bc_socks5_address source; uint32_t prefix=0;
    status=bc_socks5_udp_parse(s->packet,received,&source,&prefix);
    if (status!=BC_OK) return status;
    if (source.port!=s->target.port) return BC_PROTOCOL_ERROR;
    if (s->target.type!=BC_SOCKS5_DOMAIN && (source.type!=s->target.type ||
        source.length!=s->target.length || memcmp(source.address,s->target.address,source.length))) return BC_PROTOCOL_ERROR;
    if (received-prefix>capacity) return BC_LIMIT_EXCEEDED;
    memcpy(data,s->packet+prefix,received-prefix); *size=received-prefix;
    return BC_OK;
}
void bc_ipmi_socks5_destroy(bc_ipmi_io *io) {
    if (!io) return;
    socks_udp *s=io->userdata;
    bc_ipmi_udp_destroy(s->relay); bc_kvm_transport_destroy(s->control); free(s);
}
bc_status bc_ipmi_socks5_create(bc_string host, uint16_t port, const bc_socks5_proxy *proxy,
    uint32_t timeout_ms, bc_ipmi_io **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out=NULL;
    if (!host.data || !host.length || host.length>253 || memchr(host.data,0,(size_t)host.length) || !port ||
        !proxy || proxy->struct_size!=sizeof(*proxy) || !proxy->host.data || !proxy->host.length ||
        proxy->host.length>253 || memchr(proxy->host.data,0,(size_t)proxy->host.length) || !proxy->port || proxy->port>65535)
        return BC_INVALID_ARGUMENT;
    char proxy_name[254], name[254], url[300];
    memcpy(proxy_name,proxy->host.data,(size_t)proxy->host.length); proxy_name[proxy->host.length]=0;
    memcpy(name,host.data,(size_t)host.length); name[host.length]=0;
    snprintf(url,sizeof(url),strchr(proxy_name,':')?"tcp://[%s]:%u":"tcp://%s:%u",proxy_name,proxy->port);
    socks_udp *s=calloc(1,sizeof(*s)); if (!s) return BC_NO_MEMORY;
    s->api=(bc_ipmi_io){sizeof(bc_ipmi_io),BC_ABI_VERSION,s,proxy_send,proxy_receive};
    s->timeout=timeout_ms?timeout_ms:5000;
    bc_kvm_transport_options options={0}; options.struct_size=sizeof(options); options.abi_version=BC_ABI_VERSION;
    options.url=(bc_string){url,strlen(url)}; options.timeout_ms=s->timeout;
    s->deadline=bc_monotonic_ms()+s->timeout;
    bc_status status=bc_kvm_transport_connect(&options,&s->control);
    bc_socks5_address local={BC_SOCKS5_IPV4,4,{0},0}, bound={0}; uint8_t reply;
    if (status==BC_OK) status=bc_socks5_negotiate(BC_SOCKS5_UDP_ASSOCIATE,&local,proxy->username,proxy->password,
        control_read,control_write,s,&bound,&reply);
    char relay[256]={0};
    if (status==BC_OK) {
        if (!bound.port) status=BC_PROTOCOL_ERROR;
        else if (bound.type==BC_SOCKS5_DOMAIN) memcpy(relay,bound.address,bound.length);
        else if (!inet_ntop(bound.type==BC_SOCKS5_IPV4?AF_INET:AF_INET6,bound.address,relay,sizeof(relay))) status=BC_PROTOCOL_ERROR;
        if (!strcmp(relay,"0.0.0.0") || !strcmp(relay,"::")) strcpy(relay,proxy_name);
    }
    if (status==BC_OK) {
        uint64_t now=bc_monotonic_ms();
        status=now>=s->deadline ? BC_TIMEOUT : bc_ipmi_udp_create_timeout(
            (bc_string){relay,strlen(relay)},bound.port,(uint32_t)(s->deadline-now),&s->relay);
    }
    if (status!=BC_OK) { bc_ipmi_socks5_destroy(&s->api); return status; }
    s->target.type=BC_SOCKS5_DOMAIN; s->target.length=(uint8_t)host.length; s->target.port=port;
    memcpy(s->target.address,host.data,(size_t)host.length);
    if (inet_pton(AF_INET,name,s->target.address)==1) { s->target.type=BC_SOCKS5_IPV4; s->target.length=4; }
    else if (inet_pton(AF_INET6,name,s->target.address)==1) { s->target.type=BC_SOCKS5_IPV6; s->target.length=16; }
    *out=&s->api; return BC_OK;
}

#else
bc_status bc_ipmi_socks5_create(bc_string host, uint16_t port, const bc_socks5_proxy *proxy,
    uint32_t timeout, bc_ipmi_io **out) {
    (void)host; (void)port; (void)proxy; (void)timeout;
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL; return BC_UNSUPPORTED;
}
void bc_ipmi_socks5_destroy(bc_ipmi_io *io) { (void)io; }
#endif

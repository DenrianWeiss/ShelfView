#ifndef BCONTROL_IPMI_SESSION_INTERNAL_H
#define BCONTROL_IPMI_SESSION_INTERNAL_H
#include "bcontrol/ipmi_session.h"
typedef bc_status (*bc_ipmi_payload_handler)(void *, const uint8_t *, uint32_t, uint32_t);
bc_status bc_ipmi_payload_attach(bc_ipmi_session *, void *, bc_ipmi_payload_handler);
void bc_ipmi_payload_detach(bc_ipmi_session *, void *);
bc_status bc_ipmi_payload_send(bc_ipmi_session *, const uint8_t *, uint32_t);
bc_status bc_ipmi_payload_poll(bc_ipmi_session *, uint32_t);
#endif

#ifndef BCONTROL_IRMC_DISCOVERY_H
#define BCONTROL_IRMC_DISCOVERY_H

#include "bcontrol/kvm_transport.h"

#define BC_IRMC_AVR_JNLP "/avr.jnlp"

int bc_irmc_service_root_matches(bc_bytes body);
bc_status bc_irmc_send(bc_kvm_transport *, const uint8_t *, uint32_t);

#endif

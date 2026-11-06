#ifndef BC_AGENT_IPMI_BUDGET_H
#define BC_AGENT_IPMI_BUDGET_H
#include "bcontrol/ipmi_io_guard.h"
#include "bcontrol/operation.h"
typedef struct {
    bc_operation *operation;
    bc_ipmi_io_guard *guard;
    bc_status status;
    int cleaning;
} bc_agent_ipmi_budget;
bc_status bc_agent_ipmi_budget_open(bc_agent_ipmi_budget *, const bc_ipmi_io *, uint32_t);
void bc_agent_ipmi_budget_unlimit(bc_agent_ipmi_budget *);
void bc_agent_ipmi_budget_cleanup(bc_agent_ipmi_budget *);
void bc_agent_ipmi_budget_destroy(bc_agent_ipmi_budget *);
#endif

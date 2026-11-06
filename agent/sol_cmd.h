#ifndef BC_AGENT_SOL_CMD_H
#define BC_AGENT_SOL_CMD_H
#include "bcontrol/ipmi_session.h"
#include "ipmi_budget.h"
int bc_agent_sol_run(bc_ipmi_session *, uint16_t port, bc_agent_ipmi_budget *);
#endif

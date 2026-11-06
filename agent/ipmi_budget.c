#include "ipmi_budget.h"
#include "server.h"
static uint64_t now(void *user) { (void)user; return bc_agent_now_ms(); }
static bc_status check(void *user, uint32_t *remaining) {
    bc_agent_ipmi_budget *budget = user;
    if (budget->status != BC_OK) return budget->status;
    if (budget->operation) return bc_operation_remaining(budget->operation, now(NULL), remaining);
    *remaining = UINT32_MAX;
    return BC_OK;
}
bc_status bc_agent_ipmi_budget_open(bc_agent_ipmi_budget *budget, const bc_ipmi_io *io, uint32_t timeout) {
    budget->status = bc_operation_create(now(NULL), timeout, &budget->operation);
    if (budget->status == BC_OK)
        budget->status = bc_ipmi_io_guard_create(io, now, check, budget, &budget->guard);
    return budget->status;
}
void bc_agent_ipmi_budget_unlimit(bc_agent_ipmi_budget *budget) {
    bc_operation_destroy(budget->operation);
    budget->operation = NULL;
}
void bc_agent_ipmi_budget_cleanup(bc_agent_ipmi_budget *budget) {
    if (budget->cleaning) return;
    budget->cleaning = 1;
    bc_agent_ipmi_budget_unlimit(budget);
    budget->status = bc_operation_create(now(NULL), 3000, &budget->operation);
}
void bc_agent_ipmi_budget_destroy(bc_agent_ipmi_budget *budget) {
    bc_ipmi_io_guard_destroy(budget->guard);
    bc_agent_ipmi_budget_unlimit(budget);
}

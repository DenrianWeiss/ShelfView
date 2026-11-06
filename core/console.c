#include "bcontrol/console.h"
uint32_t bc_console_recovery(const bc_console_failure *failure, int authenticated,
    int alternate, const bc_console_retry_budget *budget) {
    if (!failure || !budget || failure->struct_size != sizeof(*failure) ||
        budget->struct_size != sizeof(*budget) || failure->status == BC_OK ||
        failure->status == BC_CANCELLED) return BC_CONSOLE_RECOVERY_STOP;
    switch (failure->cause) {
    case BC_CONSOLE_CAUSE_CREDENTIALS: case BC_CONSOLE_CAUSE_ACCESS_DENIED:
    case BC_CONSOLE_CAUSE_BUSY: case BC_CONSOLE_CAUSE_LOCKED: return BC_CONSOLE_RECOVERY_STOP;
    default: break;
    }
    if (!authenticated || (failure->phase != BC_CONSOLE_PHASE_VALIDATION &&
        failure->phase != BC_CONSOLE_PHASE_MEDIA && failure->phase != BC_CONSOLE_PHASE_LAUNCH))
        return BC_CONSOLE_RECOVERY_STOP;
    int session = failure->cause == BC_CONSOLE_CAUSE_SESSION_REJECTED ||
        failure->cause == BC_CONSOLE_CAUSE_SESSION_EXPIRED;
    if (session && budget->ticket_refreshes == 0) return BC_CONSOLE_RECOVERY_REFRESH_TICKET;
    if (alternate && budget->profile_fallbacks == 0 &&
        (session || failure->cause == BC_CONSOLE_CAUSE_PROTOCOL)) return BC_CONSOLE_RECOVERY_ALTERNATE;
    return BC_CONSOLE_RECOVERY_STOP;
}

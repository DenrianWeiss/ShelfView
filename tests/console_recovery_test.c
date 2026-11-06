#include "bcontrol/console.h"
#include <assert.h>
#include <stddef.h>

static const bc_service_profile initial = {sizeof(bc_service_profile), BC_SERVICE_KVM,
    BC_SERVICE_FAMILY_MEGARAC, BC_SERVICE_MEGARAC_KVM_H5_438, BC_SERVICE_EVIDENCE_DESCRIPTOR};
static const bc_service_profile alternate = {sizeof(bc_service_profile), BC_SERVICE_KVM,
    BC_SERVICE_FAMILY_MEGARAC, BC_SERVICE_MEGARAC_KVM_JVIEWER_195, BC_SERVICE_EVIDENCE_DESCRIPTOR};
static bc_console_recovery_op *create(void) {
    bc_console_recovery_op *op = NULL;
    assert(bc_console_recovery_op_create(&initial, 100, 1000, &op) == BC_OK && op);
    return op;
}
static bc_console_failure failure(const bc_service_profile *p, uint32_t cause) {
    return (bc_console_failure){sizeof(bc_console_failure), BC_AUTHENTICATION_FAILED,
        BC_CONSOLE_PHASE_VALIDATION, cause, p->variant, 0, 3, p->service, p->family};
}
static void budget_and_cleanup(void) {
    bc_console_recovery_op *op = create();
    bc_console_failure rejected = failure(&initial, BC_CONSOLE_CAUSE_SESSION_REJECTED);
    bc_service_profile next;
    uint32_t action;
    assert(bc_console_recovery_op_failed(op, 1, &rejected, 1, &alternate, 0, 110, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_REFRESH_TICKET);
    const bc_console_recovery_view *view = bc_console_recovery_op_view_get(op);
    assert(view->state == BC_CONSOLE_RECOVERY_CLEANUP && view->budget.ticket_refreshes == 1);
    assert(bc_console_recovery_op_failed(op, 1, &rejected, 1, &alternate, 0, 111, &action) == BC_BUSY);
    assert(action == BC_CONSOLE_RECOVERY_STOP && !view->budget.profile_fallbacks);
    assert(bc_console_recovery_op_resume(op, 1, 1, 120, &next) == BC_OK);
    assert(view->attempt == 2 && next.variant == initial.variant);
    assert(bc_console_recovery_op_failed(op, 1, &rejected, 1, &alternate, 0, 121, &action) == BC_CANCELLED);
    assert(bc_console_recovery_op_failed(op, 2, &rejected, 1, &alternate, 0, 130, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_ALTERNATE && view->budget.profile_fallbacks == 1);
    assert(bc_console_recovery_op_resume(op, 2, 1, 140, &next) == BC_OK);
    assert(view->attempt == 3 && next.variant == alternate.variant);
    rejected = failure(&alternate, BC_CONSOLE_CAUSE_SESSION_REJECTED);
    assert(bc_console_recovery_op_failed(op, 3, &rejected, 1, &initial, 0, 150, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_STOP && view->state == BC_CONSOLE_RECOVERY_STOPPED);
    assert(view->budget.ticket_refreshes == 1 && view->budget.profile_fallbacks == 1);
    bc_console_recovery_op_destroy(op);
}
static void stop_conditions(void) {
    const uint32_t causes[] = {BC_CONSOLE_CAUSE_CREDENTIALS, BC_CONSOLE_CAUSE_ACCESS_DENIED,
        BC_CONSOLE_CAUSE_BUSY, BC_CONSOLE_CAUSE_LOCKED, BC_CONSOLE_CAUSE_AUTH_REJECTED};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        bc_console_recovery_op *op = create(); uint32_t action;
        bc_console_failure rejected = failure(&initial, causes[i]);
        assert(bc_console_recovery_op_failed(op, 1, &rejected, 1, &alternate, 0, 110, &action) == BC_OK);
        assert(action == BC_CONSOLE_RECOVERY_STOP);
        bc_console_recovery_op_destroy(op);
    }
    for (int reason = 0; reason < 3; ++reason) {
        bc_console_recovery_op *op = create(); uint32_t action;
        bc_console_failure rejected = failure(&initial, BC_CONSOLE_CAUSE_SESSION_EXPIRED);
        if (reason == 2) rejected.status = BC_CANCELLED;
        assert(bc_console_recovery_op_failed(op, 1, &rejected, reason != 0,
            &alternate, reason == 1, 110, &action) == BC_OK);
        assert(action == BC_CONSOLE_RECOVERY_STOP);
        bc_console_recovery_op_destroy(op);
    }
}
static void independent_evidence(void) {
    const bc_service_profile invalid[] = {
        {sizeof(bc_service_profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_IDRAC,
            BC_SERVICE_IDRAC_KVM_EHTML5, BC_SERVICE_EVIDENCE_MANUAL},
        {sizeof(bc_service_profile), BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_IDRAC,
            BC_SERVICE_IDRAC_MEDIA_EHTML5, BC_SERVICE_EVIDENCE_HANDSHAKE},
        {sizeof(bc_service_profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_IDRAC, 200, BC_SERVICE_EVIDENCE_DESCRIPTOR},
        {sizeof(bc_service_profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC,
            BC_SERVICE_MEGARAC_KVM_H5_438, BC_SERVICE_EVIDENCE_HANDSHAKE}
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        bc_console_recovery_op *op = create(); uint32_t action;
        bc_console_failure mismatch = failure(&initial, BC_CONSOLE_CAUSE_PROTOCOL);
        assert(bc_console_recovery_op_failed(op, 1, &mismatch, 1, invalid + i, 0, 110, &action) == BC_OK);
        assert(action == BC_CONSOLE_RECOVERY_STOP);
        bc_console_recovery_op_destroy(op);
    }
    bc_console_recovery_op *op = create(); uint32_t action;
    bc_console_failure mismatch = failure(&initial, BC_CONSOLE_CAUSE_PROTOCOL);
    bc_service_profile other = invalid[0]; other.evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR;
    assert(bc_console_recovery_op_failed(op, 1, &mismatch, 1, &other, 0, 110, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_ALTERNATE);
    bc_service_profile next;
    assert(bc_console_recovery_op_resume(op, 1, 1, 120, &next) == BC_OK && next.family == BC_SERVICE_FAMILY_IDRAC);
    assert(bc_console_recovery_op_succeeded(op, 2, 130) == BC_OK);
    assert(bc_console_recovery_op_view_get(op)->state == BC_CONSOLE_RECOVERY_SUCCEEDED);
    assert(!bc_console_recovery_op_failure_get(op));
    bc_console_recovery_op_destroy(op);
}
static void lifecycle(void) {
    for (int reason = 0; reason < 4; ++reason) {
        bc_console_recovery_op *op = create(); uint32_t action;
        bc_console_failure rejected = failure(&initial, BC_CONSOLE_CAUSE_SESSION_REJECTED);
        assert(bc_console_recovery_op_failed(op, 1, &rejected, 1, NULL, 0, 110, &action) == BC_OK);
        if (reason == 0) bc_console_recovery_op_cancel(op);
        bc_service_profile next;
        bc_status expected = reason == 0 ? BC_CANCELLED : reason == 1 ? BC_TIMEOUT :
            reason == 2 ? BC_IO_ERROR : BC_INVALID_ARGUMENT;
        assert(bc_console_recovery_op_resume(op, 1, reason != 2,
            reason == 1 ? 1100 : reason == 3 ? 109 : 120, &next) == expected);
        assert(!next.evidence);
        if (reason == 2) assert(bc_console_recovery_op_failure_get(op)->cause == BC_CONSOLE_CAUSE_CLEANUP_UNCONFIRMED);
        assert(bc_console_recovery_op_view_get(op)->budget.ticket_refreshes == 1);
        bc_console_recovery_op_destroy(op);
    }
    bc_console_recovery_op *op = create(); uint32_t action;
    bc_console_failure unrelated = failure(&alternate, BC_CONSOLE_CAUSE_SESSION_REJECTED);
    assert(bc_console_recovery_op_failed(op, 1, &unrelated, 1, NULL, 0, 110, &action) == BC_INVALID_ARGUMENT);
    assert(!bc_console_recovery_op_view_get(op)->budget.ticket_refreshes);
    bc_console_recovery_op_destroy(op);
}
static void remaining_budget(void) {
    bc_console_recovery_op *op = create(); uint32_t remaining = 7, action;
    assert(bc_console_recovery_op_remaining(op, 1, 100, &remaining) == BC_OK && remaining == 1000);
    assert(bc_console_recovery_op_remaining(op, 1, 150, &remaining) == BC_OK && remaining == 950);
    /* An old callback cannot advance the current operation's clock. */
    assert(bc_console_recovery_op_remaining(op, 0, 500, &remaining) == BC_CANCELLED && !remaining);
    bc_console_failure rejected = failure(&initial, BC_CONSOLE_CAUSE_SESSION_REJECTED);
    assert(bc_console_recovery_op_failed(op, 1, &rejected, 1, NULL, 0, 160, &action) == BC_OK);
    assert(bc_console_recovery_op_remaining(op, 1, 200, &remaining) == BC_OK && remaining == 900);
    bc_service_profile next;
    assert(bc_console_recovery_op_resume(op, 1, 1, 210, &next) == BC_OK);
    assert(bc_console_recovery_op_remaining(op, 2, 1099, &remaining) == BC_OK && remaining == 1);
    assert(bc_console_recovery_op_remaining(op, 2, 1100, &remaining) == BC_TIMEOUT && !remaining);
    assert(bc_console_recovery_op_remaining(op, 2, 1001, &remaining) == BC_CANCELLED && !remaining);
    assert(bc_console_recovery_op_failure_get(op)->status == BC_TIMEOUT);
    bc_console_recovery_op_destroy(op);
    op = create();
    assert(bc_console_recovery_op_remaining(op, 1, 99, &remaining) == BC_INVALID_ARGUMENT && !remaining);
    assert(bc_console_recovery_op_remaining(op, 1, 101, &remaining) == BC_CANCELLED && !remaining);
    bc_console_recovery_op_destroy(op);
    op = create();
    assert(bc_console_recovery_op_succeeded(op, 1, 101) == BC_OK);
    assert(bc_console_recovery_op_remaining(op, 1, 102, &remaining) == BC_CANCELLED && !remaining);
    bc_console_recovery_op_destroy(op);
    assert(bc_console_recovery_op_remaining(NULL, 1, 0, &remaining) == BC_INVALID_ARGUMENT && !remaining);
    assert(bc_console_recovery_op_remaining(NULL, 1, 0, NULL) == BC_INVALID_ARGUMENT);
}
static void runtime_incidents(void) {
    bc_console_recovery_op *op = create();
    bc_console_failure lost = failure(&initial, BC_CONSOLE_CAUSE_UNKNOWN);
    lost.phase = BC_CONSOLE_PHASE_TRANSPORT; lost.status = BC_IO_ERROR;
    uint32_t action, remaining;
    assert(bc_console_recovery_op_disconnected(op, 1, &lost, 1, &alternate, 0, 110, 1000, &action) == BC_CANCELLED);
    assert(bc_console_recovery_op_succeeded(op, 1, 120) == BC_OK);
    assert(bc_console_recovery_op_disconnected(op, 1, &lost, 1, &alternate, 0, 5000, 0, &action) == BC_INVALID_ARGUMENT);
    assert(bc_console_recovery_op_view_get(op)->state == BC_CONSOLE_RECOVERY_SUCCEEDED);
    assert(bc_console_recovery_op_disconnected(op, 1, &lost, 1, &alternate, 0, 5000, 2500, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_RECONNECT_SAME);
    assert(bc_console_recovery_op_remaining(op, 1, 5100, &remaining) == BC_OK && remaining == 2400);
    assert(bc_console_recovery_op_disconnected(op, 1, &lost, 1, &alternate, 0, 5200, 1000, &action) == BC_CANCELLED);
    bc_service_profile next;
    assert(bc_console_recovery_op_resume(op, 1, 1, 5200, &next) == BC_OK);
    assert(next.variant == initial.variant);
    assert(bc_console_recovery_op_succeeded(op, 2, 5300) == BC_OK);
    assert(bc_console_recovery_op_disconnected(op, 1, &lost, 1, &alternate, 0, 99999, 1000, &action) == BC_CANCELLED);
    assert(bc_console_recovery_op_disconnected(op, 2, &lost, 1, &alternate, 0, 8000, 1000, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_RECONNECT_SAME);
    assert(bc_console_recovery_op_resume(op, 2, 1, 8010, &next) == BC_OK);
    assert(bc_console_recovery_op_failed(op, 3, &lost, 1, &alternate, 0, 8020, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_STOP);
    bc_console_recovery_op_destroy(op);

    op = create();
    assert(bc_console_recovery_op_succeeded(op, 1, 120) == BC_OK);
    lost.cause = BC_CONSOLE_CAUSE_SESSION_EXPIRED; lost.status = BC_AUTHENTICATION_FAILED;
    assert(bc_console_recovery_op_disconnected(op, 1, &lost, 1, &alternate, 0, 5000, 1000, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_REFRESH_TICKET);
    assert(bc_console_recovery_op_resume(op, 1, 1, 5010, &next) == BC_OK);
    assert(bc_console_recovery_op_failed(op, 2, &lost, 1, &alternate, 0, 5020, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_ALTERNATE);
    assert(bc_console_recovery_op_resume(op, 2, 1, 5030, &next) == BC_OK);
    lost.family = next.family; lost.profile = next.variant;
    assert(bc_console_recovery_op_failed(op, 3, &lost, 1, &initial, 0, 5040, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_STOP);
    bc_console_recovery_op_destroy(op);
    bc_service_profile media = {sizeof(media), BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_IDRAC,
        BC_SERVICE_IDRAC_MEDIA_EHTML5, BC_SERVICE_EVIDENCE_DESCRIPTOR};
    assert(bc_console_recovery_op_create(&media, 100, 1000, &op) == BC_OK);
    assert(bc_console_recovery_op_succeeded(op, 1, 120) == BC_OK);
    lost = failure(&media, BC_CONSOLE_CAUSE_SESSION_EXPIRED); lost.phase = BC_CONSOLE_PHASE_TRANSPORT;
    assert(bc_console_recovery_op_disconnected(op, 1, &lost, 1, NULL, 0, 5000, 1000, &action) == BC_UNSUPPORTED);
    assert(action == BC_CONSOLE_RECOVERY_STOP);
    bc_console_recovery_op_destroy(op);
}
static void runtime_gates(void) {
    const uint32_t causes[] = {BC_CONSOLE_CAUSE_CREDENTIALS, BC_CONSOLE_CAUSE_ACCESS_DENIED,
        BC_CONSOLE_CAUSE_LOCKED, BC_CONSOLE_CAUSE_BUSY, BC_CONSOLE_CAUSE_AUTH_REJECTED,
        BC_CONSOLE_CAUSE_SESSION_REJECTED, BC_CONSOLE_CAUSE_PROTOCOL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        bc_console_recovery_op *op = create(); uint32_t action;
        assert(bc_console_recovery_op_succeeded(op, 1, 120) == BC_OK);
        bc_console_failure lost = failure(&initial, causes[i]); lost.phase = BC_CONSOLE_PHASE_TRANSPORT;
        assert(bc_console_recovery_op_disconnected(op, 1, &lost, 1, &alternate, 0, 5000, 1000, &action) == BC_OK);
        assert(action == BC_CONSOLE_RECOVERY_STOP);
        bc_console_recovery_op_destroy(op);
    }
    for (int reason = 0; reason < 6; ++reason) {
        bc_console_recovery_op *op = create(); uint32_t action;
        assert(bc_console_recovery_op_succeeded(op, 1, 120) == BC_OK);
        bc_console_failure lost = failure(&initial, BC_CONSOLE_CAUSE_UNKNOWN);
        lost.phase = BC_CONSOLE_PHASE_TRANSPORT; lost.status = BC_IO_ERROR;
        if (reason == 2) lost.status = BC_TLS_ERROR;
        if (reason == 3) lost.status = BC_CANCELLED;
        if (reason == 4) bc_console_recovery_op_cancel(op);
        bc_status expected = reason == 4 ? BC_CANCELLED : reason == 5 ? BC_INVALID_ARGUMENT : BC_OK;
        assert(bc_console_recovery_op_disconnected(op, 1, &lost, reason != 0, &alternate,
            reason == 1, reason == 5 ? 119 : 5000, 1000, &action) == expected);
        assert(action == BC_CONSOLE_RECOVERY_STOP);
        bc_console_recovery_op_destroy(op);
    }
    bc_console_recovery_op *op = create(); uint32_t action;
    bc_console_failure lost = failure(&initial, BC_CONSOLE_CAUSE_SESSION_EXPIRED);
    lost.phase = BC_CONSOLE_PHASE_TRANSPORT;
    /* Initial transport failures have no successfully streaming connection. */
    assert(bc_console_recovery_op_failed(op, 1, &lost, 1, &alternate, 0, 110, &action) == BC_OK);
    assert(action == BC_CONSOLE_RECOVERY_STOP);
    bc_console_recovery_op_destroy(op);
}
int main(void) {
    budget_and_cleanup(); stop_conditions(); independent_evidence(); lifecycle(); remaining_budget();
    runtime_incidents(); runtime_gates();
    return 0;
}

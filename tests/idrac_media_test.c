#include "bcontrol/idrac_media.h"
#include <assert.h>
#include <string.h>

typedef struct fixture { uint8_t messages[8][4096]; uint32_t lengths[8], count, reads; } fixture;
static bc_status emit(void *context, const uint8_t *data, uint32_t length) {
    fixture *f = context;
    assert(f->count < 8 && length <= sizeof(f->messages[0]));
    memcpy(f->messages[f->count], data, length); f->lengths[f->count++] = length;
    return BC_OK;
}
static bc_status read_image(void *context, uint64_t offset, uint32_t length, uint8_t *out) {
    fixture *f = context;
    assert(offset + length <= 4096); ++f->reads;
    for (uint32_t i = 0; i < length; ++i) out[i] = (uint8_t)((offset + i) / 2048 + 17);
    return BC_OK;
}
int main(void) {
    fixture f = {0}; bc_idrac_media *m = NULL;
    bc_string key = {"abcdefghijklmnopqrstuvwx", 24};
    assert(bc_idrac_media_create(emit, &f, key, &m) == BC_OK);
    bc_media_session *session = NULL;
    assert(bc_idrac_media_wrap(m, &session) == BC_OK);
    assert(!bc_service_profile_verified(bc_idrac_media_profile_get(m), BC_SERVICE_LOCAL_MEDIA));
    bc_idrac_media_source source = {4096, &f, read_image};
    assert(bc_idrac_media_attach_cd(m, &source) == BC_UNSUPPORTED);
    uint8_t connected[40] = {16,0,0,0, 0,0,0,0, 24,0,0,0, 0x78,0x56,0x34,0x12};
    memcpy(connected + 16, "abcdefghijklmnopqrstuvwx", 24);
    assert(bc_media_session_feed(session, (bc_bytes){connected, sizeof(connected)}) == BC_OK);
    assert(bc_service_profile_verified(bc_idrac_media_profile_get(m), BC_SERVICE_LOCAL_MEDIA));
    assert(!bc_service_profile_can_attempt(bc_idrac_media_profile_get(m), BC_SERVICE_KVM));
    uint8_t auth[] = {0,32,0,0, 0,0,0,0, 0,0,0,0, 0x78,0x56,0x34,0x12};
    assert(bc_media_session_feed(session, (bc_bytes){auth, sizeof(auth)}) == BC_OK);
    assert(f.lengths[0] == 48 && f.messages[0][8] == 32);
    assert(!memcmp(f.messages[0] + 16, connected + 16, 24));
    assert(bc_idrac_media_attach_cd(m, &source) == BC_OK);
    assert(f.count == 4 && f.lengths[1] == 44 && f.lengths[2] == 36 && f.lengths[3] == 4096);
    assert(f.messages[1][16] == 2 && f.messages[1][36] == 1 && f.messages[1][40] == 20);
    assert(f.messages[3][0] == 17 && f.messages[3][2048] == 18);
    assert(bc_idrac_media_attach_cd(m, &source) == BC_BUSY);
    uint8_t request[] = {1,0,0,0, 1,0,0,0, 12,0,0,0, 0x78,0x56,0x34,0x12,
        1,0,0,0, 1,0,0,0, 0,8,0,0};
    assert(bc_media_session_feed(session, (bc_bytes){request, sizeof(request)}) == BC_OK);
    assert(f.count == 6 && f.lengths[5] == 2048 && f.messages[5][0] == 18);
    request[16] = 2;
    assert(bc_media_session_feed(session, (bc_bytes){request, sizeof(request)}) == BC_INVALID_ARGUMENT);
    assert(f.count == 6 && f.reads == 2);
    request[12] = 0;
    assert(bc_media_session_feed(session, (bc_bytes){request, sizeof(request)}) == BC_PROTOCOL_ERROR);
    assert(bc_media_session_control(session, BC_MEDIA_CONTROL_EJECT) == BC_OK);
    assert(f.messages[6][0] == 8 && !memcmp(f.messages[6] + 12, connected + 12, 4));
    assert(bc_idrac_media_state_get(m)->attached && bc_idrac_media_state_get(m)->ejecting);
    uint8_t ejected[] = {0,1,0,0, 1,0,0,0, 4,0,0,0, 0x78,0x56,0x34,0x12, 25,0,0,0};
    assert(bc_media_session_feed(session, (bc_bytes){ejected, sizeof(ejected)}) == BC_OK);
    assert(!bc_idrac_media_state_get(m)->attached && !bc_idrac_media_state_get(m)->ejecting);
    assert(bc_media_session_control(session, BC_MEDIA_CONTROL_KEEPALIVE) == BC_OK);
    assert(f.messages[7][1] == 8 && f.lengths[7] == 16);
    bc_media_session_info info = {.struct_size = sizeof(info)};
    assert(bc_media_session_info_get(session, &info) == BC_OK);
    assert(info.flags & BC_MEDIA_REMOVAL_CONFIRMED);
    bc_media_session_destroy(session);
    bc_idrac_media_destroy(m);

    /* Some firmware asks for key2 before sending a challenge notification. */
    fixture early = {0}; bc_idrac_media *m2 = NULL;
    assert(bc_idrac_media_create(emit, &early, key, &m2) == BC_OK);
    uint8_t auth2[] = {0,32,0,0, 0,0,0,0, 0,0,0,0, 0x44,0x33,0x22,0x11};
    assert(bc_idrac_media_feed_message(m2, auth2, sizeof(auth2)) == BC_OK);
    assert(bc_idrac_media_state_get(m2)->ready);
    assert(!bc_service_profile_verified(bc_idrac_media_profile_get(m2), BC_SERVICE_LOCAL_MEDIA));
    assert(bc_idrac_media_attach_cd(m2, &source) == BC_UNSUPPORTED);
    assert(early.count == 1 && early.lengths[0] == 48);
    assert(!memcmp(early.messages[0] + 16, "abcdefghijklmnopqrstuvwx", 24));
    /* The device keeps media sessions after a window close unless unmapped. */
    assert(bc_idrac_media_unmap(m2) == BC_OK);
    assert(early.count == 2 && early.lengths[1] == 16);
    assert(early.messages[1][0] == 0 && early.messages[1][1] == 4);
    assert(!memcmp(early.messages[1] + 12, auth2 + 12, 4));
    /* Status notifications may use token 0; the client only validates tokens on
     * read requests. */
    uint8_t status_zero[] = {0,1,0,0, 1,0,0,0, 4,0,0,0, 0,0,0,0, 0,0,0,0};
    assert(bc_idrac_media_feed_message(m2, status_zero, sizeof(status_zero)) == BC_OK);
    assert(!bc_service_profile_verified(bc_idrac_media_profile_get(m2), BC_SERVICE_LOCAL_MEDIA));
    const uint32_t codes[] = {89, 39, 84, 42};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        status_zero[16] = (uint8_t)codes[i];
        assert(bc_idrac_media_feed_message(m2, status_zero, sizeof(status_zero)) ==
            (codes[i] == 42 ? BC_BUSY : BC_AUTHENTICATION_FAILED));
        const bc_console_failure *failure = bc_idrac_media_failure_get(m2);
        assert(failure && failure->device_code == (int32_t)codes[i]);
        assert(failure->service == BC_SERVICE_LOCAL_MEDIA && failure->family == BC_SERVICE_FAMILY_IDRAC);
        uint32_t cause = codes[i] == 89 ? BC_CONSOLE_CAUSE_SESSION_REJECTED :
            codes[i] == 42 ? BC_CONSOLE_CAUSE_BUSY : BC_CONSOLE_CAUSE_ACCESS_DENIED;
        assert(failure->cause == cause);
        bc_console_retry_budget budget = {sizeof(budget), 0, 0};
        assert(bc_console_recovery(failure, 1, 0, &budget) ==
            (codes[i] == 89 ? BC_CONSOLE_RECOVERY_REFRESH_TICKET : BC_CONSOLE_RECOVERY_STOP));
    }
    bc_idrac_media_destroy(m2);
    return 0;
}

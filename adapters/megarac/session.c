#include "megarac.h"
#include "bcontrol/megarac_session.h"
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/console_session.h"
#include "bcontrol/wire.h"
#include "../../core/log_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OUTPUT_CAPACITY 8192u

struct bc_megarac_session {
    uint32_t media_removal_unconfirmed, media_flags;
    uint32_t kind;
    uint32_t state;
    uint32_t flags;
    int greeting_auth_sent;
    uint32_t tunnel_phase, tunnel_length;
    char tunnel_reply[256];
    char client_ip[BC_MEGARAC_MAX_IP];
    char username[BC_MEGARAC_MAX_TOKEN];
    char client_mac[64];
    bc_megarac_kvm_info info;
    bc_megarac_assembler assembler;
    uint32_t sequence;
    uint8_t keys[6], modifiers, repeat_key, key_sync;
    uint64_t repeat_due, key_sync_due, key_last_time;
    uint8_t output[OUTPUT_CAPACITY];
    uint32_t output_length;
    uint8_t *input;
    uint32_t input_length, input_capacity;
    uint16_t soc_fragment;
    bc_console_failure failure;
    bc_service_profile profile;
};

static bc_status session_queue(bc_megarac_session *session, const uint8_t *data, uint32_t length) {
    if (session->output_length + length > OUTPUT_CAPACITY) return BC_LIMIT_EXCEEDED;
    memcpy(session->output + session->output_length, data, length);
    session->output_length += length;
    return BC_OK;
}

static bc_status queue_command(bc_megarac_session *session, uint16_t type, uint16_t status, const uint8_t *payload, uint32_t length) {
    uint8_t data[512];
    bc_megarac_ivtp header = {type, status, length};
    uint32_t written = 0;
    bc_status result = bc_megarac_ivtp_encode(&header, payload, data, sizeof(data), &written);
    /* This JViewer relay counts the header in the validation length only. */
    if (result == BC_OK && session->info.single_port && BC_MEGARAC_IS_JVIEWER_373(session->kind) && type == BC_MEGARAC_OP_VALIDATE)
        bc_wire_write_le(data + 2, written, 4);
    return result == BC_OK ? session_queue(session, data, written) : result;
}

bc_status bc_megarac_session_create(const bc_megarac_session_options *options, bc_megarac_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || !options->info || !options->username || !options->client_ip ||
        (!BC_MEGARAC_IS_JVIEWER_373(options->kind) && !BC_MEGARAC_IS_JVIEWER_195(options->kind) && !BC_MEGARAC_IS_H5(options->kind))) return BC_INVALID_ARGUMENT;
    bc_megarac_session *session = calloc(1, sizeof(*session));
    if (!session) return BC_NO_MEMORY;
    if (options->frame_capacity > UINT32_MAX - BC_MEGARAC_IVTP_HEADER_SIZE) { free(session); return BC_LIMIT_EXCEEDED; }
    session->input_capacity = options->frame_capacity + BC_MEGARAC_IVTP_HEADER_SIZE;
    session->input = malloc(session->input_capacity);
    if (!session->input) { free(session); return BC_NO_MEMORY; }
    session->kind = options->kind;
    session->profile = (bc_service_profile){sizeof(session->profile), BC_SERVICE_KVM,
        BC_SERVICE_FAMILY_MEGARAC, options->kind == BC_MEGARAC_KVM_H5VIEWER_373 ? BC_SERVICE_MEGARAC_KVM_H5_373 :
        options->kind == BC_MEGARAC_KVM_H5VIEWER ? BC_SERVICE_MEGARAC_KVM_H5_438 :
        BC_MEGARAC_IS_JVIEWER_195(options->kind) ? BC_SERVICE_MEGARAC_KVM_JVIEWER_195 :
        BC_SERVICE_MEGARAC_KVM_JVIEWER_373, 0};
    session->info = *options->info;
    session->info.struct_size = sizeof(session->info);
    if (BC_MEGARAC_IS_JVIEWER_373(session->kind) && session->info.single_port)
        session->flags |= BC_MEGARAC_KEYBOARD_AUTOBREAK;
    snprintf(session->client_ip, sizeof(session->client_ip), "%s", options->client_ip);
    snprintf(session->username, sizeof(session->username), "%s", options->username);
    if (options->client_mac) snprintf(session->client_mac, sizeof(session->client_mac), "%s", options->client_mac);
    bc_status status = bc_megarac_assembler_init(&session->assembler, options->frame_buffer, options->frame_capacity);
    if (status != BC_OK) { free(session->input); free(session); return status; }
    *out = session;
    BC_LOG_INFO(BC_LOG_CATEGORY_VENDOR, "megarac.session.create", "kind=%u frame_capacity=%u user_len=%zu client_ip_len=%zu",
        session->kind, options->frame_capacity, strlen(session->username), strlen(session->client_ip));
    return BC_OK;
}

static bc_status legacy_auth(bc_megarac_session *session) {
    uint8_t auth[BC_MEGARAC_JVIEWER_AUTH_SIZE];
    bc_status status = bc_megarac_jviewer_auth(&session->info, session->client_ip,
        session->username, session->client_mac, auth, sizeof(auth));
    if (status == BC_OK && session->info.single_port)
        status = queue_command(session, BC_MEGARAC_OP_CONNECTION_COMPLETE, 0, NULL, 0);
    if (status == BC_OK && session->kind == BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION) {
        const char *end = memchr(session->info.cookie, 0, sizeof(session->info.cookie));
        if (!end || end == session->info.cookie) status = BC_INVALID_ARGUMENT;
        else status = queue_command(session, BC_MEGARAC_OP_WEB_SESSION, 0,
            (const uint8_t *)session->info.cookie, (uint32_t)(end - session->info.cookie));
    }
    if (status == BC_OK) status = queue_command(session, BC_MEGARAC_OP_VALIDATE, 0, auth,
        BC_MEGARAC_IS_JVIEWER_195(session->kind) ? 195 : sizeof(auth));
    memset(auth, 0, sizeof(auth));
    if (status == BC_OK && (session->info.single_port || BC_MEGARAC_IS_JVIEWER_195(session->kind)))
        status = queue_command(session, BC_MEGARAC_OP_RESUME, 0, NULL, 0);
    return status;
}

bc_status bc_megarac_session_start(bc_megarac_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_MEGARAC_STATE_IDLE) return BC_BUSY;
    bc_status status = BC_OK;
    if (!BC_MEGARAC_IS_H5(session->kind)) {
        if (session->info.single_port) {
            const bc_megarac_kvm_info *info = &session->info;
            uint8_t request[1024]; uint32_t n = 0;
            status = bc_megarac_tunnel_request(info, BC_MEGARAC_TUNNEL_VIDEO, request, sizeof(request), &n);
            if (status == BC_OK) status = session_queue(session, request, n);
            memset(request, 0, sizeof(request));
            if (status == BC_OK) session->tunnel_phase = 1;
        } else if (session->kind != BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION) status = legacy_auth(session);
    }
    if (status == BC_OK) session->state = BC_MEGARAC_STATE_AUTH;
    BC_LOG_INFO(BC_LOG_CATEGORY_VENDOR, "megarac.session.start", "kind=%u single_port=%u status=%s",
        session->kind, session->info.single_port, bc_status_string(status));
    return status;
}

static bc_status tunnel_feed(bc_megarac_session *session, uint8_t byte) {
    if (session->tunnel_length == sizeof(session->tunnel_reply) - 1) return BC_LIMIT_EXCEEDED;
    session->tunnel_reply[session->tunnel_length++] = (char)byte;
    uint32_t consumed = 0;
    const uint8_t *reply = (const uint8_t *)session->tunnel_reply;
    bc_status status = session->kind == BC_MEGARAC_KVM_JVIEWER_IRMC ?
        bc_megarac_tunnel_status_line(reply, session->tunnel_length, &consumed) :
        bc_megarac_tunnel_response(reply, session->tunnel_length, &consumed);
    if (status == BC_BUSY) return BC_OK;
    if (status != BC_OK) return status;
    session->tunnel_phase = 2;
    return BC_OK;
}

static bc_status push_soc_frame(bc_megarac_session *session, const uint8_t *data, uint32_t length) {
    bc_megarac_assembler *a = &session->assembler;
    if (length < 2) return BC_PROTOCOL_ERROR;
    uint16_t fragment = (uint16_t)bc_wire_read_le(data, 2);
    data += 2; length -= 2;
    if ((fragment & 0x7fff) == 0) {
        if (length < 34) return BC_PROTOCOL_ERROR;
        uint32_t size = (uint32_t)bc_wire_read_le(data + 5, 4);
        if (size > a->capacity || a->capacity - size < 34) return BC_LIMIT_EXCEEDED;
        memset(&a->header, 0, sizeof(a->header));
        a->header.struct_size = sizeof(a->header);
        a->header.source_width = a->header.width = (uint32_t)bc_wire_read_le(data + 9, 2);
        a->header.source_height = a->header.height = (uint32_t)bc_wire_read_le(data + 11, 2);
        if (!a->header.width || !a->header.height || a->header.width > 4096 || a->header.height > 4096) return BC_PROTOCOL_ERROR;
        a->header.compressed_size = size + 34;
        a->header.flags = BC_MEGARAC_VIDEO_SOC;
        a->received = 0; a->state = 1; session->soc_fragment = 0;
    }
    if ((fragment & 0x7fff) != session->soc_fragment++) return BC_PROTOCOL_ERROR;
    if (a->state != 1 || length > a->header.compressed_size - a->received) return BC_PROTOCOL_ERROR;
    memcpy(a->buffer + a->received, data, length); a->received += length;
    if (fragment & 0x8000) {
        if (a->received != a->header.compressed_size) return BC_PROTOCOL_ERROR;
        a->state = 2;
    }
    return BC_OK;
}

static bc_status handle_frame(bc_megarac_session *session, const bc_megarac_ivtp *header, const uint8_t *payload) {
    switch (header->type) {
    case BC_MEGARAC_OP_CONNECTION_ALLOWED: {
        if (session->kind == BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION &&
            !session->info.single_port && session->state == BC_MEGARAC_STATE_AUTH && !session->greeting_auth_sent) {
            if (header->length) return BC_PROTOCOL_ERROR;
            bc_status status = legacy_auth(session);
            if (status == BC_OK) session->greeting_auth_sent = 1;
            return status;
        }
        if (!BC_MEGARAC_IS_H5(session->kind) && session->tunnel_phase == 3 &&
            session->state == BC_MEGARAC_STATE_AUTH) {
            if (header->length) return BC_PROTOCOL_ERROR;
            session->tunnel_phase = 4;
            return legacy_auth(session);
        }
        if (!BC_MEGARAC_IS_H5(session->kind) || session->state != BC_MEGARAC_STATE_AUTH ||
            session->greeting_auth_sent) return BC_OK;
        if (header->length) return BC_PROTOCOL_ERROR;
        uint8_t auth[BC_MEGARAC_H5VIEWER_AUTH_SIZE];
        bc_status status;
        status = queue_command(session, BC_MEGARAC_OP_CONNECTION_COMPLETE, 1, NULL, 0);
        if (status == BC_OK) status = bc_megarac_h5viewer_auth(&session->info, session->client_ip, session->username,
            session->client_mac, auth, sizeof(auth));
        if (status == BC_OK) status = queue_command(session, BC_MEGARAC_OP_VALIDATE, 1, auth, session->kind == BC_MEGARAC_KVM_H5VIEWER_373 ? 373 : BC_MEGARAC_H5VIEWER_AUTH_SIZE);
        if (status == BC_OK) status = queue_command(session, BC_MEGARAC_OP_RESUME, 0, NULL, 0);
        memset(auth, 0, sizeof(auth));
        if (status == BC_OK) session->greeting_auth_sent = 1;
        return status;
    }
    case BC_MEGARAC_OP_VALIDATE_RESPONSE: {
        uint32_t result = header->length ? payload[0] : header->status;
        if (result != 1) {
            session->failure = (bc_console_failure){sizeof(session->failure), BC_AUTHENTICATION_FAILED,
                BC_CONSOLE_PHASE_VALIDATION, BC_CONSOLE_CAUSE_SESSION_REJECTED, session->profile.variant,
                0, result, BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC};
            session->state = BC_MEGARAC_STATE_ERROR; return BC_AUTHENTICATION_FAILED;
        }
        session->state = BC_MEGARAC_STATE_STREAMING;
        session->profile.evidence = BC_SERVICE_EVIDENCE_HANDSHAKE;
        if (session->kind == BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION)
            return queue_command(session, BC_MEGARAC_OP_REFRESH, 0, NULL, 0);
        if (session->kind == BC_MEGARAC_KVM_JVIEWER_IRMC) {
            /* iRMC JViewer restarts video after validation to request the initial frame. */
            static const uint16_t startup[] = {
                BC_MEGARAC_OP_RESUME, BC_MEGARAC_OP_KEYBOARD_LEDS, BC_MEGARAC_OP_PAUSE,
                BC_MEGARAC_OP_RESUME, BC_MEGARAC_OP_KEYBOARD_LEDS, BC_MEGARAC_OP_POWER_STATUS
            };
            for (size_t i = 0; i < sizeof(startup) / sizeof(startup[0]); ++i) {
                bc_status status = queue_command(session, startup[i], 0, NULL, 0);
                if (status != BC_OK) return status;
            }
        }
        if (BC_MEGARAC_IS_JVIEWER_373(session->kind) && !session->info.single_port)
            return queue_command(session, BC_MEGARAC_OP_RESUME, 0, NULL, 0);
        return BC_OK;
    }
    case BC_MEGARAC_OP_VIDEO_FRAGMENT: {
        bc_status status = session->kind == BC_MEGARAC_KVM_JVIEWER_195 || session->kind == BC_MEGARAC_KVM_JVIEWER_IRMC ?
            push_soc_frame(session, payload, header->length) :
            bc_megarac_assembler_push(&session->assembler, payload, header->length);
        if (status != BC_OK) return status;
        if (bc_megarac_assembler_frame(&session->assembler))
            session->flags = (session->flags & ~BC_MEGARAC_BLANK) | BC_MEGARAC_FRAME_READY;
        return BC_OK;
    }
    case BC_MEGARAC_OP_BLANK:
        session->flags = (session->flags & ~BC_MEGARAC_FRAME_READY) | BC_MEGARAC_BLANK;
        session->assembler.state = 0;
        return BC_OK;
    case BC_MEGARAC_OP_STOP:
        session->state = BC_MEGARAC_STATE_CLOSED;
        return BC_OK;
    case BC_MEGARAC_OP_REFRESH:
        return BC_OK;
    case BC_MEGARAC_OP_KEEP_ALIVE:
        if (session->info.single_port && BC_MEGARAC_IS_JVIEWER_373(session->kind)) return BC_OK;
        return queue_command(session, BC_MEGARAC_OP_KEEP_ALIVE, 0, NULL, 0);
    default:
        return BC_OK;
    }
}

static bc_status feed(bc_megarac_session *session, const uint8_t *data, uint32_t length, uint32_t *used, int stop_at_frame) {
    *used = 0;
    if (!session || (length && !data)) return BC_INVALID_ARGUMENT;
    if (session->state == BC_MEGARAC_STATE_ERROR) return BC_PROTOCOL_ERROR;
    while (length) {
        if (session->tunnel_phase == 1) {
            bc_status status = tunnel_feed(session, *data++);
            --length; ++*used;
            if (status != BC_OK) {
                session->failure = (bc_console_failure){sizeof(session->failure), status,
                    BC_CONSOLE_PHASE_TRANSPORT, status == BC_AUTHENTICATION_FAILED ? BC_CONSOLE_CAUSE_ACCESS_DENIED :
                    BC_CONSOLE_CAUSE_PROTOCOL, session->profile.variant, 0, 0, BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC};
                session->state = BC_MEGARAC_STATE_ERROR; return status;
            }
            continue;
        }
        if (session->tunnel_phase == 2) {
            session->tunnel_phase = 3;
            if (!*data) { ++data; --length; ++*used; continue; }
        }
        uint32_t target = BC_MEGARAC_IVTP_HEADER_SIZE;
        if (session->input_length >= target) {
            uint32_t payload_length = (uint32_t)bc_wire_read_le(session->input + 2, 4);
            if (payload_length > session->input_capacity - target) return BC_LIMIT_EXCEEDED;
            target += payload_length;
        }
        uint32_t copy = target - session->input_length;
        if (copy > length) copy = length;
        memcpy(session->input + session->input_length, data, copy);
        session->input_length += copy; data += copy; length -= copy;
        *used += copy;
        if (session->input_length < BC_MEGARAC_IVTP_HEADER_SIZE) continue;
        uint32_t payload_length = (uint32_t)bc_wire_read_le(session->input + 2, 4);
        if (payload_length > session->input_capacity - BC_MEGARAC_IVTP_HEADER_SIZE) return BC_LIMIT_EXCEEDED;
        if (session->input_length < payload_length + BC_MEGARAC_IVTP_HEADER_SIZE) continue;
        bc_megarac_ivtp header;
        const uint8_t *payload = NULL;
        uint32_t consumed = 0;
        bc_status status = bc_megarac_ivtp_decode(session->input, session->input_length, &header, &payload, &consumed);
        if (status == BC_OK) {
            status = handle_frame(session, &header, payload);
            if (status != BC_OK)
                BC_LOG_DEBUG(BC_LOG_CATEGORY_KVM, "megarac.packet.rejected", "type=%u length=%u status=%s",
                    header.type, header.length, bc_status_string(status));
        }
        session->input_length = 0;
        if (status != BC_OK) { session->state = BC_MEGARAC_STATE_ERROR; return status; }
        if (stop_at_frame && (session->flags & BC_MEGARAC_FRAME_READY)) break;
    }
    return BC_OK;
}

bc_status bc_megarac_session_feed(bc_megarac_session *session, const uint8_t *data, uint32_t length) {
    uint32_t consumed = 0;
    return feed(session, data, length, &consumed, 0);
}
const bc_console_failure *bc_megarac_session_failure_get(const bc_megarac_session *session) {
    return session && session->failure.status != BC_OK ? &session->failure : NULL;
}
const bc_service_profile *bc_megarac_session_profile_get(const bc_megarac_session *session) {
    return session ? &session->profile : NULL;
}

bc_status bc_megarac_session_feed_frame(bc_megarac_session *session, const uint8_t *data, uint32_t length, uint32_t *consumed) {
    if (!consumed) return BC_INVALID_ARGUMENT;
    *consumed = 0;
    if (session && (session->flags & BC_MEGARAC_FRAME_READY)) return BC_BUSY;
    return feed(session, data, length, consumed, 1);
}

bc_status bc_megarac_session_output(bc_megarac_session *session, uint8_t *data, uint32_t capacity, uint32_t *written) {
    if (!session || !written || (capacity && !data)) return BC_INVALID_ARGUMENT;
    uint32_t available = session->output_length;
    /* Legacy single-port relays consume one IVTP packet per TLS record. */
    if (session->tunnel_phase == 4 && available >= BC_MEGARAC_IVTP_HEADER_SIZE) {
        uint32_t packet = BC_MEGARAC_IVTP_HEADER_SIZE + (uint32_t)bc_wire_read_le(session->output + 2, 4);
        if (BC_MEGARAC_IS_JVIEWER_373(session->kind) && bc_wire_read_le(session->output, 2) == BC_MEGARAC_OP_VALIDATE)
            packet -= BC_MEGARAC_IVTP_HEADER_SIZE;
        if (packet <= available) available = packet;
        if (capacity < available) { *written = 0; return BC_LIMIT_EXCEEDED; }
    }
    uint32_t count = available < capacity ? available : capacity;
    if (count) memcpy(data, session->output, count);
    memmove(session->output, session->output + count, session->output_length - count);
    session->output_length -= count;
    *written = count;
    return BC_OK;
}

static bc_status queue_keyboard(bc_megarac_session *session, uint8_t modifiers, const uint8_t usages[6], int auto_break) {
    uint8_t packet[64];
    uint32_t written = 0;
    bc_status status = bc_megarac_hid_keyboard(session->sequence, modifiers, usages, packet, sizeof(packet), &written);
    if (status == BC_OK) {
        packet[42] = (uint8_t)auto_break;
        status = session_queue(session, packet, written);
    }
    if (status == BC_OK) ++session->sequence;
    return status;
}

bc_status bc_megarac_session_keyboard_mode(bc_megarac_session *session, uint32_t mode) {
    if (!session || mode > BC_MEGARAC_KEYBOARD_AUTO_BREAK) return BC_INVALID_ARGUMENT;
    if (session->state != BC_MEGARAC_STATE_IDLE) return BC_BUSY;
    if (mode == BC_MEGARAC_KEYBOARD_DEFAULT) return BC_OK;
    if (mode == BC_MEGARAC_KEYBOARD_AUTO_BREAK) session->flags |= BC_MEGARAC_KEYBOARD_AUTOBREAK;
    else session->flags &= ~BC_MEGARAC_KEYBOARD_AUTOBREAK;
    return BC_OK;
}

bc_status bc_megarac_session_keyboard(bc_megarac_session *session, uint8_t modifiers, const uint8_t usages[6]) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_MEGARAC_STATE_STREAMING) return BC_BUSY;
    if (!(session->flags & BC_MEGARAC_KEYBOARD_AUTOBREAK)) return queue_keyboard(session, modifiers, usages, 0);
    const uint8_t empty[6] = {0};
    int release_all = usages == NULL, released_lock = 0;
    if (!usages) usages = empty;
    if (session->output_length > OUTPUT_CAPACITY - 7 * 49) return BC_LIMIT_EXCEEDED;
    int pressed = 0;
    for (unsigned i = 0; i < 6; ++i) {
        if (!usages[i] || memchr(session->keys, usages[i], 6)) continue;
        uint8_t key[6] = {usages[i]};
        bc_status status = queue_keyboard(session, modifiers, key, 1);
        if (status != BC_OK) return status;
        session->repeat_key = usages[i] == 0x39 || usages[i] == 0x47 || usages[i] == 0x53 ? 0 : usages[i];
        session->repeat_due = 0;
        pressed = 1;
    }
    if (session->repeat_key && !memchr(usages, session->repeat_key, 6)) session->repeat_key = 0;
    for (unsigned i = 0; i < 6; ++i) {
        uint8_t key = session->keys[i];
        if ((key == 0x39 || key == 0x47 || key == 0x53) && !memchr(usages, key, 6)) released_lock = 1;
    }
    if (!pressed && (modifiers != session->modifiers || released_lock || release_all)) {
        bc_status status = queue_keyboard(session, modifiers, empty, 0);
        if (status != BC_OK) return status;
    }
    if (modifiers != session->modifiers) { session->key_sync = 1; session->key_sync_due = 0; }
    memcpy(session->keys, usages, 6);
    session->modifiers = modifiers;
    return BC_OK;
}

bc_status bc_megarac_session_keyboard_release(bc_megarac_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_MEGARAC_STATE_STREAMING) return BC_BUSY;
    bc_status status = queue_keyboard(session, 0, NULL, 0);
    if (status == BC_OK) {
        memset(session->keys, 0, sizeof(session->keys)); session->modifiers = 0;
        session->repeat_key = session->key_sync = 0;
        session->repeat_due = session->key_sync_due = 0;
    }
    return status;
}

bc_status bc_megarac_session_tick(bc_megarac_session *session, uint64_t now_ms) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_MEGARAC_STATE_STREAMING || !(session->flags & BC_MEGARAC_KEYBOARD_AUTOBREAK)) return BC_OK;
    if (now_ms < session->key_last_time || now_ms > UINT64_MAX - 500) return BC_INVALID_ARGUMENT;
    session->key_last_time = now_ms;
    if (session->key_sync) {
        if (!session->key_sync_due) session->key_sync_due = now_ms + 100;
        else if (now_ms >= session->key_sync_due) {
            bc_status status = queue_keyboard(session, session->modifiers, NULL, 0);
            if (status != BC_OK) return status;
            session->key_sync = 0;
        }
    }
    if (session->repeat_key) {
        if (!session->repeat_due) session->repeat_due = now_ms + 500;
        else if (now_ms >= session->repeat_due) {
            uint8_t key[6] = {session->repeat_key};
            bc_status status = queue_keyboard(session, session->modifiers, key, 1);
            if (status != BC_OK) return status;
            session->repeat_due = now_ms + 50;
        }
    }
    return BC_OK;
}

bc_status bc_megarac_session_mouse(bc_megarac_session *session, uint8_t buttons, uint16_t x, uint16_t y, int8_t wheel) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_MEGARAC_STATE_STREAMING) return BC_BUSY;
    uint8_t packet[64];
    uint32_t written = 0;
    bc_status status = bc_megarac_hid_mouse(session->sequence++, buttons, x, y, wheel, packet, sizeof(packet), &written);
    if (status == BC_OK && BC_MEGARAC_IS_JVIEWER_195(session->kind)) {
        uint8_t *iusb = packet + BC_MEGARAC_IVTP_HEADER_SIZE;
        iusb[21] = 4; iusb[11] = 0;
        uint8_t sum = 0;
        for (unsigned i = 0; i < 32; ++i) sum = (uint8_t)(sum + iusb[i]);
        iusb[11] = (uint8_t)(0u - sum);
    }
    return status == BC_OK ? session_queue(session, packet, written) : status;
}

bc_status bc_megarac_session_keepalive(bc_megarac_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    return queue_command(session, BC_MEGARAC_OP_KEEP_ALIVE, 0, NULL, 0);
}

bc_status bc_megarac_session_media_state(bc_megarac_session *session, uint8_t connected) {
    if (!session || connected > 1) return BC_INVALID_ARGUMENT;
    if (!bc_megarac_session_is_irmc(session) && !BC_MEGARAC_IS_JVIEWER_195(session->kind) &&
        !BC_MEGARAC_IS_H5(session->kind)) return BC_UNSUPPORTED;
    if (session->state != BC_MEGARAC_STATE_STREAMING) return BC_BUSY;
    bc_status status = queue_command(session, BC_MEGARAC_OP_MEDIA_STATE, connected, NULL, 0);
    if (status == BC_OK) {
        if (connected) { session->media_removal_unconfirmed = 1; session->media_flags |= BC_CONSOLE_INFO_MEDIA_SOURCE_ANNOUNCED; }
        else session->media_flags &= ~BC_CONSOLE_INFO_MEDIA_SOURCE_ANNOUNCED;
    }
    return status;
}

bc_status bc_megarac_session_media_mode(bc_megarac_session *session, uint8_t enabled) {
    if (!session || enabled > 1) return BC_INVALID_ARGUMENT;
    if (BC_MEGARAC_IS_H5(session->kind) || session->kind == BC_MEGARAC_KVM_JVIEWER_195_WEB_SESSION)
        return session->state == BC_MEGARAC_STATE_STREAMING ? BC_OK : BC_BUSY;
    if (session->kind != BC_MEGARAC_KVM_JVIEWER_195) return BC_UNSUPPORTED;
    if (session->state != BC_MEGARAC_STATE_STREAMING) return BC_BUSY;
    bc_status status = queue_command(session, BC_MEGARAC_OP_MEDIA_MODE, enabled, NULL, 0);
    if (status == BC_OK) {
        if (enabled) { session->media_removal_unconfirmed = 1; session->media_flags |= BC_CONSOLE_INFO_MEDIA_MODE_REQUESTED; }
        else session->media_flags &= ~BC_CONSOLE_INFO_MEDIA_MODE_REQUESTED;
    }
    return status;
}

uint32_t bc_megarac_session_media_removal_unconfirmed(const bc_megarac_session *session) {
    return session ? session->media_removal_unconfirmed : 0;
}

bc_status bc_megarac_session_close(bc_megarac_session *session) {
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state == BC_MEGARAC_STATE_CLOSED) return BC_OK;
    if (session->output_length > OUTPUT_CAPACITY - 57) return BC_LIMIT_EXCEEDED;
    bc_status status = session->state == BC_MEGARAC_STATE_STREAMING ?
        bc_megarac_session_keyboard_release(session) : BC_OK;
    if (status == BC_OK) status = queue_command(session, BC_MEGARAC_OP_STOP, 0, NULL, 0);
    if (status == BC_OK) session->state = BC_MEGARAC_STATE_CLOSED;
    return status;
}

int bc_megarac_session_is_irmc(const bc_megarac_session *session) {
    return session->kind == BC_MEGARAC_KVM_JVIEWER_IRMC;
}

uint32_t bc_megarac_session_state(const bc_megarac_session *session) { return session ? session->state : BC_MEGARAC_STATE_ERROR; }
uint32_t bc_megarac_session_flags(const bc_megarac_session *session) { return session ? session->flags : 0; }

const bc_megarac_video_header *bc_megarac_session_frame(const bc_megarac_session *session) {
    return session && (session->flags & BC_MEGARAC_FRAME_READY) ? bc_megarac_assembler_frame(&session->assembler) : NULL;
}

const uint8_t *bc_megarac_session_pixels(const bc_megarac_session *session) {
    return session ? session->assembler.buffer : NULL;
}

void bc_megarac_session_ack_frame(bc_megarac_session *session) {
    if (session) session->flags &= ~BC_MEGARAC_FRAME_READY;
}

void bc_megarac_session_destroy(bc_megarac_session *session) { if (session) free(session->input); free(session); }

bc_status bc_megarac_session_media_offer(const bc_megarac_session *session, bc_media_offer **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!session) return BC_INVALID_ARGUMENT;
    if (session->state != BC_MEGARAC_STATE_STREAMING) return BC_BUSY;
    const char *end = memchr(session->info.token, 0, sizeof(session->info.token));
    if (!end || end == session->info.token) return BC_PROTOCOL_ERROR;
    return bc_media_offer_token_create(BC_MEDIA_OFFER_MEGARAC, 0,
        (bc_string){session->info.token, (uint64_t)(end-session->info.token)}, out);
}

uint32_t bc_megarac_session_media_flags(const bc_megarac_session *session) {
    return session ? session->media_flags : 0;
}

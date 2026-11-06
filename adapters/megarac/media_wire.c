#include "media_internal.h"
#include "bcontrol/wire.h"
#include <string.h>

bc_status bc_megarac_media_auth(bc_string token, uint8_t instance, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!token.data || !token.length || token.length > 97 || !out || !written) return BC_INVALID_ARGUMENT;
    if (capacity < 160) return BC_LIMIT_EXCEEDED;
    memset(out, 0, 160);
    memcpy(out, "IUSB    ", 8);
    out[8] = 1; out[10] = 32;
    bc_wire_write_le(out + 12, 128, 4);
    out[17] = 5; out[18] = 1; out[19] = 0x80; out[23] = instance;
    uint8_t sum = 0;
    for (unsigned i = 0; i < 32; ++i) sum = (uint8_t)(sum + out[i]);
    out[11] = (uint8_t)(0u - sum);
    out[41] = 0xf2;
    memcpy(out + 63, token.data, (size_t)token.length);
    *written = 160;
    return BC_OK;
}

bc_status bc_megarac_media_disconnect(uint8_t instance, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!out || !written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (capacity < 62) return BC_LIMIT_EXCEEDED;
    memset(out, 0, 62); memcpy(out, "IUSB    ", 8);
    out[8] = 1; out[10] = 32; out[17] = 5; out[18] = 1; out[19] = 0x80; out[23] = instance;
    bc_wire_write_le(out + 12, 30, 4); out[41] = 0xf7;
    out[11] = bc_wire_checksum(out, 32); *written = 62;
    return BC_OK;
}

bc_status bc_megarac_media_packet_decode(const uint8_t *data, uint32_t length, bc_megarac_media_packet *out) {
    if (!data || !out) return BC_INVALID_ARGUMENT;
    if (length < 32 || memcmp(data, "IUSB    ", 8)) return BC_PROTOCOL_ERROR;
    uint32_t payload_length = (uint32_t)bc_wire_read_le(data + 12, 4);
    if (payload_length > 1024u * 1024u + 30u) return BC_LIMIT_EXCEEDED;
    if (payload_length != length - 32) return BC_PROTOCOL_ERROR;
    uint32_t flags = 0;
    if (!data[8] && !data[9] && !data[10] && !data[11]) {
        if (payload_length >= 31 && data[41] == 0xf1) flags = BC_MEGARAC_MEDIA_LEGACY_STATUS;
        else if (payload_length == 30 && data[41] == 0xf3) flags = BC_MEGARAC_MEDIA_LEGACY_CONTROL;
        else if (payload_length == 30 && data[41] < 0xc0) {
            for (unsigned i = 16; i < 32; ++i) if (data[i]) return BC_PROTOCOL_ERROR;
            flags = BC_MEGARAC_MEDIA_LEGACY_SCSI;
        } else return BC_PROTOCOL_ERROR;
    } else {
        if (data[8] != 1 || data[9] || data[10] != 32) return BC_UNSUPPORTED;
        uint8_t sum = 0;
        for (unsigned i = 0; i < 32; ++i) sum = (uint8_t)(sum + data[i]);
        if (sum) {
            if (bc_wire_checksum(data, 28)) return BC_PROTOCOL_ERROR;
            flags = BC_MEGARAC_MEDIA_HEADER28_CHECKSUM;
        }
    }
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out); out->flags = flags;
    out->sequence = (uint32_t)bc_wire_read_le(data + 24, 4);
    out->instance = data[23]; out->device = data[17]; out->protocol = data[18]; out->direction = data[19];
    out->payload = (bc_bytes){data + 32, payload_length};
    return BC_OK;
}

bc_status bc_megarac_media_discover(const uint8_t *data, uint32_t length,
    bc_service_profile *profile, bc_console_failure *failure) {
    if (!profile || !failure) return BC_INVALID_ARGUMENT;
    *profile = (bc_service_profile){sizeof(*profile), BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_MEGARAC, 0, 0};
    *failure = (bc_console_failure){sizeof(*failure), BC_OK, BC_CONSOLE_PHASE_MEDIA,
        BC_CONSOLE_CAUSE_UNKNOWN, 0, 0, 0, BC_SERVICE_LOCAL_MEDIA, BC_SERVICE_FAMILY_MEGARAC};
    bc_megarac_media_packet packet;
    bc_status status = bc_megarac_media_packet_decode(data, length, &packet);
    uint32_t evidence = 0;
    if (status == BC_OK) {
        int versioned = !(packet.flags & ~BC_MEGARAC_MEDIA_HEADER28_CHECKSUM) &&
            (packet.device & 0x7f) == 5 && packet.protocol == 1;
        if ((packet.flags == BC_MEGARAC_MEDIA_LEGACY_STATUS || versioned) &&
            packet.payload.length >= 31 && packet.payload.data[9] == 0xf1) {
            failure->profile = BC_SERVICE_MEGARAC_MEDIA_IUSB_CD;
            if (packet.payload.data[30] == 1) evidence = BC_SERVICE_EVIDENCE_HANDSHAKE;
            else {
                uint8_t code = packet.payload.data[30];
                status = code == 8 ? BC_BUSY : BC_AUTHENTICATION_FAILED;
                failure->cause = code == 5 ? BC_CONSOLE_CAUSE_ACCESS_DENIED :
                    code == 8 ? BC_CONSOLE_CAUSE_BUSY : BC_CONSOLE_CAUSE_SESSION_REJECTED;
                failure->device_code = code;
            }
        } else if ((versioned || packet.flags == BC_MEGARAC_MEDIA_LEGACY_SCSI) && (packet.payload.length == 29 || packet.payload.length == 30)) {
            evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR;
        } else if (packet.flags == BC_MEGARAC_MEDIA_LEGACY_CONTROL) {
            status = BC_OK;
            for (uint32_t i = 16; i < 62; ++i)
                if (i != 41 && data[i]) status = BC_UNSUPPORTED;
            if (status == BC_OK) evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR;
        } else status = BC_UNSUPPORTED;
    }
    if (status == BC_OK) {
        profile->variant = BC_SERVICE_MEGARAC_MEDIA_IUSB_CD;
        profile->evidence = evidence;
    } else {
        failure->status = status;
        if (status == BC_PROTOCOL_ERROR || status == BC_UNSUPPORTED) failure->cause = BC_CONSOLE_CAUSE_PROTOCOL;
    }
    return status;
}

bc_status bc_megarac_media_reply(const uint8_t *request, uint32_t prefix, uint32_t payload_length,
    const uint8_t *data, uint32_t size, uint8_t key, uint8_t asc, uint8_t ascq,
    uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (capacity < prefix || size > capacity - prefix) return BC_LIMIT_EXCEEDED;
    if (data && size) memmove(out + prefix, data, size);
    memmove(out, request, prefix);
    int legacy = !request[8] && !request[9] && !request[10];
    if (!legacy) out[17] = 5;
    out[19] = 0x80; out[11] = 0;
    memset(out + 28, 0, 4);
    out[53] = key ? 1 : 0; out[54] = key; out[55] = asc; out[56] = ascq;
    bc_wire_write_le(out + 12, payload_length + size, 4);
    bc_wire_write_le(out + 32, size, 4); bc_wire_write_le(out + 57, size, 4);
    out[11] = bc_wire_checksum(out, legacy ? prefix + size : 32); *written = prefix + size;
    return BC_OK;
}

bc_status bc_megarac_cd_respond(const uint8_t *request, uint32_t request_length,
    const bc_megarac_cd_source *source, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!source || source->struct_size != sizeof(*source) || !out || !written ||
        source->size < 2048 || source->size % 2048) return BC_INVALID_ARGUMENT;
    *written = 0;
    bc_megarac_media_packet packet;
    bc_status status = bc_megarac_media_packet_decode(request, request_length, &packet);
    if (status != BC_OK) return status;
    if (packet.flags == BC_MEGARAC_MEDIA_LEGACY_CONTROL) {
        for (uint32_t i = 16; i < 62; ++i)
            if (i != 41 && request[i]) return BC_UNSUPPORTED;
        if (capacity < 61) return BC_LIMIT_EXCEEDED;
        memmove(out, request, 61);
        out[11] = 0; out[19] = 0x80;
        bc_wire_write_le(out + 12, 29, 4);
        bc_wire_write_le(out + 32, 0, 4); bc_wire_write_le(out + 57, 0, 4);
        out[53] = 1; out[54] = 5; out[55] = 0x20; out[56] = 0;
        out[11] = bc_wire_checksum(out, 61); *written = 61;
        return BC_OK;
    }
    if ((packet.flags != BC_MEGARAC_MEDIA_LEGACY_SCSI &&
        ((packet.flags & ~BC_MEGARAC_MEDIA_HEADER28_CHECKSUM) || (packet.device & 0x7f) != 5 || packet.protocol != 1)) ||
        (packet.payload.length != 29 && packet.payload.length != 30)) return BC_UNSUPPORTED;
    const uint8_t *cdb = packet.payload.data + 9;
    uint32_t requested = packet.flags == BC_MEGARAC_MEDIA_LEGACY_SCSI ? 1024u * 1024u : (uint32_t)bc_wire_read_le(packet.payload.data, 4), size = 0;
    uint8_t small[36] = {0};
    uint32_t prefix = packet.flags == BC_MEGARAC_MEDIA_LEGACY_SCSI ? 61u : request_length;
    uint64_t offset = 0;
    int read = 0;
    if (requested > 1024u * 1024u) return BC_LIMIT_EXCEEDED;
    switch (cdb[0]) {
    case 0x00:
    case 0x1e: break;
    case 0x1b:
        if ((cdb[4] & 3) == 2) return BC_CANCELLED;
        break;
    case 0x03:
        size = 18; small[0] = 0x70; small[7] = 10;
        if (size > cdb[4]) size = cdb[4];
        break;
    case 0x12:
        if (cdb[1] || cdb[2]) return BC_UNSUPPORTED;
        size = 36; small[0] = 5; small[1] = 0x80; small[2] = 2; small[3] = 2; small[4] = 31;
        memcpy(small + 8, "bControl", 8); memcpy(small + 16, "Virtual CD-ROM  ", 16); memcpy(small + 32, "0001", 4);
        if (size > cdb[4]) size = cdb[4];
        break;
    case 0x25:
        if (source->size / 2048 > UINT32_MAX) return BC_LIMIT_EXCEEDED;
        size = 8; bc_wire_write_be(small, source->size / 2048 - 1, 4); bc_wire_write_be(small + 4, 2048, 4);
        break;
    case 0x43: {
        uint8_t format = cdb[2] & 0x0f, track = cdb[6];
        if (format > 1 || (track > 1 && track != 0xaa) || source->size / 2048 > UINT32_MAX) return BC_UNSUPPORTED;
        uint32_t entries = format == 1 || track == 0xaa ? 1 : 2;
        size = 4 + entries * 8;
        bc_wire_write_be(small, size - 2, 2); small[2] = 1; small[3] = 1;
        for (uint32_t i = 0; i < entries; ++i) {
            uint8_t *entry = small + 4 + i * 8;
            int leadout = format == 0 && (track == 0xaa || i == 1);
            uint64_t lba = leadout ? source->size / 2048 : 0;
            entry[1] = 0x14; entry[2] = leadout ? 0xaa : 1;
            if (cdb[1] & 2) {
                lba += 150;
                if (lba / 4500 > 255) return BC_UNSUPPORTED;
                entry[5] = (uint8_t)(lba / 4500); entry[6] = (uint8_t)((lba / 75) % 60); entry[7] = (uint8_t)(lba % 75);
            } else bc_wire_write_be(entry + 4, lba, 4);
        }
        uint32_t allocation = (uint32_t)bc_wire_read_be(cdb + 7, 2);
        if (size > allocation) size = allocation;
        break;
    }
    case 0x28:
    case 0xa8: {
        uint32_t blocks = (uint32_t)(packet.flags == BC_MEGARAC_MEDIA_LEGACY_SCSI && cdb[0] == 0xa8 ?
            bc_wire_read_le(cdb + 6, 4) : bc_wire_read_be(cdb + (cdb[0] == 0x28 ? 7 : 6), cdb[0] == 0x28 ? 2 : 4));
        if (blocks > (1024u * 1024u) / 2048) return BC_LIMIT_EXCEEDED;
        size = blocks * 2048; offset = bc_wire_read_be(cdb + 2, 4) * 2048;
        if (bc_media_range_check(source->size, offset, size) != BC_OK || size > requested) return BC_PROTOCOL_ERROR;
        if (size && !source->read) return BC_INVALID_ARGUMENT;
        read = 1; break;
    }
    default: return BC_UNSUPPORTED;
    }
    if (!read && size > requested) size = requested;
    if (capacity < prefix || size > capacity - prefix) return BC_LIMIT_EXCEEDED;
    if (read && size) {
        status = source->read(source->userdata, offset, size, out + prefix);
        if (status != BC_OK) return status;
    }
    return bc_megarac_media_reply(request, prefix, prefix - 32, read ? NULL : small,
        size, 0, 0, 0, out, capacity, written);
}

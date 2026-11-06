#include "media_internal.h"
#include "bcontrol/wire.h"
#include <stdlib.h>
#include <string.h>

struct bc_megarac_cd {
    bc_megarac_cd_source source;
    uint8_t present, prevented, event, attention;
    uint8_t key, asc, ascq;
};

bc_status bc_megarac_cd_create(const bc_megarac_cd_source *source, bc_megarac_cd **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!source || source->struct_size != sizeof(*source) || !source->read ||
        source->size < 2048 || source->size % 2048) return BC_INVALID_ARGUMENT;
    bc_megarac_cd *cd = calloc(1, sizeof(*cd));
    if (!cd) return BC_NO_MEMORY;
    cd->source = *source; cd->present = 1; cd->event = 2; cd->attention = 1;
    *out = cd;
    return BC_OK;
}
void bc_megarac_cd_destroy(bc_megarac_cd *cd) { free(cd); }
bc_status bc_megarac_cd_info_get(const bc_megarac_cd *cd, bc_megarac_cd_info *out) {
    if (!cd || !out || out->struct_size != sizeof(*out)) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out)); out->struct_size = sizeof(*out);
    out->flags = (cd->present ? BC_MEGARAC_CD_PRESENT : 0) |
        (cd->prevented ? BC_MEGARAC_CD_REMOVAL_PREVENTED : 0) |
        (cd->event ? BC_MEGARAC_CD_EVENT_PENDING : 0);
    out->sense_key = cd->key; out->asc = cd->asc; out->ascq = cd->ascq;
    return BC_OK;
}
static bc_status sense(bc_megarac_cd *cd, const uint8_t *request, uint32_t length, uint32_t payload,
    uint8_t key, uint8_t asc, uint8_t ascq, uint8_t *out, uint32_t capacity, uint32_t *written) {
    bc_status status = bc_megarac_media_reply(request, length, payload, NULL, 0, key, asc, ascq, out, capacity, written);
    if (status == BC_OK) { cd->key = key; cd->asc = asc; cd->ascq = ascq; }
    return status;
}
bc_status bc_megarac_cd_handle(bc_megarac_cd *cd, const uint8_t *request, uint32_t length,
    uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!cd || !out || !written) return BC_INVALID_ARGUMENT;
    *written = 0;
    bc_megarac_media_packet packet;
    bc_status status = bc_megarac_media_packet_decode(request, length, &packet);
    if (status != BC_OK) return status;
    if (packet.flags == BC_MEGARAC_MEDIA_LEGACY_CONTROL)
        return bc_megarac_cd_respond(request, length, &cd->source, out, capacity, written);
    if ((packet.flags != BC_MEGARAC_MEDIA_LEGACY_SCSI &&
        ((packet.flags & ~BC_MEGARAC_MEDIA_HEADER28_CHECKSUM) || (packet.device & 0x7f) != 5 || packet.protocol != 1)) || (packet.payload.length != 29 && packet.payload.length != 30)) return BC_UNSUPPORTED;
    uint32_t response_length = packet.flags == BC_MEGARAC_MEDIA_LEGACY_SCSI ? 61u : length;
    uint32_t payload = response_length - 32;
    uint32_t requested = packet.flags == BC_MEGARAC_MEDIA_LEGACY_SCSI ? 1024u * 1024u : (uint32_t)bc_wire_read_le(packet.payload.data, 4);
    if (requested > 1024u * 1024u) return BC_LIMIT_EXCEEDED;
    const uint8_t *cdb = packet.payload.data + 9;
    uint8_t data[18] = {0}; uint32_t size = 0;
    int consume_sense = 0, consume_attention = 0, consume_event = 0, present = -1, prevented = -1;
    if (cdb[0] != 0x03 && cdb[0] != 0x12 && cdb[0] != 0x4a && cd->attention) {
        status = sense(cd, request, response_length, payload, 6, 0x28, 0, out, capacity, written);
        if (status == BC_OK) cd->attention = 0;
        return status;
    }
    switch (cdb[0]) {
    case 0x03:
        if (cdb[1]) goto invalid_field;
        size = 18; data[0] = 0x70; data[7] = 10;
        data[2] = cd->key ? cd->key : (cd->attention ? 6 : 0);
        data[12] = cd->key ? cd->asc : (cd->attention ? 0x28 : 0); data[13] = cd->ascq;
        if (size > cdb[4]) size = cdb[4];
        consume_sense = 1; consume_attention = !cd->key; break;
    case 0x1e:
        if (cdb[4] > 1) goto invalid_field;
        prevented = cdb[4]; break;
    case 0x1b:
        if ((cdb[4] & 0xf0) || (cdb[1] & ~1u)) goto invalid_field;
        if (cdb[4] & 2) {
            present = cdb[4] & 1;
            if (!present && cd->prevented)
                return sense(cd, request, response_length, payload, 5, 0x53, 2, out, capacity, written);
        }
        break;
    case 0x4a:
        if (cdb[1] != 1) goto invalid_field;
        data[3] = 0x10;
        if (cdb[4] & 0x10) {
            size = 8; data[2] = 4; data[4] = cd->event; data[5] = cd->present ? 2 : 1;
            consume_event = 1;
        } else { size = 4; data[2] = 0x80; }
        bc_wire_write_be(data, size - 2, 2);
        { uint32_t allocation = (uint32_t)bc_wire_read_be(cdb + 7, 2); if (size > allocation) size = allocation; }
        break;
    default:
        if (cdb[0] != 0x12 && !cd->present)
            return sense(cd, request, response_length, payload, 2, 0x3a, 0, out, capacity, written);
        if (cdb[0] == 0x2a || cdb[0] == 0xaa || cdb[0] == 0x8a || cdb[0] == 0x2e ||
            cdb[0] == 0x04 || cdb[0] == 0x15 || cdb[0] == 0x55)
            return sense(cd, request, response_length, payload, 7, 0x27, 0, out, capacity, written);
        if (cdb[0] == 0x28 || cdb[0] == 0xa8) {
            uint64_t offset = bc_wire_read_be(cdb + 2, 4) * 2048;
            uint64_t count = (packet.flags == BC_MEGARAC_MEDIA_LEGACY_SCSI && cdb[0] == 0xa8 ?
                bc_wire_read_le(cdb + 6, 4) : bc_wire_read_be(cdb + (cdb[0] == 0x28 ? 7 : 6), cdb[0] == 0x28 ? 2 : 4)) * 2048;
            if (bc_media_range_check(cd->source.size, offset, count) != BC_OK)
                return sense(cd, request, response_length, payload, 5, 0x21, 0, out, capacity, written);
        }
        status = bc_megarac_cd_respond(request, length, &cd->source, out, capacity, written);
        if (status == BC_IO_ERROR)
            return sense(cd, request, response_length, payload, 3, 0x11, 0, out, capacity, written);
        if (status != BC_UNSUPPORTED) return status;
        return sense(cd, request, response_length, payload, 5, cdb[0] == 0x12 || cdb[0] == 0x43 ? 0x24 : 0x20,
            0, out, capacity, written);
    }
    if (size > requested) size = requested;
    status = bc_megarac_media_reply(request, response_length, payload, data, size, 0, 0, 0, out, capacity, written);
    if (status != BC_OK) return status;
    if (consume_sense && size >= 14) {
        cd->key = cd->asc = cd->ascq = 0;
        if (consume_attention) cd->attention = 0;
    }
    if (consume_event && size >= 8) cd->event = 0;
    if (prevented >= 0) cd->prevented = (uint8_t)prevented;
    if (present >= 0 && cd->present != present) {
        cd->present = (uint8_t)present; cd->event = present ? 2 : 3; cd->attention = 1;
    }
    return BC_OK;
invalid_field:
    return sense(cd, request, response_length, payload, 5, 0x24, 0, out, capacity, written);
}

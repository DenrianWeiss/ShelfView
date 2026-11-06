#include "bcontrol/ipmi_fru.h"
#include "bcontrol/wire.h"
#include <stdlib.h>
#include <string.h>

#define BC_IPMI_FRU_FORMAT_VERSION 1u
#define BC_IPMI_FRU_FIELD_END 0xC1u
/* Get FRU Inventory Area Info / Read FRU Data: FRU device ID not valid. */
#define BC_IPMI_COMPLETION_INVALID_FRU_DEVICE 0xC7u

static bc_status fru_completion(uint8_t code) {
    if (!code) return BC_OK;
    if (code == 0xc1 || code == 0xcb || code == 0xcd) return BC_UNSUPPORTED;
    if (code == 0xd4) return BC_AUTHENTICATION_FAILED;
    if (code == 0xc0 || code == 0x81) return BC_BUSY;
    if (code == 0xc3) return BC_TIMEOUT;
    if (code == BC_IPMI_COMPLETION_INVALID_FRU_DEVICE || code == 0xc9) return BC_UNSUPPORTED;
    return BC_PROTOCOL_ERROR;
}

static uint8_t fru_checksum_ok(const uint8_t *data, uint32_t length) {
    uint32_t sum = 0;
    while (length--) sum = (sum + *data++) & 0xff;
    return (uint8_t)(sum == 0);
}

bc_status bc_ipmi_fru_text_decode(uint8_t type, bc_bytes data, uint8_t language,
    char *out, uint32_t capacity) {
    static const char bcd_plus[] = "0123456789 -.";
    if (!out || (!data.data && data.length)) return BC_INVALID_ARGUMENT;
    if (!capacity) return BC_LIMIT_EXCEEDED;
    switch (type) {
    case 0:
        return BC_UNSUPPORTED; /* binary fields have no text representation */
    case 1: {
        if (data.length * 2 + 1 > capacity) return BC_LIMIT_EXCEEDED;
        for (uint32_t i = 0; i < data.length * 2; ++i) {
            uint8_t nibble = (uint8_t)((data.data[i / 2] >> ((i % 2) ? 0 : 4)) & 0x0f);
            if (nibble > 12) return BC_PROTOCOL_ERROR; /* reserved per FRU spec */
            out[i] = bcd_plus[nibble];
        }
        out[data.length * 2] = 0;
        return BC_OK;
    }
    case 2: {
        uint32_t count = (data.length * 8) / 6, used = 0, bits = 0, available = 0;
        if (count + 1 > capacity) return BC_LIMIT_EXCEEDED;
        for (uint32_t i = 0; i < data.length && used < count; ++i) {
            bits |= (uint32_t)data.data[i] << available;
            available += 8;
            while (available >= 6 && used < count) {
                out[used++] = (char)((bits & 0x3f) + 0x20);
                bits >>= 6;
                available -= 6;
            }
        }
        out[used] = 0;
        return BC_OK;
    }
    case 3: {
        if (!language || language == 25) {
            if (data.length >= capacity) return BC_LIMIT_EXCEEDED;
            uint32_t used = 0;
            for (uint32_t i = 0; i < data.length; ++i) {
                uint8_t c = data.data[i];
                uint32_t need = c < 0x80 ? 1 : 2;
                if ((uint64_t)used + need + 1 > capacity) return BC_LIMIT_EXCEEDED;
                if (need == 2) out[used++] = (char)(0xc0 | (c >> 6));
                out[used++] = (char)(need == 1 ? c : 0x80 | (c & 0x3f));
            }
            out[used] = 0;
            return BC_OK;
        }
        if (data.length % 2) return BC_PROTOCOL_ERROR;
        uint32_t used = 0;
        for (uint32_t i = 0; i + 1 < data.length; i += 2) {
            uint32_t unit = bc_wire_read_le(data.data + i, 2), codepoint;
            if (unit >= 0xd800 && unit <= 0xdbff) {
                if (i + 3 >= data.length) return BC_PROTOCOL_ERROR;
                uint32_t low = bc_wire_read_le(data.data + i + 2, 2);
                if (low < 0xdc00 || low > 0xdfff) return BC_PROTOCOL_ERROR;
                codepoint = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                i += 2;
            } else if (unit >= 0xdc00 && unit <= 0xdfff) {
                return BC_PROTOCOL_ERROR;
            } else {
                codepoint = unit;
            }
            uint32_t need = codepoint < 0x80 ? 1 : codepoint < 0x800 ? 2 : codepoint < 0x10000 ? 3 : 4;
            if (used + need + 1 > capacity) return BC_LIMIT_EXCEEDED;
            if (need == 1) out[used++] = (char)codepoint;
            else if (need == 2) {
                out[used++] = (char)(0xc0 | (codepoint >> 6));
                out[used++] = (char)(0x80 | (codepoint & 0x3f));
            } else if (need == 3) {
                out[used++] = (char)(0xe0 | (codepoint >> 12));
                out[used++] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
                out[used++] = (char)(0x80 | (codepoint & 0x3f));
            } else {
                out[used++] = (char)(0xf0 | (codepoint >> 18));
                out[used++] = (char)(0x80 | ((codepoint >> 12) & 0x3f));
                out[used++] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
                out[used++] = (char)(0x80 | (codepoint & 0x3f));
            }
        }
        out[used] = 0;
        return BC_OK;
    }
    default:
        return BC_UNSUPPORTED;
    }
}

bc_status bc_ipmi_fru_area_info_get(bc_ipmi_session *session, uint8_t fru_id, bc_ipmi_fru_area_info *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    uint8_t code = 0, data[3];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_FRU_INVENTORY_AREA_INFO,
        (bc_bytes){&fru_id, 1}, &code, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (code) return fru_completion(code);
    if (length != 3) return BC_PROTOCOL_ERROR;
    out->area_size = bc_wire_read_le(data, 2);
    out->word_access = (uint8_t)((data[2] & 1) != 0);
    return BC_OK;
}

/* Like bc_ipmi_fru_area_info_get but leaves completion code interpretation to the caller. */
static bc_status fru_area_info_query(bc_ipmi_session *session, uint8_t fru_id,
    bc_ipmi_fru_area_info *out, uint8_t *completion) {
    uint8_t data[3];
    uint32_t length = 0;
    bc_status status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_GET_FRU_INVENTORY_AREA_INFO,
        (bc_bytes){&fru_id, 1}, completion, data, sizeof(data), &length);
    if (status != BC_OK) return status;
    if (!*completion && length == 3) {
        out->area_size = bc_wire_read_le(data, 2);
        out->word_access = (uint8_t)((data[2] & 1) != 0);
    }
    return BC_OK;
}

bc_status bc_ipmi_fru_data_read(bc_ipmi_session *session, uint8_t fru_id, uint32_t offset,
    uint8_t *buffer, uint32_t capacity, uint32_t *length) {
    if (!session || !buffer || !length) return BC_INVALID_ARGUMENT;
    *length = 0;
    bc_ipmi_fru_area_info info = {0};
    info.struct_size = sizeof(info);
    info.abi_version = BC_ABI_VERSION;
    bc_status status = bc_ipmi_fru_area_info_get(session, fru_id, &info);
    if (status != BC_OK) return status;
    if (offset >= info.area_size) return BC_INVALID_ARGUMENT;
    uint32_t start = (info.word_access && (offset & 1)) ? offset - 1 : offset;
    uint32_t shift = offset - start;
    uint32_t want = capacity + shift;
    uint32_t remaining = info.area_size - start;
    if (want > remaining) want = remaining;
    if (info.word_access && (want & 1)) ++want;
    uint32_t got = 0, chunk_limit = BC_IPMI_FRU_READ_CHUNK;
    while (got < want) {
        uint32_t chunk = want - got;
        if (chunk > chunk_limit) chunk = chunk_limit;
        if (info.word_access && (chunk & 1)) --chunk;
        if (!chunk) return BC_PROTOCOL_ERROR;
        uint32_t wire_offset = info.word_access ? (start + got) >> 1 : start + got;
        uint8_t request[4] = {fru_id, (uint8_t)wire_offset, (uint8_t)(wire_offset >> 8), (uint8_t)chunk};
        uint8_t code = 0, response[BC_IPMI_FRU_READ_CHUNK + 1];
        uint32_t response_length = 0;
        status = bc_ipmi_session_command(session, BC_IPMI_NETFN_STORAGE, BC_IPMI_CMD_READ_FRU_DATA,
            (bc_bytes){request, sizeof(request)}, &code, response, sizeof(response), &response_length);
        if (status != BC_OK) return status;
        if (code == 0xca && chunk > (info.word_access ? 2u : 1u)) {
            chunk_limit = chunk / 2;
            if (info.word_access) chunk_limit &= ~1u;
            if (!chunk_limit) chunk_limit = 2;
            continue;
        }
        if (code) return fru_completion(code);
        if (response_length < 1 || response[0] == 0 || response[0] > chunk || response_length != 1u + response[0])
            return BC_PROTOCOL_ERROR;
        if (info.word_access && (response[0] & 1)) return BC_PROTOCOL_ERROR;
        got += response[0];
        uint32_t from = got - response[0];
        uint32_t low = from > shift ? from : shift;
        uint32_t high = got < shift + capacity ? got : shift + capacity;
        if (high > low) {
            memcpy(buffer + low - shift, response + 1 + (low - from), high - low);
            *length = high - shift;
        }
    }
    return BC_OK;
}

bc_status bc_ipmi_fru_inventory_get(bc_ipmi_session *session, bc_ipmi_fru_inventory *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    for (uint8_t id = 0; id < BC_IPMI_FRU_MAX_DEVICES; ++id) {
        bc_ipmi_fru_area_info info = {0};
        uint8_t completion = 0;
        bc_status status = fru_area_info_query(session, id, &info, &completion);
        if (status != BC_OK) {
            out->device_status[id] = status;
            return out->status = status;
        }
        if (completion == BC_IPMI_COMPLETION_INVALID_FRU_DEVICE || completion == 0xc9)
            return out->status; /* absent device: inventory ends here */
        if (completion) {
            out->device_status[id] = fru_completion(completion);
            return out->status = out->device_status[id];
        }
        out->device_status[id] = BC_OK;
        out->device_size[id] = info.area_size;
        out->device_access[id] = info.word_access;
        out->count = id + 1;
    }
    out->flags |= BC_IPMI_FRU_TRUNCATED;
    return out->status = BC_LIMIT_EXCEEDED;
}

static bc_status fru_field_decode(bc_bytes content, uint8_t language, bc_ipmi_fru_field *out) {
    out->raw_length = (uint8_t)content.length;
    memcpy(out->raw, content.data, content.length);
    if (out->field_type == 0) {
        out->status = BC_OK; /* binary content: raw bytes are the value */
        return BC_OK;
    }
    out->status = bc_ipmi_fru_text_decode(out->field_type, content, language, out->text, sizeof(out->text));
    return out->status;
}

static bc_status fru_parse_fields(const uint8_t *data, uint32_t size, uint8_t language,
    bc_ipmi_fru_field *fixed, uint32_t fixed_count, bc_ipmi_fru_field *custom, uint32_t custom_cap,
    uint32_t *custom_count, uint32_t *flags) {
    uint32_t pos = 0, index = 0;
    bc_status area = BC_OK;
    while (pos < size) {
        uint8_t tl = data[pos++];
        if (tl == BC_IPMI_FRU_FIELD_END) return area;
        uint32_t length = tl & 0x3f;
        bc_ipmi_fru_field *target = NULL;
        if (index < fixed_count) {
            target = &fixed[index];
        } else if (*custom_count < custom_cap) {
            target = &custom[*custom_count];
        } else {
            *flags |= BC_IPMI_FRU_AREA_CUSTOM_TRUNCATED;
        }
        if (length > size - pos) {
            if (target) {
                target->raw_length = (uint8_t)(size - pos);
                memcpy(target->raw, data + pos, size - pos);
                target->status = BC_PROTOCOL_ERROR;
            }
            return area == BC_OK ? BC_PROTOCOL_ERROR : area;
        }
        if (target) {
            memset(target, 0, sizeof(*target));
            target->struct_size = sizeof(*target);
            target->abi_version = BC_ABI_VERSION;
            target->field_type = (uint8_t)(tl >> 6);
            fru_field_decode((bc_bytes){data + pos, length}, language, target);
            if (area == BC_OK && target->status != BC_OK) area = target->status;
            if (index >= fixed_count) ++*custom_count;
        }
        index++;
        pos += length;
    }
    return area == BC_OK ? BC_PROTOCOL_ERROR : area; /* no end-of-fields marker */
}

static bc_status fru_chassis_parse(bc_bytes area, bc_ipmi_fru_chassis *out) {
    out->present = 1;
    if (area.length < 8 || (area.data[0] & 0x0f) != BC_IPMI_FRU_FORMAT_VERSION) return out->status = BC_UNSUPPORTED;
    out->chassis_type = area.data[2];
    bc_ipmi_fru_field fixed[2];
    for (unsigned i = 0; i < 2; ++i) fixed[i].status = BC_UNSUPPORTED;
    bc_status status = fru_parse_fields(area.data + 3, area.length - 4, 0, fixed, 2,
        out->custom, BC_IPMI_FRU_CUSTOM_MAX, &out->custom_count, &out->flags);
    out->part_number = fixed[0];
    out->serial_number = fixed[1];
    return out->status = status;
}

static bc_status fru_board_parse(bc_bytes area, bc_ipmi_fru_board *out) {
    out->present = 1;
    if (area.length < 8 || (area.data[0] & 0x0f) != BC_IPMI_FRU_FORMAT_VERSION) return out->status = BC_UNSUPPORTED;
    out->language = area.data[2];
    out->mfg_date = bc_wire_read_le(area.data + 3, 3);
    bc_ipmi_fru_field fixed[5];
    for (unsigned i = 0; i < 5; ++i) fixed[i].status = BC_UNSUPPORTED;
    bc_status status = fru_parse_fields(area.data + 6, area.length - 7, out->language, fixed, 5,
        out->custom, BC_IPMI_FRU_CUSTOM_MAX, &out->custom_count, &out->flags);
    out->manufacturer = fixed[0];
    out->product = fixed[1];
    out->serial = fixed[2];
    out->part_number = fixed[3];
    out->file_id = fixed[4];
    return out->status = status;
}

static bc_status fru_product_parse(bc_bytes area, bc_ipmi_fru_product *out) {
    out->present = 1;
    if (area.length < 8 || (area.data[0] & 0x0f) != BC_IPMI_FRU_FORMAT_VERSION) return out->status = BC_UNSUPPORTED;
    out->language = area.data[2];
    bc_ipmi_fru_field fixed[7];
    for (unsigned i = 0; i < 7; ++i) fixed[i].status = BC_UNSUPPORTED;
    bc_status status = fru_parse_fields(area.data + 3, area.length - 4, out->language, fixed, 7,
        out->custom, BC_IPMI_FRU_CUSTOM_MAX, &out->custom_count, &out->flags);
    out->manufacturer = fixed[0];
    out->name = fixed[1];
    out->part_number = fixed[2];
    out->version = fixed[3];
    out->serial = fixed[4];
    out->asset_tag = fixed[5];
    out->file_id = fixed[6];
    return out->status = status;
}

static bc_status fru_area_check(bc_bytes area, uint32_t *length) {
    if (area.length < 2) return BC_PROTOCOL_ERROR;
    *length = (uint32_t)area.data[1] * 8;
    if (*length < 8 || *length > area.length) return BC_PROTOCOL_ERROR;
    if (!fru_checksum_ok(area.data, *length)) return BC_PROTOCOL_ERROR;
    return BC_OK;
}

bc_status bc_ipmi_fru_image_parse(bc_bytes image, bc_ipmi_fru_info *out) {
    if (!out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    if (!image.data || image.length < BC_IPMI_FRU_HEADER_SIZE)
        return out->status = BC_PROTOCOL_ERROR;
    if (!fru_checksum_ok(image.data, BC_IPMI_FRU_HEADER_SIZE) ||
        (image.data[0] & 0x0f) != BC_IPMI_FRU_FORMAT_VERSION)
        return out->status = BC_PROTOCOL_ERROR;
    out->header_version = (uint8_t)(image.data[0] & 0x0f);
    static const uint8_t offsets[] = {1, 2, 3, 4, 5};
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        uint32_t at = (uint32_t)image.data[offsets[i]] * 8;
        if (!at) continue;
        uint32_t length = 0;
        bc_status status = at + 2 <= image.length
            ? fru_area_check((bc_bytes){image.data + at, image.length - at}, &length)
            : BC_PROTOCOL_ERROR;
        if (i == 0) {
            out->internal_status = status == BC_OK ? BC_UNSUPPORTED : status;
            continue;
        }
        if (i == 4) {
            /* The multi-record area has no area checksum and runs to the end of the device area. */
            if (at >= image.length) {
                out->multi_status = BC_PROTOCOL_ERROR;
            } else {
                uint32_t available = image.length - at;
                out->multi_status = BC_UNSUPPORTED; /* records are never decoded here */
                out->multi_length = available > BC_IPMI_FRU_MULTI_MAX ? BC_IPMI_FRU_MULTI_MAX : available;
                if (available > BC_IPMI_FRU_MULTI_MAX) out->flags |= BC_IPMI_FRU_TRUNCATED;
                memcpy(out->multi_raw, image.data + at, out->multi_length);
            }
            continue;
        }
        bc_bytes area = {status == BC_OK ? image.data + at : NULL, length};
        if (i == 1) {
            out->chassis.present = 1;
            if (status == BC_OK) status = fru_chassis_parse(area, &out->chassis);
            else out->chassis.status = status;
        } else if (i == 2) {
            out->board.present = 1;
            if (status == BC_OK) status = fru_board_parse(area, &out->board);
            else out->board.status = status;
        } else {
            out->product.present = 1;
            if (status == BC_OK) status = fru_product_parse(area, &out->product);
            else out->product.status = status;
        }
        if (status != BC_OK && out->status == BC_OK) out->status = status;
    }
    return out->status;
}

bc_status bc_ipmi_fru_info_get(bc_ipmi_session *session, uint8_t fru_id, bc_ipmi_fru_info *out) {
    if (!session || !out || out->struct_size != sizeof(*out) || out->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->abi_version = BC_ABI_VERSION;
    out->fru_id = fru_id;
    bc_ipmi_fru_area_info area = {0};
    area.struct_size = sizeof(area);
    area.abi_version = BC_ABI_VERSION;
    bc_status status = bc_ipmi_fru_area_info_get(session, fru_id, &area);
    if (status != BC_OK) return out->status = status;
    uint32_t want = area.area_size < BC_IPMI_FRU_IMAGE_MAX ? area.area_size : BC_IPMI_FRU_IMAGE_MAX;
    uint8_t *image = malloc(want ? want : 1);
    if (!image) return out->status = BC_NO_MEMORY;
    uint32_t length = 0;
    status = bc_ipmi_fru_data_read(session, fru_id, 0, image, want, &length);
    bc_status parse = bc_ipmi_fru_image_parse((bc_bytes){image, length}, out);
    free(image);
    out->fru_id = fru_id;
    out->area = area;
    if (status != BC_OK) return out->status = status;
    return out->status = parse;
}

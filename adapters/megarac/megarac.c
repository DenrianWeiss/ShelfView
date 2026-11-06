#include "megarac.h"
#include "bcontrol/wire.h"
#include "yyjson.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IUSB_HEADER_SIZE 32u
#define IUSB_KEYBOARD 0x30u
#define IUSB_MOUSE 0x31u
#define IUSB_PROTOCOL_KEYBOARD 0x10u
#define IUSB_PROTOCOL_MOUSE 0x20u
#define VIDEO_FRAGMENT_PREFIX 2u

static bc_status write_field(uint8_t *out, uint32_t length, const char *value) {
    size_t n = value ? strlen(value) : 0;
    if (n >= length) return BC_INVALID_ARGUMENT;
    memset(out, 0, length);
    if (n) memcpy(out, value, n);
    return BC_OK;
}
bc_status bc_megarac_ivtp_encode(const bc_megarac_ivtp *header, const uint8_t *payload, uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!header || !out || !written) return BC_INVALID_ARGUMENT;
    uint64_t need = BC_MEGARAC_IVTP_HEADER_SIZE + (uint64_t)header->length;
    if (capacity < need) return BC_LIMIT_EXCEEDED;
    bc_wire_write_le(out, header->type, 2);
    bc_wire_write_le(out + 2, header->length, 4);
    bc_wire_write_le(out + 6, header->status, 2);
    if (payload && header->length) memcpy(out + BC_MEGARAC_IVTP_HEADER_SIZE, payload, header->length);
    *written = (uint32_t)need;
    return BC_OK;
}

bc_status bc_megarac_ivtp_decode(const uint8_t *data, uint32_t length, bc_megarac_ivtp *header, const uint8_t **payload, uint32_t *consumed) {
    if (!data || !header || !payload || !consumed || length < BC_MEGARAC_IVTP_HEADER_SIZE) return BC_INVALID_ARGUMENT;
    uint32_t size = (uint32_t)bc_wire_read_le(data + 2, 4);
    if (size > length - BC_MEGARAC_IVTP_HEADER_SIZE) return BC_PROTOCOL_ERROR;
    header->type = (uint16_t)bc_wire_read_le(data, 2);
    header->length = size;
    header->status = (uint16_t)bc_wire_read_le(data + 6, 2);
    *payload = data + BC_MEGARAC_IVTP_HEADER_SIZE;
    *consumed = BC_MEGARAC_IVTP_HEADER_SIZE + size;
    return BC_OK;
}

typedef struct { uint32_t count; char values[64][BC_MEGARAC_MAX_TOKEN]; } arguments;
static const char open_tag[] = "<argument>";
static const char close_tag[] = "</argument>";

static void parse_arguments(const char *text, uint32_t length, arguments *out) {
    memset(out, 0, sizeof(*out));
    for (uint32_t i = 0; i + sizeof(open_tag) - 1 < length && out->count < 64; ++i) {
        if (memcmp(text + i, open_tag, sizeof(open_tag) - 1)) continue;
        uint32_t start = i + (uint32_t)sizeof(open_tag) - 1;
        uint32_t end = start;
        while (end + sizeof(close_tag) - 1 <= length && memcmp(text + end, close_tag, sizeof(close_tag) - 1)) ++end;
        if (end + sizeof(close_tag) - 1 > length) break;
        uint32_t n = end - start;
        if (n >= BC_MEGARAC_MAX_TOKEN) n = BC_MEGARAC_MAX_TOKEN - 1;
        memcpy(out->values[out->count], text + start, n);
        out->values[out->count][n] = 0;
        ++out->count;
        i = end + (uint32_t)sizeof(close_tag) - 2;
    }
}

bc_status bc_megarac_parse_jnlp(const uint8_t *data, uint32_t length, bc_megarac_kvm_info *out) {
    if (!data || !out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->kind = BC_MEGARAC_KVM_JVIEWER;
    arguments args;
    parse_arguments((const char *)data, length, &args);
    for (uint32_t i = 0; i + 1 < args.count; ++i) {
        const char *name = args.values[i], *value = args.values[i + 1];
        if (!strcmp(name, "-hostname")) strncpy(out->host, value, sizeof(out->host) - 1);
        else if (!strcmp(name, "-kvmtoken")) strncpy(out->token, value, sizeof(out->token) - 1);
        else if (!strcmp(name, "-webcookie")) strncpy(out->cookie, value, sizeof(out->cookie) - 1);
        else if (!strcmp(name, "-kvmport")) out->port = (uint32_t)strtoul(value, NULL, 10);
        else if (!strcmp(name, "-kvmsecure")) out->secure = (uint32_t)(strtoul(value, NULL, 10) != 0);
        else if (!strcmp(name, "-singleportenabled")) out->single_port = (uint32_t)(strtoul(value, NULL, 10) != 0);
    }
    return BC_OK;
}

static bc_status json_string(yyjson_val *root, const char *key, char *out, size_t capacity) {
    yyjson_val *value = yyjson_obj_get(root, key);
    if (!value) return BC_OK;
    if (yyjson_is_str(value)) {
        const char *text = yyjson_get_str(value);
        if (strlen(text) >= capacity) return BC_LIMIT_EXCEEDED;
        strcpy(out, text);
        return BC_OK;
    }
    if (yyjson_is_uint(value)) {
        char number[32];
        snprintf(number, sizeof(number), "%llu", (unsigned long long)yyjson_get_uint(value));
        if (strlen(number) >= capacity) return BC_LIMIT_EXCEEDED;
        strcpy(out, number);
        return BC_OK;
    }
    return BC_PROTOCOL_ERROR;
}

bc_status bc_megarac_parse_h5_config(const uint8_t *data, uint32_t length, bc_megarac_kvm_info *out) {
    if (!data || !out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->kind = BC_MEGARAC_KVM_H5VIEWER;
    yyjson_doc *doc = yyjson_read((const char *)data, length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    if (!root || !yyjson_is_obj(root)) { if (doc) yyjson_doc_free(doc); return BC_PROTOCOL_ERROR; }
    bc_status status = json_string(root, "token", out->token, sizeof(out->token));
    if (status == BC_OK) status = json_string(root, "session", out->session, sizeof(out->session));
    if (status == BC_OK) status = json_string(root, "client_ip", out->client_ip, sizeof(out->client_ip));
    if (status == BC_OK) status = json_string(root, "server_ip", out->server_ip, sizeof(out->server_ip));
    yyjson_doc_free(doc);
    return status;
}
bc_status bc_megarac_discover_h5_config(const uint8_t *data, uint32_t length,
    bc_megarac_kvm_info *out, bc_service_profile *profile) {
    if (!out || !profile) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    *profile = (bc_service_profile){sizeof(*profile), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC, 0, 0};
    if (!data || !length) return BC_INVALID_ARGUMENT;
    if (length > 65536) return BC_LIMIT_EXCEEDED;
    yyjson_doc *doc = yyjson_read((const char *)data, length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    bc_status status = yyjson_is_obj(root) ? BC_OK : BC_PROTOCOL_ERROR;
    static const char *const fields[] = {"token", "session", "client_ip", "server_ip"};
    if (status == BC_OK) {
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
            size_t index, count, matches = 0; yyjson_val *key, *value;
            yyjson_obj_foreach(root, index, count, key, value) {
                (void)value;
                if (!strcmp(yyjson_get_str(key), fields[i])) ++matches;
            }
            if (matches != 1) { status = BC_PROTOCOL_ERROR; break; }
        }
    }
    bc_megarac_kvm_info info = {0};
    if (status == BC_OK) status = bc_megarac_parse_h5_config(data, length, &info);
    const char *values[] = {info.token, info.session, info.client_ip, info.server_ip};
    const size_t limits[] = {128, BC_MEGARAC_MAX_TOKEN - 1, 64, 64};
    if (status == BC_OK) {
        for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
            size_t size = strlen(values[i]);
            if (!size || size > limits[i]) { status = BC_PROTOCOL_ERROR; break; }
            for (size_t j = 0; j < size; ++j)
                if ((unsigned char)values[i][j] < 33 || (unsigned char)values[i][j] > 126) status = BC_PROTOCOL_ERROR;
        }
    }
    if (doc) yyjson_doc_free(doc);
    if (status == BC_OK) {
        *out = info;
        profile->variant = BC_SERVICE_MEGARAC_KVM_H5_438;
        profile->evidence = BC_SERVICE_EVIDENCE_DESCRIPTOR;
    }
    volatile uint8_t *secret = (volatile uint8_t *)&info;
    for (size_t i = 0; i < sizeof(info); ++i) secret[i] = 0;
    return status;
}

bc_status bc_megarac_jviewer_auth(const bc_megarac_kvm_info *info, const char *client_ip, const char *username, const char *mac,
    uint8_t *out, uint32_t capacity) {
    if (!info || !out || !username || capacity < BC_MEGARAC_JVIEWER_AUTH_SIZE) return BC_INVALID_ARGUMENT;
    memset(out, 0, BC_MEGARAC_JVIEWER_AUTH_SIZE);
    out[0] = 0;
    bc_status status = write_field(out + 1, 129, info->token);
    if (status == BC_OK) status = write_field(out + 130, 65, client_ip);
    if (status == BC_OK) status = write_field(out + 195, 129, username);
    if (status == BC_OK) status = write_field(out + 324, 49, mac);
    return status;
}

bc_status bc_megarac_jviewer_reconnect(const bc_megarac_kvm_info *info, const char *client_ip, const char *username, const char *mac,
    uint8_t session_id, uint8_t *out, uint32_t capacity) {
    if (!info || !out || !username || capacity < BC_MEGARAC_JVIEWER_RECONNECT_SIZE) return BC_INVALID_ARGUMENT;
    memset(out, 0, BC_MEGARAC_JVIEWER_RECONNECT_SIZE);
    bc_status status = write_field(out, 130, info->token);
    if (status == BC_OK) status = write_field(out + 130, 65, client_ip);
    if (status == BC_OK) status = write_field(out + 195, 129, username);
    if (status == BC_OK) status = write_field(out + 324, 49, mac);
    out[373] = session_id;
    return status;
}

bc_status bc_megarac_h5viewer_auth(const bc_megarac_kvm_info *info, const char *client_ip, const char *username, const char *mac,
    uint8_t *out, uint32_t capacity) {
    if (!info || !out || !username || capacity < BC_MEGARAC_H5VIEWER_AUTH_SIZE) return BC_INVALID_ARGUMENT;
    memset(out, 0, BC_MEGARAC_H5VIEWER_AUTH_SIZE);
    out[0] = 0;
    bc_status status = write_field(out + 1, 129, info->token);
    if (status == BC_OK) status = write_field(out + 130, 65, client_ip);
    if (status == BC_OK) status = write_field(out + 195, 129, username);
    if (status == BC_OK) status = write_field(out + 324, 49, mac);
    if (status == BC_OK) status = write_field(out + 373, 65, info->server_ip);
    return status;
}

static bc_status hid_packet(uint8_t device, uint8_t protocol, uint8_t interface_number, uint32_t sequence,
    uint32_t report_field, const uint8_t *report, uint32_t report_length, uint8_t *out, uint32_t capacity, uint32_t *written) {
    uint32_t payload = IUSB_HEADER_SIZE + 1 + report_length;
    uint64_t need = BC_MEGARAC_IVTP_HEADER_SIZE + payload;
    if (!out || !written || capacity < need || report_length > 255) return BC_LIMIT_EXCEEDED;
    memset(out, 0, (size_t)need);
    bc_megarac_ivtp header = {BC_MEGARAC_OP_HID, 0, payload};
    uint32_t header_length = 0;
    bc_status status = bc_megarac_ivtp_encode(&header, NULL, out, capacity, &header_length);
    if (status != BC_OK) return status;
    uint8_t *iusb = out + BC_MEGARAC_IVTP_HEADER_SIZE;
    memcpy(iusb, "IUSB    ", 8);
    iusb[8] = 1; iusb[9] = 0; iusb[10] = IUSB_HEADER_SIZE;
    bc_wire_write_le(iusb + 12, report_field, 4);
    iusb[17] = device; iusb[18] = protocol; iusb[19] = 0x80; iusb[20] = 2; iusb[21] = interface_number;
    bc_wire_write_le(iusb + 24, sequence, 4);
    iusb[IUSB_HEADER_SIZE] = (uint8_t)report_length;
    memcpy(iusb + IUSB_HEADER_SIZE + 1, report, report_length);
    uint8_t sum = 0;
    for (uint32_t i = 0; i < IUSB_HEADER_SIZE; ++i) sum = (uint8_t)(sum + iusb[i]);
    iusb[11] = (uint8_t)(0u - sum);
    *written = (uint32_t)need;
    return BC_OK;
}

bc_status bc_megarac_hid_keyboard(uint32_t sequence, uint8_t modifiers, const uint8_t usages[6], uint8_t *out, uint32_t capacity, uint32_t *written) {
    uint8_t report[8] = {modifiers, 0};
    if (usages) memcpy(report + 2, usages, 6);
    return hid_packet(IUSB_KEYBOARD, IUSB_PROTOCOL_KEYBOARD, 0, sequence, 9, report, sizeof(report), out, capacity, written);
}

bc_status bc_megarac_hid_mouse(uint32_t sequence, uint8_t buttons, uint16_t x, uint16_t y, int8_t wheel, uint8_t *out, uint32_t capacity, uint32_t *written) {
    uint8_t report[6] = {buttons};
    bc_wire_write_le(report + 1, x, 2);
    bc_wire_write_le(report + 3, y, 2);
    report[5] = (uint8_t)wheel;
    return hid_packet(IUSB_MOUSE, IUSB_PROTOCOL_MOUSE, 1, sequence, 7, report, sizeof(report), out, capacity, written);
}

bc_status bc_megarac_assembler_init(bc_megarac_assembler *assembler, uint8_t *buffer, uint32_t capacity) {
    if (!assembler || !buffer || !capacity) return BC_INVALID_ARGUMENT;
    memset(assembler, 0, sizeof(*assembler));
    assembler->struct_size = sizeof(*assembler);
    assembler->buffer = buffer;
    assembler->capacity = capacity;
    return BC_OK;
}

const bc_megarac_video_header *bc_megarac_assembler_frame(const bc_megarac_assembler *assembler) {
    return assembler && assembler->state == 2 ? &assembler->header : NULL;
}

bc_status bc_megarac_assembler_push(bc_megarac_assembler *assembler, const uint8_t *fragment, uint32_t length) {
    if (!assembler || !fragment) return BC_INVALID_ARGUMENT;
    if (assembler->state == 2) { assembler->state = 0; assembler->received = 0; }
    if (assembler->state == 0) {
        if (length < VIDEO_FRAGMENT_PREFIX + BC_MEGARAC_AST_HEADER_SIZE) return BC_PROTOCOL_ERROR;
        const uint8_t *raw = fragment + VIDEO_FRAGMENT_PREFIX;
        bc_status status = bc_megarac_ast_header(raw, &assembler->header);
        if (status != BC_OK) return status;
        uint32_t compressed = assembler->header.compressed_size;
        if (!assembler->header.source_width || !assembler->header.source_height ||
            assembler->header.source_width > 4096 || assembler->header.source_height > 4096 ||
            !assembler->header.width || !assembler->header.height ||
            assembler->header.width > 4096 || assembler->header.height > 4096 ||
            !compressed || compressed > assembler->capacity) return BC_LIMIT_EXCEEDED;
        uint32_t copy = length - VIDEO_FRAGMENT_PREFIX - BC_MEGARAC_AST_HEADER_SIZE;
        if (copy > compressed) return BC_PROTOCOL_ERROR;
        memcpy(assembler->buffer, raw + BC_MEGARAC_AST_HEADER_SIZE, copy);
        assembler->received = copy;
        assembler->state = 1;
    } else {
        if (length < VIDEO_FRAGMENT_PREFIX) return BC_PROTOCOL_ERROR;
        uint32_t copy = length - VIDEO_FRAGMENT_PREFIX;
        if (copy > assembler->header.compressed_size - assembler->received) return BC_PROTOCOL_ERROR;
        memcpy(assembler->buffer + assembler->received, fragment + VIDEO_FRAGMENT_PREFIX, copy);
        assembler->received += copy;
    }
    if (assembler->received == assembler->header.compressed_size) assembler->state = 2;
    return BC_OK;
}

bc_status bc_megarac_h5_media_parameters(const uint8_t *data, uint32_t length, bc_megarac_media_parameters *out) {
    if (!out) return BC_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!data || !length || length > 65536) return BC_INVALID_ARGUMENT;
    yyjson_doc *doc = yyjson_read((const char *)data, length, 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_val *count = yyjson_obj_get(root, "num_cd"), *kvm = yyjson_obj_get(root, "kvm_num_cd");
    yyjson_val *enabled = yyjson_obj_get(root, "kvm_service_status");
    bc_status status = BC_UNSUPPORTED;
    if (yyjson_is_uint(count) && yyjson_get_uint(count) > 0 && yyjson_get_uint(count) <= 255 &&
        yyjson_is_uint(kvm) && yyjson_get_uint(kvm) > 0 && yyjson_get_uint(kvm) <= yyjson_get_uint(count) &&
        yyjson_is_uint(enabled) && yyjson_get_uint(enabled) == 1) {
        *out = (bc_megarac_media_parameters){sizeof(*out), BC_MEGARAC_MEDIA_WEBSOCKET |
            BC_MEGARAC_MEDIA_DEVICES_PRESENT, 0, 0, 0, (uint32_t)yyjson_get_uint(kvm), 1};
        status = BC_OK;
    }
    if (doc) yyjson_doc_free(doc);
    return status;
}

static int tunnel_text(const char *value, size_t capacity) {
    size_t i = 0;
    for (; i < capacity && value[i]; ++i)
        if ((unsigned char)value[i] <= 32 || (unsigned char)value[i] >= 127) return 0;
    return i > 0 && i < capacity;
}


bc_status bc_megarac_tunnel_request(const bc_megarac_kvm_info *info, uint32_t service,
    uint8_t *out, uint32_t capacity, uint32_t *written) {
    if (!info || !out || !written) return BC_INVALID_ARGUMENT;
    *written = 0;
    if (info->struct_size != sizeof(*info) || !tunnel_text(info->host, sizeof(info->host)) ||
        !tunnel_text(info->cookie, sizeof(info->cookie)) || !info->port || info->port > 65535 ||
        info->secure > 1 || info->single_port != 1 ||
        (service != BC_MEGARAC_TUNNEL_VIDEO && service != BC_MEGARAC_TUNNEL_CD)) return BC_INVALID_ARGUMENT;
    char request[1024];
    int n = snprintf(request, sizeof(request),
        "CONNECT %s:%u %s/1.1\r\n cookie %s\r\n\r\nJVIEWER %s cookie %s\r\n\r\n",
        info->host, info->port, info->secure ? "HTTPS" : "HTTP", info->cookie,
        service == BC_MEGARAC_TUNNEL_CD ? "CDMEDIA" : "VIDEO", info->cookie);
    bc_status status = n < 0 || (size_t)n >= sizeof(request) || (uint32_t)n > capacity ? BC_LIMIT_EXCEEDED : BC_OK;
    if (status == BC_OK) { memcpy(out, request, (size_t)n); *written = (uint32_t)n; }
    memset(request, 0, sizeof(request));
    return status;
}

static bc_status tunnel_status(const uint8_t *data, uint32_t length) {
    if (length < 13 || (memcmp(data, "HTTP/1.0 ", 9) && memcmp(data, "HTTP/1.1 ", 9)))
        return BC_PROTOCOL_ERROR;
    if (!memcmp(data + 9, "200 ", 4)) return BC_OK;
    return !memcmp(data + 9, "401 ", 4) || !memcmp(data + 9, "403 ", 4) ?
        BC_AUTHENTICATION_FAILED : BC_HTTP_ERROR;
}

bc_status bc_megarac_tunnel_status_line(const uint8_t *data, uint32_t length, uint32_t *consumed) {
    if (!data || !consumed) return BC_INVALID_ARGUMENT;
    *consumed = 0;
    for (uint32_t n = 2; n <= length && n <= 255; ++n) {
        if (memcmp(data + n - 2, "\r\n", 2)) continue;
        bc_status status = tunnel_status(data, n - 2);
        if (status == BC_OK) *consumed = n;
        return status;
    }
    return length >= 255 ? BC_LIMIT_EXCEEDED : BC_BUSY;
}

bc_status bc_megarac_tunnel_response(const uint8_t *data, uint32_t length, uint32_t *consumed) {
    if (!data || !consumed) return BC_INVALID_ARGUMENT;
    *consumed = 0;
    uint32_t n = 4;
    for (; n <= length && n <= 255; ++n) if (!memcmp(data + n - 4, "\r\n\r\n", 4)) break;
    if (n > 255) return BC_LIMIT_EXCEEDED;
    if (n > length) return BC_BUSY;
    bc_status status = tunnel_status(data, n);
    if (status == BC_OK) *consumed = n;
    return status;
}

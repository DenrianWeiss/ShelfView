#include "bcontrol/inventory.h"
#include "bcontrol/redfish.h"
#include "yyjson.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct bc_inventory_import { bc_inventory_entry *entries; uint32_t count; };
static const char *const fields[] = {"name", "address", "username", "protocol", "system_uri"};
static bc_status failure(bc_inventory_error *error, uint32_t code, uint32_t field, bc_status status) {
    error->code = code; error->field = field; return status;
}
static bc_string copy(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (p) { memcpy(p, s, n); p[n] = 0; }
    return (bc_string){p, p ? n : 0};
}
static void clear_entry(bc_inventory_entry *entry) {
    free((void *)entry->name.data); free((void *)entry->address.data);
    free((void *)entry->username.data); free((void *)entry->system_uri.data);
}
void bc_inventory_import_destroy(bc_inventory_import *value) {
    if (!value) return;
    for (uint32_t i = 0; i < value->count; ++i) clear_entry(&value->entries[i]);
    free(value->entries); free(value);
}
uint32_t bc_inventory_count(const bc_inventory_import *value) { return value ? value->count : 0; }
const bc_inventory_entry *bc_inventory_entry_get(const bc_inventory_import *value, uint32_t index) {
    return value && index < value->count ? &value->entries[index] : NULL;
}
static int field_index(const char *s, size_t length) {
    for (unsigned i = 0; i < 5; ++i) if (strlen(fields[i]) == length && !memcmp(s, fields[i], length)) return (int)i;
    return -1;
}
static int text_valid(const char *s, size_t n) {
    for (size_t i = 0; i < n; ++i) if ((unsigned char)s[i] < 32 || (unsigned char)s[i] == 127) return 0;
    return 1;
}
static int ipv4(const char *s, size_t n) {
    unsigned parts = 0; size_t at = 0;
    while (at < n) {
        unsigned value = 0, digits = 0;
        while (at < n && s[at] >= '0' && s[at] <= '9') { value = value * 10 + (unsigned)(s[at++] - '0'); if (++digits > 3) return 0; }
        if (!digits || value > 255 || ++parts > 4) return 0;
        if (at == n) break;
        if (s[at++] != '.' || at == n) return 0;
    }
    return parts == 4;
}
static int hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
static int ipv6(const char *s, size_t n) {
    size_t at = 0; unsigned groups = 0; int compressed = 0;
    if (n >= 2 && s[0] == ':' && s[1] == ':') { compressed = 1; at = 2; }
    while (at < n) {
        size_t start = at;
        while (at < n && hex(s[at])) ++at;
        if (at < n && s[at] == '.') { if (!ipv4(s + start, n - start)) return 0; groups += 2; at = n; break; }
        if (at == start || at - start > 4 || ++groups > 8) return 0;
        if (at == n) break;
        if (s[at++] != ':') return 0;
        if (at < n && s[at] == ':') { if (compressed) return 0; compressed = 1; ++at; }
        else if (at == n) return 0;
    }
    return compressed ? groups < 8 : groups == 8;
}
static int hostname(const char *s, size_t n) {
    if (!n || n > 253) return 0;
    int numeric = 1; size_t label = 0;
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        if (c == '.') { if (!label || label > 63 || s[i - 1] == '-') return 0; label = 0; continue; }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return 0;
        if (!label && c == '-') return 0;
        if (c < '0' || c > '9') numeric = 0;
        ++label;
    }
    return label && label <= 63 && s[n - 1] != '-' && (!numeric || ipv4(s, n));
}
static bc_string address(const char *s, size_t n, uint32_t protocol) {
    char result[2100]; const char *scheme = protocol == BC_INVENTORY_IPMI ? "ipmi://" : "https://";
    size_t offset = 0;
    if (n >= 8 && !memcmp(s, "https://", 8)) { if (protocol == BC_INVENTORY_IPMI) return (bc_string){0}; offset = 8; }
    else if (n >= 7 && !memcmp(s, "ipmi://", 7)) { if (protocol != BC_INVENTORY_IPMI) return (bc_string){0}; offset = 7; }
    if (n > offset && s[n - 1] == '/') --n;
    if (offset >= n) return (bc_string){0};
    size_t end = offset, port_at = n;
    if (s[offset] == '[') {
        ++end;
        while (end < n && s[end] != ']') ++end;
        if (end == n || !ipv6(s + offset + 1, end - offset - 1)) return (bc_string){0};
        ++end;
        if (end < n) { if (s[end] != ':') return (bc_string){0}; port_at = end + 1; }
    } else {
        while (end < n && s[end] != ':') ++end;
        if (!hostname(s + offset, end - offset)) return (bc_string){0};
        if (end < n) port_at = end + 1;
    }
    unsigned port = protocol == BC_INVENTORY_IPMI ? 623 : 443;
    if (port_at < n) {
        port = 0;
        if (n - port_at > 5) return (bc_string){0};
        for (size_t i = port_at; i < n; ++i) { if (s[i] < '0' || s[i] > '9') return (bc_string){0}; port = port * 10 + (unsigned)(s[i] - '0'); }
        if (!port || port > 65535) return (bc_string){0};
    } else if (end < n) return (bc_string){0};
    size_t used = strlen(scheme); memcpy(result, scheme, used);
    for (size_t i = offset; i < end; ++i) result[used++] = s[i] >= 'A' && s[i] <= 'Z' ? (char)(s[i] + 32) : s[i];
    if (port != (protocol == BC_INVENTORY_IPMI ? 623u : 443u)) used += (size_t)snprintf(result + used, sizeof(result) - used, ":%u", port);
    return copy(result, used);
}
static bc_status add(bc_inventory_import *value, const bc_string input[5], bc_inventory_error *error) {
    if (value->count == BC_INVENTORY_MAX_ENTRIES) return failure(error, BC_INVENTORY_ERROR_LIMIT, 0, BC_LIMIT_EXCEEDED);
    const size_t limits[] = {120, 2048, 64, 16, 8192};
    for (unsigned i = 0; i < 5; ++i)
        if (input[i].length > limits[i] || (input[i].length && !text_valid(input[i].data, (size_t)input[i].length)))
            return failure(error, BC_INVENTORY_ERROR_FIELD, i + 1, BC_INVALID_ARGUMENT);
    uint32_t protocol = BC_INVENTORY_AUTO;
    if (input[3].length) {
        const char *p = input[3].data; uint64_t n = input[3].length;
        if (n == 7 && !memcmp(p, "redfish", 7)) protocol = BC_INVENTORY_REDFISH;
        else if (n == 4 && !memcmp(p, "ipmi", 4)) protocol = BC_INVENTORY_IPMI;
        else if (n != 4 || memcmp(p, "auto", 4)) return failure(error, BC_INVENTORY_ERROR_FIELD, 4, BC_INVALID_ARGUMENT);
    }
    if (!input[1].length) return failure(error, BC_INVENTORY_ERROR_FIELD, 2, BC_INVALID_ARGUMENT);
    if (input[4].length && !bc_redfish_uri_supported(input[4])) return failure(error, BC_INVENTORY_ERROR_FIELD, 5, BC_INVALID_ARGUMENT);
    bc_inventory_entry entry = {0}; entry.struct_size = sizeof(entry); entry.protocol = protocol; entry.duplicate_of = BC_INVENTORY_NO_DUPLICATE;
    entry.address = address(input[1].data, (size_t)input[1].length, protocol);
    if (!entry.address.data) return failure(error, BC_INVENTORY_ERROR_FIELD, 2, BC_INVALID_ARGUMENT);
    entry.name = copy(input[0].data ? input[0].data : "", (size_t)input[0].length);
    entry.username = copy(input[2].data ? input[2].data : "", (size_t)input[2].length);
    entry.system_uri = copy(input[4].data ? input[4].data : "", (size_t)input[4].length);
    if (!entry.name.data || !entry.username.data || !entry.system_uri.data) { clear_entry(&entry); return BC_NO_MEMORY; }
    for (uint32_t i = 0; i < value->count; ++i) {
        const bc_inventory_entry *previous = &value->entries[i];
        if (!strcmp(previous->address.data, entry.address.data) && !strcmp(previous->system_uri.data, entry.system_uri.data)) { entry.duplicate_of = i; break; }
    }
    value->entries[value->count++] = entry;
    return BC_OK;
}
static bc_status json_parse(bc_inventory_import *value, const char *data, size_t size, bc_inventory_error *error) {
    yyjson_read_err parse_error;
    yyjson_doc *doc = yyjson_read_opts((char *)data, size, 0, NULL, &parse_error);
    if (!doc) {
        error->line = 1;
        for (size_t i = 0; i < parse_error.pos && i < size; ++i) if (data[i] == '\n') ++error->line;
        return failure(error, BC_INVENTORY_ERROR_SYNTAX, 0, BC_PROTOCOL_ERROR);
    }
    bc_status status = BC_OK;
    yyjson_val *root = yyjson_doc_get_root(doc), *servers = NULL;
    if (!yyjson_is_obj(root) || yyjson_obj_size(root) != 2) status = failure(error, BC_INVENTORY_ERROR_FIELD, BC_INVENTORY_FIELD_UNKNOWN, BC_INVALID_ARGUMENT);
    if (status == BC_OK) {
        unsigned seen = 0; size_t i, max; yyjson_val *key, *item;
        yyjson_obj_foreach(root, i, max, key, item) {
            const char *name = yyjson_get_str(key); unsigned bit = yyjson_get_len(key) == 7 && !memcmp(name, "version", 7) ? 1u : yyjson_get_len(key) == 7 && !memcmp(name, "servers", 7) ? 2u : 0;
            if (!bit || (seen & bit)) { status = failure(error, BC_INVENTORY_ERROR_FIELD, BC_INVENTORY_FIELD_UNKNOWN, BC_INVALID_ARGUMENT); break; }
            seen |= bit;
        }
        yyjson_val *version = yyjson_obj_get(root, "version"); servers = yyjson_obj_get(root, "servers");
        if (status == BC_OK && (!yyjson_is_uint(version) || yyjson_get_uint(version) != 1)) status = failure(error, BC_INVENTORY_ERROR_VERSION, 0, BC_UNSUPPORTED);
        if (status == BC_OK && !yyjson_is_arr(servers)) status = failure(error, BC_INVENTORY_ERROR_FIELD, 0, BC_INVALID_ARGUMENT);
    }
    if (status == BC_OK && yyjson_arr_size(servers) > BC_INVENTORY_MAX_ENTRIES) status = failure(error, BC_INVENTORY_ERROR_LIMIT, 0, BC_LIMIT_EXCEEDED);
    if (status == BC_OK) {
        size_t i, max; yyjson_val *record;
        yyjson_arr_foreach(servers, i, max, record) {
            error->record = (uint32_t)i + 1; bc_string input[5] = {{0}}; unsigned seen = 0;
            if (!yyjson_is_obj(record)) { status = failure(error, BC_INVENTORY_ERROR_FIELD, 0, BC_INVALID_ARGUMENT); break; }
            size_t j, count; yyjson_val *key, *item;
            yyjson_obj_foreach(record, j, count, key, item) {
                int field = field_index(yyjson_get_str(key), yyjson_get_len(key));
                if (field < 0 || (seen & (1u << field)) || !yyjson_is_str(item)) {
                    status = failure(error, BC_INVENTORY_ERROR_FIELD, field < 0 ? BC_INVENTORY_FIELD_UNKNOWN : (uint32_t)field + 1, BC_INVALID_ARGUMENT); break;
                }
                seen |= 1u << field; input[field] = (bc_string){yyjson_get_str(item), yyjson_get_len(item)};
            }
            if (status == BC_OK) status = add(value, input, error);
            if (status != BC_OK) break;
        }
    }
    yyjson_doc_free(doc); return status;
}
static int utf8(const uint8_t *s, size_t n) {
    for (size_t i = 0; i < n;) {
        uint32_t code = s[i++]; unsigned trailing; uint32_t minimum;
        if (code < 128) continue;
        if (code >= 0xc2 && code <= 0xdf) { trailing = 1; minimum = 0x80; code &= 31; }
        else if (code >= 0xe0 && code <= 0xef) { trailing = 2; minimum = 0x800; code &= 15; }
        else if (code >= 0xf0 && code <= 0xf4) { trailing = 3; minimum = 0x10000; code &= 7; }
        else return 0;
        if (trailing > n - i) return 0;
        while (trailing--) { if ((s[i] & 0xc0) != 0x80) return 0; code = (code << 6) | (s[i++] & 63); }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return 0;
    }
    return 1;
}
static bc_status csv_parse(bc_inventory_import *value, const char *data, size_t size, bc_inventory_error *error) {
    char *buffer = malloc(size + 1); if (!buffer) return BC_NO_MEMORY;
    bc_string cells[5] = {{0}}; int columns[5]; unsigned column_count = 0, cell_count = 0, seen = 0;
    size_t used = 0, start = 0; int state = 0, header = 1, record_open = 0; bc_status status = BC_OK;
    error->line = 1;
    for (size_t at = 0; at <= size; ++at) {
        int end = at == size; char c = end ? '\n' : data[at];
        if (end && !record_open && !cell_count && used == start) break;
        if (state == 1) {
            if (end) { status = failure(error, BC_INVENTORY_ERROR_SYNTAX, 0, BC_PROTOCOL_ERROR); break; }
            if (c == '"') { if (at + 1 < size && data[at + 1] == '"') { buffer[used++] = '"'; ++at; } else state = 2; }
            else { buffer[used++] = c; if (c == '\n') ++error->line; }
            continue;
        }
        if (state == 2 && c != ',' && c != '\r' && c != '\n') { status = failure(error, BC_INVENTORY_ERROR_SYNTAX, 0, BC_PROTOCOL_ERROR); break; }
        if (!state && c == '"') { if (used != start) { status = failure(error, BC_INVENTORY_ERROR_SYNTAX, 0, BC_PROTOCOL_ERROR); break; } state = 1; record_open = 1; continue; }
        if (c != ',' && c != '\r' && c != '\n') { buffer[used++] = c; record_open = 1; continue; }
        if (cell_count == 5) { status = failure(error, BC_INVENTORY_ERROR_FIELD, BC_INVENTORY_FIELD_UNKNOWN, BC_INVALID_ARGUMENT); break; }
        cells[cell_count++] = (bc_string){buffer + start, used - start}; buffer[used++] = 0; start = used; state = 0;
        if (c == ',') { record_open = 1; continue; }
        if (header) {
            for (unsigned i = 0; i < cell_count; ++i) {
                int index = field_index(cells[i].data, (size_t)cells[i].length);
                if (index < 0 || (seen & (1u << index))) { status = failure(error, BC_INVENTORY_ERROR_FIELD, BC_INVENTORY_FIELD_UNKNOWN, BC_INVALID_ARGUMENT); break; }
                columns[i] = index; seen |= 1u << index;
            }
            column_count = cell_count; header = 0;
            if (status == BC_OK && !(seen & 2u)) status = failure(error, BC_INVENTORY_ERROR_FIELD, 2, BC_INVALID_ARGUMENT);
        } else {
            error->record = value->count + 1;
            if (cell_count != column_count) status = failure(error, BC_INVENTORY_ERROR_FIELD, 0, BC_INVALID_ARGUMENT);
            else { bc_string input[5] = {{0}}; for (unsigned i = 0; i < cell_count; ++i) input[columns[i]] = cells[i]; status = add(value, input, error); }
        }
        if (status != BC_OK) break;
        if (c == '\r' && at + 1 < size && data[at + 1] == '\n') ++at;
        ++error->line; cell_count = 0; used = start = 0; record_open = 0;
    }
    if (status == BC_OK && header) status = failure(error, BC_INVENTORY_ERROR_SYNTAX, 0, BC_PROTOCOL_ERROR);
    free(buffer); return status;
}
bc_status bc_inventory_parse(bc_bytes input, uint32_t format, bc_inventory_import **out, bc_inventory_error *error) {
    if (!out || !error || error->struct_size != sizeof(*error)) return BC_INVALID_ARGUMENT;
    *out = NULL; memset(error, 0, sizeof(*error)); error->struct_size = sizeof(*error);
    if (!input.data || !input.length || (format != BC_INVENTORY_JSON && format != BC_INVENTORY_CSV)) return BC_INVALID_ARGUMENT;
    if (input.length > BC_INVENTORY_MAX_BYTES) return failure(error, BC_INVENTORY_ERROR_LIMIT, 0, BC_LIMIT_EXCEEDED);
    const uint8_t *data = input.data; size_t size = (size_t)input.length;
    if (size >= 3 && !memcmp(data, "\xef\xbb\xbf", 3)) { data += 3; size -= 3; }
    if (!utf8(data, size)) return failure(error, BC_INVENTORY_ERROR_SYNTAX, 0, BC_PROTOCOL_ERROR);
    bc_inventory_import *value = calloc(1, sizeof(*value)); if (!value) return BC_NO_MEMORY;
    value->entries = calloc(BC_INVENTORY_MAX_ENTRIES, sizeof(*value->entries));
    if (!value->entries) { free(value); return BC_NO_MEMORY; }
    bc_status status = format == BC_INVENTORY_JSON ? json_parse(value, (const char *)data, size, error) : csv_parse(value, (const char *)data, size, error);
    if (status != BC_OK) { bc_inventory_import_destroy(value); return status; }
    error->line = error->record = 0; *out = value; return BC_OK;
}

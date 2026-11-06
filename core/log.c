#include "bcontrol/log.h"
#include "log_internal.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint32_t level;
    uint32_t categories;
    bc_log_sink sink;
    void *userdata;
} log_state;

static log_state state;

int bc_log_enabled(uint32_t level, uint32_t category) {
    return state.sink && state.level != BC_LOG_LEVEL_OFF && level <= state.level &&
        level <= BC_LOG_LEVEL_VERBOSE && (state.categories & category) != 0;
}

bc_status bc_log_configure(const bc_log_options *options) {
    if (!options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        options->reserved || options->level > BC_LOG_LEVEL_VERBOSE ||
        (options->level != BC_LOG_LEVEL_OFF && !options->sink)) return BC_INVALID_ARGUMENT;
    state.level = options->level;
    state.categories = options->categories;
    state.sink = options->sink;
    state.userdata = options->userdata;
    return BC_OK;
}

static void sanitize(char *text, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c < 32 || c == 127) text[i] = ' ';
    }
}

void bc_log_emitf(uint32_t level, uint32_t category, const char *event, const char *format, ...) {
    if (!bc_log_enabled(level, category)) return;
    char detail[BC_LOG_DETAIL_MAX];
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(detail, sizeof(detail), format, arguments);
    va_end(arguments);
    if (written < 0) detail[0] = 0;
    sanitize(detail, strlen(detail));
    bc_log_sink sink = state.sink;
    void *userdata = state.userdata;
    bc_log_record record = {sizeof(record), level, category,
        (bc_string){event ? event : "", event ? strlen(event) : 0}, (bc_string){detail, strlen(detail)}};
    sink(userdata, &record);
}

uint32_t bc_log_path(char *out, size_t capacity, const char *data, size_t length) {
    if (!out || !capacity) return 0;
    size_t used = 0;
    uint32_t query = 0, truncated = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)data[i];
        if (c == '?' || c == '#') { query = 1; break; }
        if (used + 1 < capacity) out[used++] = (char)(c < 32 || c == 127 ? '?' : c);
        else truncated = 1;
    }
    if ((truncated || query) && used + 4 < capacity) {
        out[used++] = '.'; out[used++] = '.'; out[used++] = '.';
    }
    out[used] = 0;
    return query;
}

void bc_log_text(char *out, size_t capacity, const char *data, size_t length) {
    if (!out || !capacity) return;
    size_t used = 0;
    for (size_t i = 0; i < length && used + 1 < capacity; ++i) {
        unsigned char c = (unsigned char)data[i];
        out[used++] = (char)(c < 32 || c == 127 ? '?' : c);
    }
    out[used] = 0;
}

uint32_t bc_log_hex(char *out, size_t capacity, const uint8_t *data, uint32_t length, uint32_t maximum) {
    static const char digits[] = "0123456789abcdef";
    if (!out || capacity < 3 || !data) return 0;
    uint32_t limit = length < maximum ? length : maximum;
    uint32_t used = 0;
    for (uint32_t i = 0; i < limit && used + 3 <= capacity; ++i) {
        out[used++] = digits[data[i] >> 4];
        out[used++] = digits[data[i] & 15];
    }
    out[used] = 0;
    return used / 2;
}

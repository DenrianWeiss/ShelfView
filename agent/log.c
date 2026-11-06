#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "log.h"
#include "bcontrol/log.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static int equal_ci(const char *text, size_t length, const char *name) {
    size_t n = strlen(name);
    if (length != n) return 0;
    for (size_t i = 0; i < n; ++i) {
        char c = text[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != name[i]) return 0;
    }
    return 1;
}
static int level_value(const char *text, size_t length, uint32_t *out) {
    static const struct { const char *name; uint32_t value; } levels[] = {
        {"off", BC_LOG_LEVEL_OFF}, {"error", BC_LOG_LEVEL_ERROR}, {"warn", BC_LOG_LEVEL_WARN},
        {"info", BC_LOG_LEVEL_INFO}, {"debug", BC_LOG_LEVEL_DEBUG}, {"trace", BC_LOG_LEVEL_TRACE},
        {"verbose", BC_LOG_LEVEL_VERBOSE}
    };
    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); ++i)
        if (equal_ci(text, length, levels[i].name)) { *out = levels[i].value; return 1; }
    return 0;
}
static int category_value(const char *text, size_t length, uint32_t *out) {
    static const struct { const char *name; uint32_t value; } categories[] = {
        {"lifecycle", BC_LOG_CATEGORY_LIFECYCLE}, {"http", BC_LOG_CATEGORY_HTTP},
        {"tls", BC_LOG_CATEGORY_TLS}, {"redfish", BC_LOG_CATEGORY_REDFISH},
        {"ipmi", BC_LOG_CATEGORY_IPMI}, {"kvm", BC_LOG_CATEGORY_KVM},
        {"media", BC_LOG_CATEGORY_MEDIA}, {"vendor", BC_LOG_CATEGORY_VENDOR}
    };
    if (equal_ci(text, length, "all")) { *out = BC_LOG_CATEGORY_ALL; return 1; }
    if (equal_ci(text, length, "none")) { *out = 0; return 1; }
    for (size_t i = 0; i < sizeof(categories) / sizeof(categories[0]); ++i)
        if (equal_ci(text, length, categories[i].name)) { *out = categories[i].value; return 1; }
    return 0;
}
static int category_list(const char *text, uint32_t *out) {
    uint32_t mask = 0;
    while (*text) {
        const char *comma = strchr(text, ',');
        size_t length = comma ? (size_t)(comma - text) : strlen(text);
        uint32_t value = 0;
        if (!length || !category_value(text, length, &value)) return 0;
        mask |= value;
        if (!comma) break;
        text = comma + 1;
    }
    *out = mask;
    return 1;
}
static const char *level_name(uint32_t level) {
    static const char *const names[] = {"off", "error", "warn", "info", "debug", "trace", "verbose"};
    return level < sizeof(names) / sizeof(names[0]) ? names[level] : "unknown";
}
static const char *category_name(uint32_t category) {
    switch (category) {
    case BC_LOG_CATEGORY_LIFECYCLE: return "lifecycle";
    case BC_LOG_CATEGORY_HTTP: return "http";
    case BC_LOG_CATEGORY_TLS: return "tls";
    case BC_LOG_CATEGORY_REDFISH: return "redfish";
    case BC_LOG_CATEGORY_IPMI: return "ipmi";
    case BC_LOG_CATEGORY_KVM: return "kvm";
    case BC_LOG_CATEGORY_MEDIA: return "media";
    case BC_LOG_CATEGORY_VENDOR: return "vendor";
    default: return "other";
    }
}
static void write_stderr(void *userdata, const bc_log_record *record) {
    (void)userdata;
    char stamp[32] = "-";
    time_t now = time(NULL);
    struct tm broken;
#ifdef _WIN32
    if (gmtime_s(&broken, &now) == 0) strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &broken);
#else
    if (gmtime_r(&now, &broken)) strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &broken);
#endif
    fprintf(stderr, "%s level=%s category=%s event=%.*s %.*s\n", stamp, level_name(record->level),
        category_name(record->category), (int)record->event.length, record->event.data ? record->event.data : "",
        (int)record->detail.length, record->detail.data ? record->detail.data : "");
    fflush(stderr);
}
int bc_agent_log_options(int *argc, char **argv) {
    uint32_t level = BC_LOG_LEVEL_OFF, categories = BC_LOG_CATEGORY_ALL;
    int level_set = 0;
    int write = 1;
    for (int i = 1; i < *argc; ++i) {
        const char *argument = argv[i], *value = NULL;
        int is_level = 0, is_categories = 0;
        if (!strcmp(argument, "--log-level")) {
            if (++i >= *argc) { fputs("bcontrol-agent: --log-level requires a value\n", stderr); return 2; }
            value = argv[i]; is_level = 1;
        } else if (!strncmp(argument, "--log-level=", 12)) {
            value = argument + 12; is_level = 1;
        } else if (!strcmp(argument, "--log-categories")) {
            if (++i >= *argc) { fputs("bcontrol-agent: --log-categories requires a value\n", stderr); return 2; }
            value = argv[i]; is_categories = 1;
        } else if (!strncmp(argument, "--log-categories=", 17)) {
            value = argument + 17; is_categories = 1;
        }
        if (is_level) {
            if (!level_value(value, strlen(value), &level)) {
                fprintf(stderr, "bcontrol-agent: unknown log level '%s'\n", value);
                return 2;
            }
            level_set = 1;
        } else if (is_categories) {
            if (!category_list(value, &categories)) {
                fprintf(stderr, "bcontrol-agent: unknown log category list '%s'\n", value);
                return 2;
            }
        } else {
            argv[write++] = argv[i];
        }
    }
    argv[write] = NULL;
    *argc = write;
    if (level_set && level != BC_LOG_LEVEL_OFF) {
        bc_log_options options = {sizeof(options), BC_ABI_VERSION, level, categories, write_stderr, NULL, 0};
        if (bc_log_configure(&options) != BC_OK) {
            fputs("bcontrol-agent: cannot configure logging\n", stderr);
            return 2;
        }
    }
    return 0;
}

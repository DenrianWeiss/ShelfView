#ifndef BC_LOG_INTERNAL_H
#define BC_LOG_INTERNAL_H
#include "bcontrol/log.h"
#include <stddef.h>
#include <stdint.h>

#ifndef BC_LOG_COMPILE_LEVEL
#define BC_LOG_COMPILE_LEVEL BC_LOG_LEVEL_VERBOSE
#endif

#define BC_LOG_PATH_MAX 512u
#define BC_LOG_TEXT_MAX 256u
#define BC_LOG_DETAIL_MAX 2048u

/* Internal cross-library entry points; not part of the installed ABI. */
BC_API int bc_log_enabled(uint32_t level, uint32_t category);
BC_API void bc_log_emitf(uint32_t level, uint32_t category, const char *event, const char *format, ...);
/* Writes the pathname without query/fragment values. Returns 1 if a query or
 * fragment was stripped. */
BC_API uint32_t bc_log_path(char *out, size_t capacity, const char *data, size_t length);
BC_API void bc_log_text(char *out, size_t capacity, const char *data, size_t length);
/* Returns the number of source bytes rendered and writes lowercase hex. */
BC_API uint32_t bc_log_hex(char *out, size_t capacity, const uint8_t *data, uint32_t length, uint32_t maximum);

#define BC_LOG_AT(level, category, event, ...) do { \
    if (bc_log_enabled((level), (category))) bc_log_emitf((level), (category), (event), __VA_ARGS__); \
} while (0)

#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_ERROR
#define BC_LOG_ERROR(category, event, ...) BC_LOG_AT(BC_LOG_LEVEL_ERROR, category, event, __VA_ARGS__)
#else
#define BC_LOG_ERROR(category, event, ...) ((void)0)
#endif
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_WARN
#define BC_LOG_WARN(category, event, ...) BC_LOG_AT(BC_LOG_LEVEL_WARN, category, event, __VA_ARGS__)
#else
#define BC_LOG_WARN(category, event, ...) ((void)0)
#endif
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_INFO
#define BC_LOG_INFO(category, event, ...) BC_LOG_AT(BC_LOG_LEVEL_INFO, category, event, __VA_ARGS__)
#else
#define BC_LOG_INFO(category, event, ...) ((void)0)
#endif
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_DEBUG
#define BC_LOG_DEBUG(category, event, ...) BC_LOG_AT(BC_LOG_LEVEL_DEBUG, category, event, __VA_ARGS__)
#else
#define BC_LOG_DEBUG(category, event, ...) ((void)0)
#endif
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_TRACE
#define BC_LOG_TRACE(category, event, ...) BC_LOG_AT(BC_LOG_LEVEL_TRACE, category, event, __VA_ARGS__)
#else
#define BC_LOG_TRACE(category, event, ...) ((void)0)
#endif
#if BC_LOG_COMPILE_LEVEL >= BC_LOG_LEVEL_VERBOSE
#define BC_LOG_VERBOSE(category, event, ...) BC_LOG_AT(BC_LOG_LEVEL_VERBOSE, category, event, __VA_ARGS__)
#else
#define BC_LOG_VERBOSE(category, event, ...) ((void)0)
#endif

#endif

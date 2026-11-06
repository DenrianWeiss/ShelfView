#ifndef BCONTROL_DIAGNOSTIC_ASSETS_H
#define BCONTROL_DIAGNOSTIC_ASSETS_H
#include "console_discovery.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Pure structured XML redaction, <=64KiB input and <=512KiB output. No I/O.
 * Unknown values and all URLs are hidden; safe relative archive names and
 * explicitly known protocol switches/ports may remain. Positional arguments
 * are hidden unless the existing strict descriptor proves named pairs.
 * NULL output/capacity0 queries required bytes, excluding the trailing NUL.
 * Otherwise capacity must exceed written. On failure output is empty; never
 * fall back to exporting the raw JNLP. This output is diagnostic, not runnable. */
BC_DISCOVERY_API bc_status bc_diagnostic_jnlp_redact(const uint8_t *, uint32_t,
    char *output, uint32_t capacity, uint32_t *written);
#ifdef __cplusplus
}
#endif
#endif

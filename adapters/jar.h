#ifndef BC_JAR_H
#define BC_JAR_H
#include "bcontrol/bcontrol.h"
typedef struct { uint8_t *data; uint32_t length; } bc_jar_entry;
/* Outputs must be zero initialized; clear them on success and failure. */
bc_status bc_jar_extract(const uint8_t *, uint32_t, const char *const *, uint32_t, bc_jar_entry *);
void bc_jar_entries_clear(bc_jar_entry *, uint32_t);
#endif

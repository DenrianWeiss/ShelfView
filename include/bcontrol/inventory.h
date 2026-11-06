#ifndef BCONTROL_INVENTORY_H
#define BCONTROL_INVENTORY_H
#include "bcontrol.h"
#if defined(_WIN32)
# ifdef BC_INVENTORY_BUILD
#  define BC_INVENTORY_API __declspec(dllexport)
# else
#  define BC_INVENTORY_API __declspec(dllimport)
# endif
#else
# define BC_INVENTORY_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define BC_INVENTORY_JSON 1u
#define BC_INVENTORY_CSV 2u
#define BC_INVENTORY_AUTO 0u
#define BC_INVENTORY_REDFISH 1u
#define BC_INVENTORY_IPMI 2u
#define BC_INVENTORY_MAX_BYTES 1048576u
#define BC_INVENTORY_MAX_ENTRIES 1000u
#define BC_INVENTORY_NO_DUPLICATE UINT32_MAX
#define BC_INVENTORY_FIELD_NONE 0u
#define BC_INVENTORY_FIELD_NAME 1u
#define BC_INVENTORY_FIELD_ADDRESS 2u
#define BC_INVENTORY_FIELD_USERNAME 3u
#define BC_INVENTORY_FIELD_PROTOCOL 4u
#define BC_INVENTORY_FIELD_SYSTEM_URI 5u
#define BC_INVENTORY_FIELD_UNKNOWN 6u
#define BC_INVENTORY_ERROR_SYNTAX 1u
#define BC_INVENTORY_ERROR_VERSION 2u
#define BC_INVENTORY_ERROR_FIELD 3u
#define BC_INVENTORY_ERROR_LIMIT 4u

typedef struct bc_inventory_import bc_inventory_import;
typedef struct {
    uint32_t struct_size;
    uint32_t record;
    uint32_t line;
    uint32_t field;
    uint32_t code;
    uint32_t reserved;
} bc_inventory_error;
typedef struct {
    uint32_t struct_size;
    uint32_t protocol;
    uint32_t duplicate_of;
    uint32_t reserved;
    bc_string name;
    bc_string address;
    bc_string username;
    bc_string system_uri;
} bc_inventory_entry;
/* Parsing and canonicalization only: no I/O, credentials or configuration writes.
 * Views remain valid until import_destroy. Errors never contain input values. */
BC_INVENTORY_API bc_status bc_inventory_parse(bc_bytes, uint32_t format, bc_inventory_import **, bc_inventory_error *);
BC_INVENTORY_API uint32_t bc_inventory_count(const bc_inventory_import *);
BC_INVENTORY_API const bc_inventory_entry *bc_inventory_entry_get(const bc_inventory_import *, uint32_t index);
BC_INVENTORY_API void bc_inventory_import_destroy(bc_inventory_import *);
#ifdef __cplusplus
}
#endif
#endif

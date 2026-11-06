#ifndef BC_PACK_MEMORY_H
#define BC_PACK_MEMORY_H
#include <stddef.h>
void *bc_pack_malloc(size_t);
void *bc_pack_realloc(void *,size_t);
void bc_pack_free(void *);
#endif

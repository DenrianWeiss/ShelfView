#ifndef BC_ZTE_REMOTE_MEDIA_H
#define BC_ZTE_REMOTE_MEDIA_H
#include "bcontrol/redfish.h"
#include "yyjson.h"

bc_status bc_zte_media_target(yyjson_val *, bc_string slot, const char **target, const char **media_type);
bc_status bc_zte_media_body(const bc_redfish_virtual_media_insert_options *, char **, size_t *);
int bc_zte_media_accepted(bc_bytes, bc_string slot);

#endif

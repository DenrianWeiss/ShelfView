#ifndef BC_LENOVO_REMOTE_MEDIA_H
#define BC_LENOVO_REMOTE_MEDIA_H
#include "bcontrol/redfish.h"
#include "yyjson.h"
uint32_t bc_lenovo_media_candidate(yyjson_val *, bc_string uri, char owner[1025]);
int bc_lenovo_media_owner(yyjson_val *, bc_string uri);
#endif

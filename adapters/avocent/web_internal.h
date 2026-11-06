#ifndef BC_AVOCENT_WEB_INTERNAL_H
#define BC_AVOCENT_WEB_INTERNAL_H
#include "bcontrol/bcontrol.h"
typedef struct {
    uint32_t status, auth_result, fields;
    char forward[1025];
} bc_avocent_web_reply;
bc_status bc_avocent_web_parse(bc_bytes, int login, bc_avocent_web_reply *);
char *bc_avocent_web_password(bc_string);
#endif

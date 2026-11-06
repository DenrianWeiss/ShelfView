#ifndef BCONTROL_INSPUR_INTERNAL_H
#define BCONTROL_INSPUR_INTERNAL_H
#include "bcontrol/megarac.h"
#include "bcontrol/inspur.h"
bc_status bc_inspur_login_form(bc_string, bc_string, const uint8_t *, uint32_t, char **);
int bc_inspur_web_media_proxy_matches(const uint8_t *, uint32_t);
#endif

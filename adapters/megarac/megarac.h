#ifndef BCONTROL_MEGARAC_COMPAT_H
#define BCONTROL_MEGARAC_COMPAT_H
#include "bcontrol/megarac.h"

int bc_megarac_session_is_irmc(const bc_megarac_session *);
bc_status bc_megarac_ast_header(const uint8_t *, bc_megarac_video_header *);
#endif

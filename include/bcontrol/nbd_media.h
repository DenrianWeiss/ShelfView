#ifndef BCONTROL_NBD_MEDIA_H
#define BCONTROL_NBD_MEDIA_H
#include "media_factory.h"
#ifdef __cplusplus
extern "C" {
#endif
BC_CONSOLE_API bc_status bc_nbd_media_create(const bc_media_options *, bc_media_session **);
#ifdef __cplusplus
}
#endif
#endif

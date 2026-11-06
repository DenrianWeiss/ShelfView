#ifndef BCONTROL_AVOCENT_MEDIA_H
#define BCONTROL_AVOCENT_MEDIA_H
#include "avocent.h"
#include "media_factory.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Uses an already negotiated APCP/TLS transport. Copies the single-use ticket. */
BC_AVOCENT_API bc_status bc_avocent_media_create(const bc_media_options *, bc_media_session **);
#ifdef __cplusplus
}
#endif
#endif

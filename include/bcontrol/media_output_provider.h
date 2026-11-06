#ifndef BCONTROL_MEDIA_OUTPUT_PROVIDER_H
#define BCONTROL_MEDIA_OUTPUT_PROVIDER_H
#include "media_session.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct bc_media_output bc_media_output;
BC_API bc_status bc_media_output_create(bc_media_output **);
BC_API bc_status bc_media_output_emit(void *, const uint8_t *, uint32_t);
BC_API bc_status bc_media_output_take(bc_media_output *, uint8_t *, uint32_t, uint32_t *);
BC_API void bc_media_output_destroy(bc_media_output *);
BC_API void bc_media_session_bind_output(bc_media_session *, bc_media_output *);
#ifdef __cplusplus
}
#endif
#endif

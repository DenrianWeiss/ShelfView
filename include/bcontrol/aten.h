#ifndef BCONTROL_ATEN_H
#define BCONTROL_ATEN_H
#include "console_factory.h"
#include "media_factory.h"
#if defined(_WIN32)
# ifdef BC_ATEN_BUILD
#  define BC_ATEN_API __declspec(dllexport)
# else
#  define BC_ATEN_API __declspec(dllimport)
# endif
#else
# define BC_ATEN_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t struct_size, port, media_port, tls, tls_port;
    char host[256], username[25], password[25], viewer_version[65];
    uint32_t media_tls_port, media_enabled, media_layout, pack_enabled, mouse_bytes, mouse_cipher;
    char jar_path[1025], native_path[1025], codebase[1025];
} bc_aten_launch;
/* Client version is diagnostic evidence, not a firmware or media-layout version. */
BC_ATEN_API bc_status bc_aten_launch_parse(const uint8_t *, uint32_t, bc_aten_launch *);
typedef struct bc_aten_identity bc_aten_identity;
BC_ATEN_API bc_status bc_aten_identity_extract(const uint8_t *, uint32_t, bc_aten_identity **);
BC_ATEN_API bc_string bc_aten_identity_certificate(const bc_aten_identity *);
BC_ATEN_API bc_string bc_aten_identity_private_key(const bc_aten_identity *);
BC_ATEN_API void bc_aten_identity_destroy(bc_aten_identity *);
BC_ATEN_API bc_status bc_aten_native_jar_media_layout(const uint8_t *, uint32_t, uint32_t *);
BC_ATEN_API bc_status bc_aten_native_media_layout(const uint8_t *, uint32_t, uint32_t *);
BC_ATEN_API bc_status bc_aten_native_mouse_bytes(const uint8_t *, uint32_t, uint32_t *);
BC_ATEN_API bc_status bc_aten_native_jar_mouse_bytes(const uint8_t *, uint32_t, uint32_t *);
BC_ATEN_API bc_status bc_aten_native_mouse_cipher(const uint8_t *, uint32_t, uint32_t *);
BC_ATEN_API bc_status bc_aten_native_jar_mouse_cipher(const uint8_t *, uint32_t, uint32_t *);
typedef struct { bc_aten_launch launch; uint32_t layout; } bc_aten_media_ticket;
BC_ATEN_API bc_status bc_aten_media_create(const bc_media_options *, bc_media_session **);
BC_ATEN_API bc_status bc_aten_console_create(const bc_aten_launch *, bc_console_emit, void *, bc_console_session **);
#ifdef __cplusplus
}
#endif
#endif

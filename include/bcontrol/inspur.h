#ifndef BCONTROL_INSPUR_H
#define BCONTROL_INSPUR_H
#include "bcontrol.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Known legacy firmware assets; matching is metadata, never login permission
 * on another endpoint. The caller must fetch both assets on its selected BMC. */
BC_API int bc_inspur_login_page_matches(const uint8_t *, uint32_t);
BC_API int bc_inspur_login_script_matches(const uint8_t *, uint32_t);
BC_API int bc_inspur_viewer_script_matches(const uint8_t *, uint32_t);
BC_API int bc_inspur_rpc_page_matches(const uint8_t *, uint32_t);
BC_API int bc_inspur_rpc_script_matches(const uint8_t *, uint32_t);
BC_API bc_bytes bc_inspur_rpc_payload(bc_bytes, const char *);
#ifdef __cplusplus
}
#endif
#endif

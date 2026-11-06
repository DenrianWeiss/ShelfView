#ifndef BC_WEB_LOGIN_INTERNAL_H
#define BC_WEB_LOGIN_INTERNAL_H
#include "bcontrol/web_login.h"
bc_status bc_web_login_page_matches(const uint8_t *, uint32_t, bc_string page_path,
    bc_string script_path, const bc_web_login_hint *);
#define BC_WEB_LINK_HTML 1u
#define BC_WEB_LINK_SCRIPT 2u
#define BC_WEB_LINK_INLINE 3u
#define BC_WEB_LINK_NAVIGATION 4u
#define BC_WEB_LINK_STARTUP 5u
typedef bc_status (*bc_web_link_callback)(void *, uint32_t kind, bc_string);
int bc_web_login_resolve_path(bc_string page, bc_string relative, char out[1025]);
bc_status bc_web_login_html_links(const uint8_t *, uint32_t, bc_web_link_callback, void *);
bc_status bc_web_login_script_origin_links(const uint8_t *, uint32_t, bc_string, bc_web_link_callback, void *);
bc_status bc_web_login_script_links(const uint8_t *, uint32_t, bc_web_link_callback, void *);
bc_status bc_web_login_page_library_matches(const uint8_t *, uint32_t, bc_string page_path,
    bc_string library_path, bc_string login_path, const bc_web_login_hint *);
struct bc_web_login_contract {
    bc_web_entry_graph *graph;
    bc_endpoint *endpoint;
    uint64_t generation;
    uint32_t flags, kind;
    int consumed;
    char cookie_name[65], csrf_path[1025], landing_path[1025];
};
bc_status bc_web_login_appweb_script(const uint8_t *, uint32_t);
bc_status bc_web_login_form_hint(const uint8_t *, uint32_t, bc_web_login_hint *);
bc_status bc_web_login_csrf_tokens(const uint8_t *, uint32_t, char st1[257], char st2[257]);
bc_status bc_web_session_submit(bc_web_session *, const bc_http_options *, bc_completion, void *, bc_request **);
bc_status bc_web_login_contract_validate(bc_web_login_contract *);
#endif

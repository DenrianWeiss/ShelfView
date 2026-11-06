#ifndef BC_SUPERMICRO_CONSOLE_H
#define BC_SUPERMICRO_CONSOLE_H
#include "bcontrol/web_login.h"

#define BC_SUPERMICRO_CONSOLE_PAGE "/cgi/url_redirect.cgi?url_name=man_remoteconsole"
#define BC_SUPERMICRO_MODE_PAGE "/cgi/url_redirect.cgi?url_name=man_remoteconsole_mod"
#define BC_SUPERMICRO_HTML5_PAGE "/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap"
#define BC_SUPERMICRO_JNLP "/cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk"

BC_DISCOVERY_API bc_status bc_supermicro_console_csrf(bc_bytes page, int require_change, char token[257]);
BC_DISCOVERY_API bc_status bc_supermicro_console_ticket(bc_bytes page, char ticket[25]);
BC_DISCOVERY_API bc_status bc_supermicro_console_mode(bc_bytes xml, uint32_t *mode);
BC_DISCOVERY_API bc_status bc_supermicro_html5_media_enabled(bc_bytes page, int *enabled);
#endif

#ifndef BC_MEGARAC_WEB_RPC_H
#define BC_MEGARAC_WEB_RPC_H
#include "bcontrol/bcontrol.h"

#define BC_MEGARAC_INLINE_RPC_LOGIN_PAGE "/page/login.html"
#define BC_MEGARAC_INLINE_RPC_LOGIN_SCRIPT "/impl/login_imp.js"
#define BC_MEGARAC_INLINE_RPC_XMIT_SCRIPT "/lib/xmit.js"
#define BC_MEGARAC_INLINE_RPC_LOGIN_RPC "/rpc/WEBSES/create.asp"

int bc_megarac_inline_rpc_asset_matches(const char *, bc_bytes);
#endif

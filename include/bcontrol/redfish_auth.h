#ifndef BCONTROL_REDFISH_AUTH_H
#define BCONTROL_REDFISH_AUTH_H
#include "redfish.h"
#ifdef __cplusplus
extern "C" {
#endif

#define BC_REDFISH_LOGIN_AUTO 0u
#define BC_REDFISH_LOGIN_BASIC 1u
#define BC_REDFISH_LOGIN_SESSION 2u
#define BC_REDFISH_AUTH_FELL_BACK 1u
#define BC_REDFISH_AUTH_SESSION_CREATED 2u
#define BC_REDFISH_AUTH_SESSION_MAY_EXIST 4u
#define BC_REDFISH_AUTH_PASSWORD_CHANGE_REQUIRED 8u
#define BC_REDFISH_AUTH_LOGGED_OUT 16u
#define BC_REDFISH_AUTH_INSPUR_LEGACY 32u
#define BC_REDFISH_CONNECTION_OPEN 0u
#define BC_REDFISH_CONNECTION_CLOSING 1u
#define BC_REDFISH_CONNECTION_CLOSED 2u

typedef struct bc_redfish_auth_operation bc_redfish_auth_operation;
typedef struct bc_redfish_connection bc_redfish_connection;
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t mode;
    uint32_t request_timeout_ms;
    bc_string username;
    bc_string password;
} bc_redfish_login_options;
typedef struct {
    uint32_t struct_size;
    uint32_t mode;
    uint32_t state;
    uint32_t reserved;
    bc_string session_uri;
    uint64_t endpoint_revision;
} bc_redfish_connection_info;
typedef struct {
    uint32_t struct_size;
    bc_status status;
    uint32_t http_status;
    uint32_t flags;
    uint32_t auth_mode;
    uint32_t reserved;
    bc_redfish_connection *connection;
    bc_string session_uri;
    bc_bytes error_body;
    bc_bytes messages_json;
} bc_redfish_auth_result;
typedef void (*bc_redfish_auth_completion)(bc_redfish_auth_operation *, const bc_redfish_auth_result *, void *);

BC_REDFISH_API bc_status bc_redfish_login(bc_endpoint *, const bc_redfish_login_options *, bc_redfish_auth_completion, void *, bc_redfish_auth_operation **);
BC_REDFISH_API bc_status bc_redfish_logout(bc_redfish_connection *, uint32_t timeout_ms, bc_redfish_auth_completion, void *, bc_redfish_auth_operation **);
BC_REDFISH_API bc_status bc_redfish_auth_cancel(bc_redfish_auth_operation *);
BC_REDFISH_API void bc_redfish_auth_retain(bc_redfish_auth_operation *);
BC_REDFISH_API void bc_redfish_auth_release(bc_redfish_auth_operation *);
BC_REDFISH_API const bc_redfish_auth_result *bc_redfish_auth_result_get(const bc_redfish_auth_operation *);
BC_REDFISH_API void bc_redfish_connection_retain(bc_redfish_connection *);
BC_REDFISH_API void bc_redfish_connection_release(bc_redfish_connection *);
BC_REDFISH_API const bc_redfish_connection_info *bc_redfish_connection_info_get(const bc_redfish_connection *);
BC_REDFISH_API bc_endpoint *bc_redfish_connection_endpoint(const bc_redfish_connection *);

#ifdef __cplusplus
}
#endif
#endif

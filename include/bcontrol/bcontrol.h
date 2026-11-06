#ifndef BCONTROL_H
#define BCONTROL_H
#include <stdint.h>
#if defined(_WIN32)
# ifdef BC_BUILD
#  define BC_API __declspec(dllexport)
# else
#  define BC_API __declspec(dllimport)
# endif
#else
# define BC_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define BC_ABI_VERSION 1u
typedef uint32_t bc_status;
#define BC_OK 0u
#define BC_INVALID_ARGUMENT 1u
#define BC_NO_MEMORY 2u
#define BC_BUSY 3u
#define BC_UNSUPPORTED 4u
#define BC_CANCELLED 5u
#define BC_TIMEOUT 6u
#define BC_TLS_ERROR 7u
#define BC_LIMIT_EXCEEDED 8u
#define BC_IO_ERROR 9u
#define BC_SHUTTING_DOWN 10u
#define BC_OUTCOME_UNKNOWN 11u
#define BC_HTTP_ERROR 12u
#define BC_PROTOCOL_ERROR 13u
#define BC_REDFISH_ERROR 14u
#define BC_CONFIRMATION_REQUIRED 15u
#define BC_AUTHENTICATION_FAILED 16u

#define BC_CERT_STRICT 0u
#define BC_CERT_SKIP_CHAIN 1u
#define BC_ENDPOINT_COOKIE_JAR 1u
#define BC_CERT_SKIP_ALL 2u
#define BC_TLS_DEFAULT 0u
#define BC_TLS_1_0 10u
#define BC_TLS_1_1 11u
#define BC_TLS_1_2 12u
#define BC_TLS_1_3 13u
#define BC_HTTP_GET 0u
#define BC_HTTP_POST 1u
#define BC_HTTP_PATCH 2u
#define BC_HTTP_DELETE 3u
#define BC_AUTH_NONE 0u
#define BC_AUTH_BASIC 1u
#define BC_AUTH_TOKEN 2u
#define BC_POWER_UNKNOWN 0u
#define BC_POWER_ON 1u
#define BC_POWER_OFF 2u
#define BC_POWERING_ON 3u
#define BC_POWERING_OFF 4u

typedef struct bc_context bc_context;
typedef struct bc_endpoint bc_endpoint;
typedef struct bc_request bc_request;
typedef struct bc_transport bc_transport;
typedef struct { const char *data; uint64_t length; } bc_string;
typedef struct { const uint8_t *data; uint64_t length; } bc_bytes;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    bc_transport *transport;
    uint64_t max_response_bytes;
    uint32_t max_requests;
    uint32_t reserved;
} bc_context_options;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    bc_string device_id;
    bc_string endpoint_id;
    bc_string origin;
    bc_string ca_file;
    bc_string username;
    bc_string password;
    uint32_t cert_policy;
    uint32_t tls_min;
    uint32_t tls_max;
    uint32_t reserved;
    uint32_t flags;
    uint32_t reserved2;
} bc_endpoint_options;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t mode;
    uint32_t reserved;
    bc_string username;
    bc_string password;
    bc_string token;
} bc_auth_options;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    bc_string path;
    bc_bytes body;
    uint32_t method;
    uint32_t timeout_ms;
    bc_string content_type;
    const bc_string *headers;
    uint32_t header_count;
    uint32_t reserved2;
} bc_http_options;

/* The peer ended the response before transport framing completed. Status
 * remains an error; protocol adapters may independently validate completeness. */
#define BC_RESPONSE_EARLY_EOF 1u
typedef struct {
    uint32_t struct_size;
    bc_status status;
    uint32_t http_status;
    uint32_t cert_policy;
    uint64_t endpoint_revision;
    bc_bytes body;
    bc_string error;
    bc_string tls_version;
    bc_string cipher;
    uint32_t peer_verified;
    uint32_t flags;
} bc_response;

typedef struct {
    uint32_t struct_size;
    uint32_t reserved;
    bc_string location;
    bc_string retry_after;
} bc_http_metadata;

typedef void (*bc_completion)(bc_request *, const bc_response *, void *);

BC_API uint32_t bc_abi_version(void);
BC_API const char *bc_status_string(bc_status status);
BC_API bc_status bc_context_create(const bc_context_options *, bc_context **);
/* All context/object operations are serialized on the polling thread. */
BC_API bc_status bc_context_poll(bc_context *, uint32_t timeout_ms);
BC_API bc_status bc_context_shutdown(bc_context *);
/* Destroy returns BUSY until all endpoints and requests have been released. */
BC_API bc_status bc_context_destroy(bc_context *);
BC_API bc_status bc_endpoint_create(bc_context *, const bc_endpoint_options *, bc_endpoint **);
/* Derive an isolated endpoint with the same target/TLS and explicit auth. */
BC_API bc_status bc_endpoint_with_auth(const bc_endpoint *, const bc_auth_options *, bc_endpoint **);
/* Copy a session token for vendor protocol authentication. No terminating NUL.
 * Caller must erase the output and must not log it; Basic endpoints return UNSUPPORTED. */
BC_API bc_status bc_endpoint_copy_auth_token(const bc_endpoint *, uint8_t *, uint32_t capacity, uint32_t *written);
BC_API void bc_endpoint_retain(bc_endpoint *);
BC_API void bc_endpoint_release(bc_endpoint *);
/* Import a script-issued host-only session cookie into this endpoint's enabled jar. */
/* Read-only capability check, before creating sessions that need body cookies. */
BC_API bc_status bc_endpoint_cookie_jar_available(const bc_endpoint *);
BC_API bc_status bc_endpoint_set_cookie(bc_endpoint *, bc_string name, bc_string value);
BC_API uint64_t bc_endpoint_revision(const bc_endpoint *);
/* Immutable original target; borrowed until endpoint release. Never log user targets. */
BC_API bc_string bc_endpoint_origin(const bc_endpoint *);
BC_API bc_status bc_http_submit(bc_endpoint *, const bc_http_options *, bc_completion, void *, bc_request **);
BC_API bc_status bc_request_cancel(bc_request *);
BC_API void bc_request_retain(bc_request *);
BC_API void bc_request_release(bc_request *);
/* Response is borrowed until request release; NULL before completion. */
BC_API const bc_response *bc_request_response(const bc_request *);
/* Provenance of an owned request; borrowed until request release. */
BC_API const bc_endpoint *bc_request_endpoint(const bc_request *);
/* Immutable borrowed request path, valid while retained. Queries may contain
 * secrets; do not log or persist. */
BC_API bc_string bc_request_path(const bc_request *);
/* Optional metadata is borrowed until request release; NULL if unavailable. */
BC_API const bc_http_metadata *bc_request_http_metadata(const bc_request *);
/* Sensitive response token; borrowed until request release, never logged. */
BC_API bc_string bc_request_auth_token(const bc_request *);
BC_API bc_string bc_request_cookie_header(const bc_request *);
/* Sensitive XSRF-TOKEN response header, distinct from Redfish X-Auth-Token.
 * Borrowed until request release; never log or persist. */
BC_API bc_string bc_request_csrf_token(const bc_request *);

#define BC_MEDIA_HEADER_SIZE 40u
#define BC_MEDIA_READ 1u
#define BC_MEDIA_DATA 2u
#define BC_MEDIA_ERROR 3u
#define BC_MEDIA_CANCEL 4u
#define BC_MEDIA_CLOSE 5u
typedef struct {
    uint32_t opcode;
    uint32_t channel;
    uint32_t flags;
    uint64_t request_id;
    uint64_t offset;
    uint32_t payload_length;
    uint32_t reserved;
} bc_media_header;
BC_API bc_status bc_media_header_encode(const bc_media_header *, uint8_t out[BC_MEDIA_HEADER_SIZE]);
BC_API bc_status bc_media_header_decode(const uint8_t *, uint64_t, uint32_t max_payload, bc_media_header *);
BC_API bc_status bc_media_range_check(uint64_t size, uint64_t offset, uint64_t length);
BC_API bc_status bc_media_read_encode(const bc_media_header *, uint32_t length, uint64_t source_size, uint32_t max_block, uint8_t out[44]);
BC_API bc_status bc_media_read_decode(const uint8_t *, uint64_t size, uint64_t source_size, uint32_t max_block, bc_media_header *, uint32_t *length);

#ifdef __cplusplus
}
#endif
#endif

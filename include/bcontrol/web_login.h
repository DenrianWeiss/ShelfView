#ifndef BCONTROL_WEB_LOGIN_H
#define BCONTROL_WEB_LOGIN_H
#include "console_discovery.h"
#ifdef __cplusplus
extern "C" {
#endif
#define BC_WEB_LOGIN_LEGACY_RPC 1u
#define BC_WEB_LOGIN_APPWEB_XML 2u
#define BC_WEB_LOGIN_ATEN_CGI 3u
#define BC_WEB_LOGIN_CLIENT_ID 1u
#define BC_WEB_LOGIN_TRANSPORT_TYPE 2u
#define BC_WEB_LOGIN_ATEN_BASE64 4u
/* Structural metadata only. It does not grant a KVM/media profile or authorize
 * login. The caller must also establish reachability from its public entry. */
typedef struct {
    uint32_t struct_size, kind, flags;
    char path[1025], username_input[65], password_input[65];
} bc_web_login_hint;
/* Bounded JavaScript lexical/call-relationship analysis, never execution.
 * Unknown request construction or ambiguous candidates return UNSUPPORTED. */
BC_DISCOVERY_API bc_status bc_web_login_script_hint(const uint8_t *, uint32_t, bc_web_login_hint *);
/* Pure same-page relationship analysis. Paths are origin-relative request paths;
 * source provenance remains the caller's responsibility in this raw form. */
BC_DISCOVERY_API bc_status bc_web_login_page_script_hint(const uint8_t *page, uint32_t page_length,
    bc_string page_path, const uint8_t *script, uint32_t script_length,
    bc_string script_path, bc_web_login_hint *);
#define BC_WEB_LOGIN_XMIT_FORM_POST 1u
#define BC_WEB_LOGIN_XMIT_SESSION_GUARD 2u
/* Same-library constructor/add/send/encoding relationships only. SESSION_GUARD
 * records the known browser-side sender replacement condition. Neither bit is
 * login permission, a response contract, or console protocol evidence. */
BC_DISCOVERY_API bc_status bc_web_login_xmit_form_hint(const uint8_t *, uint32_t, uint32_t *);
#define BC_WEB_LOGIN_RESPONSE_COOKIE 1u
#define BC_WEB_LOGIN_RESPONSE_CSRF_RPC 2u
typedef struct {
    uint32_t struct_size, flags;
    char csrf_path[1025], landing_relative[1025];
} bc_web_login_response_hint;
/* Pure callback/data-flow metadata; cookie-name and transport provenance are
 * required before Web login. Console routes remain independently discovered. */
BC_DISCOVERY_API bc_status bc_web_login_response_hint_get(const uint8_t *, uint32_t,
    bc_web_login_response_hint *);
/* Literal root-window cookie-key declaration; no script execution or inference
 * from protocol layouts. Source/window provenance remains a separate check. */
BC_DISCOVERY_API bc_status bc_web_login_cookie_name_hint(const uint8_t *, uint32_t, char out[65]);
typedef struct bc_web_login_evidence bc_web_login_evidence;
/* Both completed requests must belong to this exact endpoint. The HTML must
 * advertise the script's path and contain the matching text/password input IDs.
 * No I/O, root traversal, redirect following or authentication is performed. */
BC_DISCOVERY_API bc_status bc_web_login_evidence_from_requests(bc_endpoint *, uint64_t generation,
    bc_request *page, bc_request *script, bc_web_login_evidence **);
BC_DISCOVERY_API const bc_web_login_hint *bc_web_login_evidence_hint_get(const bc_web_login_evidence *,
    const bc_endpoint *, uint64_t generation);
BC_DISCOVERY_API void bc_web_login_evidence_cancel(bc_web_login_evidence *);
BC_DISCOVERY_API void bc_web_login_evidence_release(bc_web_login_evidence *);
typedef struct bc_web_entry_graph bc_web_entry_graph;
typedef struct {
    uint32_t struct_size, abi_version;
    uint64_t generation;
    uint32_t timeout_ms, max_requests, max_depth;
    uint64_t max_bytes;
    uint64_t (*clock_ms)(void *);
    void *clock_user;
} bc_web_entry_options;
typedef struct {
    uint32_t struct_size;
    bc_status status;
    uint64_t endpoint_revision, generation, bytes;
    uint32_t requests, skipped_links, unsupported_scripts, failed_requests;
    bc_web_login_hint hint;
    char page_path[1025], script_path[1025];
} bc_web_entry_result;
typedef void (*bc_web_entry_completion)(bc_web_entry_graph *, void *);
/* Starts at / and reads only advertised origin-relative HTML/JS assets. No
 * credentials are added, JS executed, login submitted or protocol granted.
 * Use a public endpoint without inherited credentials/cookies. Limits: <=32
 * requests, <=8 levels, <=8 MiB total, <=256 KiB per response. Clock userdata
 * outlives the graph. Unknown/dynamic navigation is recorded, never guessed. */
BC_DISCOVERY_API bc_status bc_web_entry_start(bc_endpoint *, const bc_web_entry_options *,
    bc_web_entry_completion, void *, bc_web_entry_graph **);
/* Exact endpoint/generation; expiry or clock regression clears the hint even
 * after completion. Paths may contain queries: do not log or persist them. */
BC_DISCOVERY_API const bc_web_entry_result *bc_web_entry_result_get(bc_web_entry_graph *,
    const bc_endpoint *, uint64_t generation);
/* The selected login HTML advertises this library before its login script,
 * both without async/defer. Still a hint, not permission to submit credentials. */
BC_DISCOVERY_API bc_status bc_web_entry_xmit_form_hint_get(bc_web_entry_graph *,
    const bc_endpoint *, uint64_t generation, uint32_t *);
/* Response metadata from the exact selected, source-bound login script.
 * Together with root cookie-name/transport evidence it can permit Web login;
 * console-route discovery is a separate step on that authenticated owner. */
BC_DISCOVERY_API bc_status bc_web_entry_response_hint_get(bc_web_entry_graph *,
    const bc_endpoint *, uint64_t generation, bc_web_login_response_hint *);
BC_DISCOVERY_API bc_status bc_web_entry_cancel(bc_web_entry_graph *);
BC_DISCOVERY_API void bc_web_entry_release(bc_web_entry_graph *);
typedef struct bc_web_login_contract bc_web_login_contract;
typedef struct bc_web_session bc_web_session;
/* A source-complete, single-use Web login permit. No KVM/media permission.
 * The exact public endpoint/generation and discovery expiry remain bound. */
BC_DISCOVERY_API bc_status bc_web_login_contract_from_graph(bc_web_entry_graph *,
    const bc_endpoint *, uint64_t generation, bc_web_login_contract **);
BC_DISCOVERY_API void bc_web_login_contract_release(bc_web_login_contract *);
typedef struct {
    uint32_t struct_size, abi_version, timeout_ms;
    bc_string username, password, client_id;
    /* Required monotonic clock; userdata outlives handshake and own cleanup.
     * timeout_ms covers login + CSRF together; logout has one separate window
     * of min(timeout_ms,5000ms), shared by any cleanup retries/release. */
    uint64_t (*clock_ms)(void *);
    void *clock_user;
} bc_web_session_options;
typedef struct {
    uint32_t struct_size;
    bc_status status, cleanup_status;
    uint32_t http_status;
    char landing_path[1025];
} bc_web_session_result;
typedef void (*bc_web_session_completion)(bc_web_session *, void *);
/* Owns a fresh credential-free endpoint, then submits the source-proven form
 * exactly once. Reusing a consumed permit is rejected. Failure cleans up only
 * its own session. Poll the original context to drive all callbacks. */
BC_DISCOVERY_API bc_status bc_web_session_start(bc_web_login_contract *, const bc_web_session_options *,
    bc_web_session_completion, void *, bc_web_session **);
BC_DISCOVERY_API const bc_web_session_result *bc_web_session_result_get(const bc_web_session *);
/* Borrowed successful owner; retain it only while the session remains open.
 * This is Web authentication, never console protocol/layout evidence. */
BC_DISCOVERY_API bc_endpoint *bc_web_session_endpoint(const bc_web_session *);
/* Pending handshake only: retains the original single completion. An in-flight
 * login is observed to its bounded completion before cleaning up its known own
 * session; no subsequent CSRF/startup request is made. Ready owners use close. */
BC_DISCOVERY_API bc_status bc_web_session_cancel(bc_web_session *);
BC_DISCOVERY_API bc_status bc_web_session_close(bc_web_session *, bc_web_session_completion, void *);
/* Second-stage read-only graph, seeded only by the source-proven landing of
 * this live Web owner. The caller keeps the session open until completion.
 * Follows advertised assets/navigation, never submits forms or executes JS.
 * Up to32 GETs, 64 queued candidates, depth16; other public byte/time limits
 * apply. HTML/scripts alternate and each kind rotates source owners, preventing
 * one page from monopolizing GETs. Published startup resources go first. No
 * path-name/brand inference, invented URI or authentication permission. */
BC_DISCOVERY_API bc_status bc_web_entry_start_owned(bc_web_session *, const bc_web_entry_options *,
    bc_web_entry_completion, void *, bc_web_entry_graph **);
/* Selects the requested descriptor service when a page publishes both KVM and media. */
BC_DISCOVERY_API bc_status bc_web_entry_start_owned_service(bc_web_session *, const bc_web_entry_options *,
    uint32_t service, bc_web_entry_completion, void *, bc_web_entry_graph **);
/* A completed, structurally parsed startup request on this same owner. This is
 * descriptor metadata; JViewer layout still needs independent JAR evidence. */
BC_DISCOVERY_API bc_request *bc_web_entry_launch_request_get(bc_web_entry_graph *,
    const bc_endpoint *, uint64_t generation);
/* RAM-only diagnostics over already-completed GETs in this graph. Exact
 * endpoint/generation and live expiry are required, including on failed graphs.
 * Responses may contain credentials/tickets: never log, reflect or persist.
 * No additional I/O, retention outside this graph, or protocol permission. */
#define BC_WEB_LIMIT_DEPTH 1u
#define BC_WEB_LIMIT_CANDIDATES 2u
#define BC_WEB_LIMIT_REQUESTS 3u
#define BC_WEB_LIMIT_RESPONSE_BYTES 4u
#define BC_WEB_LIMIT_TOTAL_BYTES 5u
#define BC_WEB_LIMIT_SCRIPT_PARSE 6u
#define BC_WEB_LIMIT_HTML_PARSE 7u
#define BC_WEB_LIMIT_TRANSPORT_BODY 8u
typedef struct {
    uint32_t struct_size, abi_version, reason, source_index;
    uint32_t candidates, requests, depth, max_depth;
    uint64_t observed, maximum, bytes, max_bytes;
} bc_web_entry_limit;
/* Pure numeric diagnostics, same live scope/expiry as resource getters. Caller
 * initializes struct_size/abi_version. source_index refers to the completed
 * resource enumeration, UINT32_MAX if unavailable. Parser reasons report input
 * bytes in observed, maximum=0 when the internal parser limit is unspecified.
 * SCRIPT_PARSE may coexist with overall BC_OK: that script was rolled back,
 * unsupported_scripts records incomplete analysis; only independent complete
 * evidence can produce a login/startup result. Graph resource limits still stop.
 * No permission or additional I/O; failure clears the output. */
BC_DISCOVERY_API bc_status bc_web_entry_limit_get(bc_web_entry_graph *,
    const bc_endpoint *, uint64_t generation, bc_web_entry_limit *);
BC_DISCOVERY_API uint32_t bc_web_entry_resource_count(bc_web_entry_graph *,
    const bc_endpoint *, uint64_t generation);
BC_DISCOVERY_API bc_request *bc_web_entry_resource_request_get(bc_web_entry_graph *,
    const bc_endpoint *, uint64_t generation, uint32_t index);
/* Prefer close + its completion before releasing the owner. Releasing during
 * work suppresses user callbacks and queues own cleanup; its context must keep
 * polling through that bounded cleanup before transport/context destruction. */
BC_DISCOVERY_API void bc_web_session_release(bc_web_session *);
#ifdef __cplusplus
}
#endif
#endif

#ifndef BC_CLIENT_INTERNAL_H
#define BC_CLIENT_INTERNAL_H
#include "bcontrol/console_client.h"
#include "bcontrol/transport.h"
#include "bcontrol/kvm_transport.h"
#include "bcontrol/redfish_auth.h"
#include "bcontrol/web_login.h"
#include "bcontrol/huawei_launch.h"
#include "bcontrol/jviewer_discovery.h"
#include "bcontrol/idrac_http.h"
#include "bcontrol/media_factory.h"
#include "bcontrol/console_idrac_launch.h"
#include "bcontrol/console_huawei_launch.h"
#include "bcontrol/megarac_launch.h"
#include "../../adapters/irmc/discovery.h"
#include "../../platform/monotonic.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../platform/mutex.h"
typedef bc_mutex client_mutex;
#define mutex_init bc_mutex_init
#define mutex_lock bc_mutex_lock
#define mutex_unlock bc_mutex_unlock
#define mutex_destroy bc_mutex_destroy
#define CLIENT_BYTES (32u * 1024u * 1024u)
#define CLIENT_MESSAGES 256u
typedef struct client_message {
    struct client_message *next;
    uint32_t channel, size;
    uint8_t data[];
} client_message;
struct bc_console_client {
    bc_console_client_options options;
    char *address, *username, *password, *ca_file, *proxy_host, *proxy_user, *proxy_password;
    bc_socks5_proxy proxy;
    bc_media_source source;
    client_mutex mutex;
    bc_console_client_info info, published;
    uint64_t deadline, heartbeat;
    int irmc, irmc_media_announced;
    uint32_t protocol, generation, channels, reads, keyboard_mode, keyboard_leds;
    char *host, *origin, *cookie, *urls[2], *media_url;
    uint32_t port, kind;
    bc_transport *http;
    bc_context *context;
    bc_endpoint *public_endpoint, *endpoint;
    bc_redfish_connection *redfish;
    bc_request *login;
    bc_web_session *web;
    bc_megarac_probe *probe;
    bc_console_launch *launch;
    bc_console_session *console;
    bc_console_bootstrap *bootstrap;
    bc_media_session *media;
    bc_media_offer *offer;
    bc_kvm_transport *links[2], *bootstrap_link;
    bc_aten_launch aten;
    bc_aten_identity *aten_identity;
    char aten_peer[BC_ATEN_PEER_PEM_CAPACITY];
    int aten_websocket;
    int lenovo_xcc3;
    char lenovo_remote[1025], lenovo_network[1025], lenovo_media[1025];
    bc_megarac_kvm_info mega;
    bc_megarac_media_parameters media_parameters;
    bc_huawei_kvm_params huawei;
    bc_huawei_kvm_resource resource;
    bc_huawei_download_action download;
    uint32_t format, modes;
    char action_info[1025], media_uri[1025];
    uint8_t *input, *diagnostic_startup, *diagnostic_archive;
    uint32_t diagnostic_startup_size, diagnostic_archive_size;
    client_message *output_head, *output_tail, *input_head, *input_tail;
    uint32_t output_bytes, output_count, input_count;
    uint32_t pending_controls;
    bc_status media_status;
    int offer_requested;
    bc_console_client *parent;
    uint32_t media_children;
    uint32_t pressed[256], pressed_count;
    bc_console_input pointer;
    int closing, closed;
};
static inline bc_string str(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
uint64_t client_clock(void *);
uint32_t client_remaining(bc_console_client *);
int client_cancelled(bc_console_client *);
bc_status client_http_open(bc_console_client *);
bc_status client_startup(bc_console_client *);
bc_status client_http_close(bc_console_client *);
bc_status client_redfish_get(bc_console_client *, const char *, bc_request **);
bc_status client_wait_request(bc_console_client *, bc_request *);
bc_status client_wait_redfish(bc_console_client *, bc_redfish_operation *);
bc_status client_parent_media_start(bc_console_client *);
bc_status client_parent_media_attached(bc_console_client *);
bc_status client_irmc_media_detach(bc_console_client *);
void client_parent_media_close(bc_console_client *);
bc_status client_irmc_media_tunnel(bc_console_client *);
bc_status client_media_readback(bc_console_client *, int);
bc_status client_network_open(bc_console_client *, const char *, const char *, bc_kvm_transport **);
bc_status client_drain(bc_console_client *);
bc_status client_pump(bc_console_client *, uint32_t, int);
bc_status client_emit(void *, const uint8_t *, uint32_t);
bc_status client_receive(void *, uint8_t *, uint32_t, uint32_t *, uint32_t);
bc_status client_submit(void *, bc_decode_job *);
void client_publish_protocol(bc_console_client *);
char *client_copy(bc_string, uint32_t);
bc_status client_url(bc_console_client *, const char *, uint32_t, const char *, char **);
bc_status client_cookie(bc_console_client *, bc_string);
bc_status client_supermicro_launch(bc_console_client *, int *matched);
bc_status client_supermicro_mode(bc_console_client *, uint32_t expected, uint32_t target, bc_console_mode_info *);
bc_status client_web_login(bc_console_client *, uint32_t *kind);
bc_status client_supermicro_html5_media_prepare(bc_console_client *);
bc_status client_aten_identity(bc_console_client *, const bc_aten_launch *);
bc_status client_aten_mouse_layout(bc_console_client *);
bc_status client_aten_media_offer(bc_console_client *);
bc_status client_lenovo_discover(bc_console_client *, bc_bytes, const char *);
bc_status client_lenovo_launch(bc_console_client *);
bc_status client_lenovo_probe_media(bc_console_client *);
#endif

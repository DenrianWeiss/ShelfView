#include "bcontrol/console_factory.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "bcontrol/media_offer_provider.h"
#include "bcontrol/megarac_launch.h"
#include "bcontrol/megarac_session.h"
#include "bcontrol/console_huawei_launch.h"
#include "bcontrol/huawei_session.h"
#include "bcontrol/kvm_session.h"
#include "bcontrol/ilo_session.h"
#include "bcontrol/idrac_session.h"
#include "bcontrol/console_idrac_launch.h"

struct bc_console_launch {
    uint32_t protocol, generation, token_length;
    char token[256];
    bc_megarac_kvm_info megarac;
    bc_huawei_kvm_params huawei;
    uint32_t kind, keyboard_mode;
    char client_ip[BC_MEGARAC_MAX_IP], username[BC_MEGARAC_MAX_TOKEN], client_mac[64];
};
bc_status bc_console_launch_from_token(uint32_t protocol, uint32_t generation,
    bc_string token, bc_console_launch **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (protocol != BC_CONSOLE_PROTOCOL_RFB && protocol != BC_CONSOLE_PROTOCOL_ILO && protocol != BC_CONSOLE_PROTOCOL_IDRAC)
        return BC_UNSUPPORTED;
    if (token.length > 256 || (token.length && !token.data)) return BC_INVALID_ARGUMENT;
    bc_console_launch *launch = calloc(1, sizeof(*launch));
    if (!launch) return BC_NO_MEMORY;
    launch->protocol = protocol; launch->generation = generation;
    launch->token_length = (uint32_t)token.length;
    if (token.length) memcpy(launch->token, token.data, (size_t)token.length);
    *out = launch;
    return BC_OK;
}
bc_status bc_console_launch_from_megarac(const bc_megarac_session_options *options, uint32_t keyboard_mode,
    bc_console_launch **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size != sizeof(*options) || !options->info ||
        options->info->struct_size != sizeof(*options->info) || !options->client_ip || !options->username ||
        keyboard_mode > BC_MEGARAC_KEYBOARD_AUTO_BREAK) return BC_INVALID_ARGUMENT;
    if (!BC_MEGARAC_IS_JVIEWER_373(options->kind) && !BC_MEGARAC_IS_JVIEWER_195(options->kind) &&
        options->kind != BC_MEGARAC_KVM_H5VIEWER && options->kind != BC_MEGARAC_KVM_H5VIEWER_373) return BC_UNSUPPORTED;
    bc_console_launch *launch = calloc(1, sizeof(*launch));
    if (!launch) return BC_NO_MEMORY;
    launch->protocol = BC_CONSOLE_PROTOCOL_MEGARAC; launch->kind = options->kind;
    launch->keyboard_mode = keyboard_mode; launch->megarac = *options->info;
    snprintf(launch->client_ip, sizeof(launch->client_ip), "%s", options->client_ip);
    snprintf(launch->username, sizeof(launch->username), "%s", options->username);
    if (options->client_mac) snprintf(launch->client_mac, sizeof(launch->client_mac), "%s", options->client_mac);
    *out = launch;
    return BC_OK;
}
bc_status bc_console_launch_from_huawei(const bc_huawei_kvm_params *params, bc_console_launch **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!params || params->struct_size != sizeof(*params) || params->abi_version != BC_ABI_VERSION) return BC_INVALID_ARGUMENT;
    bc_console_launch *launch = calloc(1, sizeof(*launch));
    if (!launch) return BC_NO_MEMORY;
    launch->protocol = BC_CONSOLE_PROTOCOL_HUAWEI; launch->huawei = *params;
    *out = launch;
    return BC_OK;
}
bc_status bc_console_launch_from_idrac(const bc_idrac_console_launch *descriptor, bc_console_launch **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!descriptor || descriptor->struct_size != sizeof(*descriptor)) return BC_INVALID_ARGUMENT;
    const char *end = memchr(descriptor->secondary_key, 0, sizeof(descriptor->secondary_key));
    if (!end || end == descriptor->secondary_key) return BC_INVALID_ARGUMENT;
    return bc_console_launch_from_token(BC_CONSOLE_PROTOCOL_IDRAC, 0,
        (bc_string){descriptor->secondary_key, (uint64_t)(end-descriptor->secondary_key)}, out);
}
void bc_console_launch_destroy(bc_console_launch *launch) {
    if (!launch) return;
    volatile unsigned char *bytes = (volatile unsigned char *)launch;
    for (size_t i = 0; i < sizeof(*launch); ++i) bytes[i] = 0;
    free(launch);
}

bc_status bc_console_session_create(const bc_console_options *options, bc_console_session **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!options || options->struct_size < sizeof(*options) || options->abi_version != BC_ABI_VERSION || !options->launch)
        return BC_INVALID_ARGUMENT;
    const bc_console_launch *launch = options->launch;
    bc_string token = {launch->token, launch->token_length};
    switch (launch->protocol) {
    case BC_CONSOLE_PROTOCOL_RFB:
        return bc_kvm_session_create(&options->display, options->emit, options->user, out);
    case BC_CONSOLE_PROTOCOL_ILO:
        return bc_ilo_session_create(launch->generation, token, options->display.max_width,
            options->display.max_height, options->emit, options->user, out);
    case BC_CONSOLE_PROTOCOL_IDRAC:
        return bc_idrac_session_create(&options->display, token, options->emit, options->leds, options->user, out);
    case BC_CONSOLE_PROTOCOL_MEGARAC: {
        bc_megarac_session_options configuration = {0};
        configuration.struct_size = sizeof(configuration); configuration.kind = launch->kind;
        configuration.info = &launch->megarac; configuration.client_ip = launch->client_ip;
        configuration.username = launch->username; configuration.client_mac = launch->client_mac;
        configuration.frame_capacity = 16u * 1024u * 1024u;
        return bc_megarac_console_create(&configuration, launch->keyboard_mode, options->submit, options->user, out);
    }
    case BC_CONSOLE_PROTOCOL_HUAWEI: {
        bc_huawei_io io = {options->transport_user, options->emit, options->receive};
        bc_huawei_kvm_options configuration = {0};
        configuration.struct_size = sizeof(configuration); configuration.abi_version = BC_ABI_VERSION;
        configuration.frame_capacity = 4096u * 4096u * 4u;
        configuration.handshake_timeout_ms = options->handshake_timeout_ms;
        configuration.heartbeat_interval_ms = options->heartbeat_interval_ms;
        configuration.clock = options->clock; configuration.clock_user = options->clock_user;
        return bc_huawei_console_create(&launch->huawei, &io, &configuration, options->submit, options->user, out);
    }
    default:
        return BC_UNSUPPORTED;
    }
}

bc_status bc_console_launch_idrac_auth(const bc_console_launch *launch, bc_idrac_console_auth **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!launch || launch->protocol != BC_CONSOLE_PROTOCOL_IDRAC) return BC_INVALID_ARGUMENT;
    return bc_idrac_console_auth_create((bc_string){launch->token, launch->token_length}, out);
}

struct bc_console_bootstrap { bc_idrac_console_auth *protocol; };
bc_status bc_console_bootstrap_create(const bc_console_launch *launch, bc_console_bootstrap **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!launch) return BC_INVALID_ARGUMENT;
    if (launch->protocol != BC_CONSOLE_PROTOCOL_IDRAC) return BC_UNSUPPORTED;
    bc_console_bootstrap *bootstrap = calloc(1, sizeof(*bootstrap));
    if (!bootstrap) return BC_NO_MEMORY;
    bc_status status = bc_console_launch_idrac_auth(launch, &bootstrap->protocol);
    if (status != BC_OK) { free(bootstrap); return status; }
    *out = bootstrap; return BC_OK;
}
bc_status bc_console_bootstrap_feed(bc_console_bootstrap *bootstrap, bc_bytes bytes) {
    if (!bootstrap || !bytes.data || !bytes.length || bytes.length > 65536) return BC_INVALID_ARGUMENT;
    return bc_idrac_console_auth_feed_message(bootstrap->protocol, bytes.data, (uint32_t)bytes.length);
}
bc_status bc_console_bootstrap_output(bc_console_bootstrap *bootstrap, uint8_t *bytes, uint32_t capacity, uint32_t *written) {
    if (!bootstrap) return BC_INVALID_ARGUMENT;
    return bc_idrac_console_auth_output(bootstrap->protocol, bytes, capacity, written);
}
bc_status bc_console_bootstrap_media_offer(const bc_console_bootstrap *bootstrap, bc_media_offer **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!bootstrap) return BC_INVALID_ARGUMENT;
    bc_string key = bc_idrac_console_auth_key_get(bootstrap->protocol);
    return key.length ? bc_media_offer_token_create(BC_MEDIA_OFFER_IDRAC, 0, key, out) : BC_BUSY;
}
bc_status bc_console_bootstrap_close(bc_console_bootstrap *bootstrap) {
    return bootstrap ? bc_idrac_console_auth_close_session(bootstrap->protocol) : BC_INVALID_ARGUMENT;
}
const bc_console_failure *bc_console_bootstrap_failure_get(const bc_console_bootstrap *bootstrap) {
    return bootstrap ? bc_idrac_console_auth_failure_get(bootstrap->protocol) : NULL;
}
void bc_console_bootstrap_destroy(bc_console_bootstrap *bootstrap) {
    if (!bootstrap) return;
    bc_idrac_console_auth_destroy(bootstrap->protocol); free(bootstrap);
}

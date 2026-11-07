#include "bcontrol/redfish.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define KEY(s) "manage.redfish." s

typedef struct { bc_redfish_network_row_callback emit; void *user; } rows;
static bc_string text(const char *s) { return (bc_string){s, s ? strlen(s) : 0}; }
static int equal(bc_string s, const char *v) { return s.length == strlen(v) && (!s.length || (s.data && !memcmp(s.data, v, (size_t)s.length))); }
static int key(const char *s) { return !strncmp(s, "manage.", 7) || !strncmp(s, "media.", 6); }
static void emit(rows *r, const char *label, bc_string value, const char *suffix, uint32_t flags) {
    bc_redfish_network_row row = {sizeof(row), flags | (key(label) ? BC_REDFISH_NETWORK_ROW_LABEL_KEY : 0), text(label), value, text(suffix)};
    r->emit(&row, r->user);
}
static bc_string token(bc_string value, uint32_t *flags) {
    static const struct { const char *value, *key; } values[] = {
        {"LinkUp", KEY("linkUp")}, {"LinkDown", KEY("linkDown")}, {"NoLink", KEY("linkDown")},
        {"Dedicated", KEY("dedicated")}, {"Shared", KEY("shared")},
        {"Static", KEY("staticAddress")}, {"LinkLocal", KEY("linkLocal")},
        {"Enabled", KEY("enabled")}, {"Disabled", KEY("disabled")}
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
        if (equal(value, values[i].value)) { *flags |= BC_REDFISH_NETWORK_ROW_VALUE_KEY; return text(values[i].key); }
    return value;
}
static void string_row(rows *r, const char *label, bc_string value, uint32_t present, uint32_t null, uint32_t bit, int translate) {
    if (!(present & bit)) return;
    uint32_t flags = 0;
    if (null & bit) { value = text("common.unknown"); flags = BC_REDFISH_NETWORK_ROW_VALUE_KEY | BC_REDFISH_NETWORK_ROW_NULL; }
    else if (translate) value = token(value, &flags);
    emit(r, label, value, NULL, flags);
}
static void boolean(rows *r, const char *label, uint32_t value, uint32_t present, uint32_t null, uint32_t bit, int required, const char *suffix) {
    if (!(present & bit) && !required) return;
    uint32_t flags = BC_REDFISH_NETWORK_ROW_VALUE_KEY;
    const char *v = value ? KEY("enabled") : KEY("disabled");
    if (!(present & bit)) { v = "common.unknown"; flags |= BC_REDFISH_NETWORK_ROW_MISSING; }
    else if (null & bit) { v = "common.unknown"; flags |= BC_REDFISH_NETWORK_ROW_NULL; }
    emit(r, label, text(v), suffix, flags);
}
static void number(rows *r, const char *label, uint32_t value, uint32_t present, uint32_t null, uint32_t bit, const char *suffix) {
    if (!(present & bit)) return;
    if (null & bit) { string_row(r, label, text(NULL), present, null, bit, 0); return; }
    char buffer[16]; snprintf(buffer, sizeof(buffer), "%" PRIu32, value);
    emit(r, label, text(buffer), suffix, 0);
}
static void servers(rows *r, const char *label, const bc_string *values, uint32_t count) {
    char buffer[BC_REDFISH_NETWORK_MAX_SERVERS * 258 + 1]; size_t used = 0;
    for (uint32_t i = 0; i < count && i < BC_REDFISH_NETWORK_MAX_SERVERS; ++i) {
        bc_string value = values[i];
        if (!value.data || !value.length || equal(value, "0.0.0.0") || equal(value, "::")) continue;
        if (value.length > sizeof(buffer) - used - 3) continue;
        if (used) { buffer[used++] = ','; buffer[used++] = ' '; }
        memcpy(buffer + used, value.data, (size_t)value.length); used += (size_t)value.length;
    }
    if (used) emit(r, label, (bc_string){buffer, used}, NULL, 0);
}
static void protocols(rows *r, const bc_redfish_network_protocol_info *n) {
    string_row(r, KEY("hostname"), n->host_name, n->host_name.data ? 1 : n->null_flags & 1, n->null_flags, 1, 0);
    string_row(r, KEY("fqdn"), n->fqdn, n->fqdn.data ? 2 : n->null_flags & 2, n->null_flags, 2, 0);
    servers(r, KEY("ntp"), n->ntp_servers, n->ntp_server_count);
    servers(r, KEY("dhcpNtp"), n->ntp_network_supplied, n->ntp_network_supplied_count);
    static const char *const names[] = {"NTP", "SSH", "SNMP", "HTTP", "HTTPS", "IPMI", "media.title", "KVM", "SSDP", "Telnet"};
    for (uint32_t i = 0; i < BC_REDFISH_NETWORK_PROTOCOL_COUNT; ++i) {
        const bc_redfish_network_protocol_entry *e = &n->protocols[i];
        if (!(e->flags & BC_REDFISH_NET_PROTOCOL_PRESENT)) continue;
        char suffix[20] = "";
        if ((e->flags & BC_REDFISH_NET_PROTOCOL_PORT) && !(e->null_flags & BC_REDFISH_NET_PROTOCOL_PORT_NULL))
            snprintf(suffix, sizeof(suffix), " :%" PRIu32, e->port);
        const char *label = e->flags & BC_REDFISH_NET_PROTOCOL_SNMPV3 ? "SNMPv3" : names[i];
        boolean(r, label, e->enabled, e->flags, (e->null_flags & BC_REDFISH_NET_PROTOCOL_ENABLED_NULL) ? BC_REDFISH_NET_PROTOCOL_ENABLED : 0,
            BC_REDFISH_NET_PROTOCOL_ENABLED, 1, suffix);
    }
}
static void ethernet(rows *r, const bc_redfish_result *result, const bc_redfish_ethernet_info *e) {
    bc_string title = result->name.length ? result->name : result->id;
    uint32_t flags = BC_REDFISH_NETWORK_ROW_HEADING;
    if (equal(title, "Manager Ethernet Interface")) { title = text(KEY("managementInterface")); flags |= BC_REDFISH_NETWORK_ROW_VALUE_KEY; }
    else if (equal(title, "Manager Ethernet Over USB Interface")) { title = text(KEY("hostInterface")); flags |= BC_REDFISH_NETWORK_ROW_VALUE_KEY; }
    emit(r, "", title, NULL, flags);
#define STR(label, member, bit, translate) string_row(r, label, e->member, e->flags, e->null_flags, bit, translate)
#define BOOL(label, member, bit) boolean(r, label, e->member, e->flags, e->null_flags, bit, 0, NULL)
#define NUM(label, member, bit, suffix) number(r, label, e->member, e->flags, e->null_flags, bit, suffix)
    BOOL(KEY("interfaceEnabled"), interface_enabled, BC_REDFISH_ETH_INTERFACE_ENABLED);
    STR(KEY("nicMode"), interface_mode, BC_REDFISH_ETH_MODE, 1);
    STR(KEY("mac"), mac, BC_REDFISH_ETH_MAC, 0);
    STR(KEY("hostname"), host_name, BC_REDFISH_ETH_HOST_NAME, 0);
    STR(KEY("fqdn"), fqdn, BC_REDFISH_ETH_FQDN, 0);
    if ((e->flags & BC_REDFISH_ETH_LINK_STATUS) && !(e->null_flags & BC_REDFISH_ETH_LINK_STATUS)) {
        STR(KEY("link"), link_status, BC_REDFISH_ETH_LINK_STATUS, 1);
    } else if (e->flags & BC_REDFISH_ETH_STATUS_STATE) {
        STR(KEY("link"), state, BC_REDFISH_ETH_STATUS_STATE, 1);
    } else { STR(KEY("link"), link_status, BC_REDFISH_ETH_LINK_STATUS, 1); }
    NUM(KEY("speed"), speed_mbps, BC_REDFISH_ETH_SPEED, " Mbps");
    NUM("MTU", mtu, BC_REDFISH_ETH_MTU, NULL);
    BOOL("DHCPv4", dhcp4_enabled, BC_REDFISH_ETH_DHCP4_ENABLED);
    if (e->flags & BC_REDFISH_ETH_DHCP6_MODE) { STR("DHCPv6", dhcp6_mode, BC_REDFISH_ETH_DHCP6_MODE, 1); }
    else { BOOL("DHCPv6", dhcp6_enabled, BC_REDFISH_ETH_DHCP6_ENABLED); }
    BOOL("VLAN", vlan_enabled, BC_REDFISH_ETH_VLAN_ENABLED);
    if ((e->flags & BC_REDFISH_ETH_VLAN_ENABLED) && !(e->null_flags & BC_REDFISH_ETH_VLAN_ENABLED) && e->vlan_enabled) {
        NUM("VLAN ID", vlan_id, BC_REDFISH_ETH_VLAN_ID, NULL);
    }
    for (uint32_t i = 0; i < e->ipv4_count; ++i) {
        const bc_redfish_ipv4_entry *ip = &e->ipv4[i];
        string_row(r, "IPv4", ip->address, ip->flags, ip->null_flags, 1, 0);
        string_row(r, KEY("subnetMask"), ip->subnet_mask, ip->flags, ip->null_flags, 2, 0);
        string_row(r, KEY("gateway"), ip->gateway, ip->flags, ip->null_flags, 4, 0);
        string_row(r, KEY("addressOrigin"), ip->address_origin, ip->flags, ip->null_flags, 8, 1);
    }
    for (uint32_t i = 0; i < e->ipv6_count; ++i) {
        const bc_redfish_ipv6_entry *ip = &e->ipv6[i];
        char address[1100]; bc_string value = ip->address;
        if ((ip->flags & 3) == 3 && !(ip->null_flags & 3) && value.length < 1024) {
            int length = snprintf(address, sizeof(address), "%.*s/%" PRIu32, (int)value.length, value.data ? value.data : "", ip->prefix_length);
            if (length >= 0 && (size_t)length < sizeof(address)) value = (bc_string){address, (uint64_t)length};
        }
        string_row(r, "IPv6", value, ip->flags, ip->null_flags, 1, 0);
        string_row(r, KEY("addressOrigin"), ip->address_origin, ip->flags, ip->null_flags, 4, 1);
    }
    if (!equal(e->ipv6_gateway, "::")) { STR(KEY("ipv6Gateway"), ipv6_gateway, BC_REDFISH_ETH_IPV6_GATEWAY, 0); }
    servers(r, "DNS", e->name_servers, e->name_server_count);
#undef STR
#undef BOOL
#undef NUM
}
bc_status bc_redfish_network_rows(const bc_redfish_operation *op, bc_redfish_network_row_callback callback, void *user) {
    if (!op || !callback) return BC_INVALID_ARGUMENT;
    rows r = {callback, user};
    const bc_redfish_network_protocol_info *network = bc_redfish_network_protocol_info_get(op);
    const bc_redfish_ethernet_info *interface = bc_redfish_ethernet_info_get(op);
    if (network) protocols(&r, network);
    else if (interface) ethernet(&r, bc_redfish_result_get(op), interface);
    else return BC_UNSUPPORTED;
    return BC_OK;
}

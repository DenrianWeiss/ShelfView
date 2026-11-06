#ifndef BCONTROL_IPMI_LAN_H
#define BCONTROL_IPMI_LAN_H
#include "ipmi_session.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Read-only LAN configuration per IPMI 2.0 chapter 23. Get LAN Configuration
 * Parameters is NetFn Transport (0x0C) command 0x02; Set (0x01) is never
 * issued by this API. Selector numbering follows Table 23-4 as implemented by
 * ipmitool and FreeIPMI (IP Address is 3, IP Address Source is 4, VLAN ID is
 * 20, RMCP+ cipher parameters are 22-24). Request is channel, selector,
 * set selector, block selector; a successful response carries a parameter
 * revision byte (low nibble) followed by the parameter data. */
#define BC_IPMI_NETFN_TRANSPORT 0x0Cu
#define BC_IPMI_CMD_SET_LAN_CONFIG 0x01u
#define BC_IPMI_CMD_GET_LAN_CONFIG 0x02u
#define BC_IPMI_CMD_GET_CHANNEL_INFO 0x42u

#define BC_IPMI_LAN_PARAM_SET_IN_PROGRESS 0u
#define BC_IPMI_LAN_PARAM_AUTH_TYPE_SUPPORT 1u
#define BC_IPMI_LAN_PARAM_AUTH_TYPE_ENABLES 2u
#define BC_IPMI_LAN_PARAM_IP_ADDRESS 3u
#define BC_IPMI_LAN_PARAM_IP_ADDRESS_SOURCE 4u
#define BC_IPMI_LAN_PARAM_MAC_ADDRESS 5u
#define BC_IPMI_LAN_PARAM_SUBNET_MASK 6u
#define BC_IPMI_LAN_PARAM_IPV4_HEADER 7u
#define BC_IPMI_LAN_PARAM_PRIMARY_RMCP_PORT 8u
#define BC_IPMI_LAN_PARAM_SECONDARY_RMCP_PORT 9u
#define BC_IPMI_LAN_PARAM_BMC_ARP_CONTROL 10u
#define BC_IPMI_LAN_PARAM_GRATUITOUS_ARP_INTERVAL 11u
#define BC_IPMI_LAN_PARAM_DEFAULT_GATEWAY 12u
#define BC_IPMI_LAN_PARAM_DEFAULT_GATEWAY_MAC 13u
#define BC_IPMI_LAN_PARAM_BACKUP_GATEWAY 14u
#define BC_IPMI_LAN_PARAM_BACKUP_GATEWAY_MAC 15u
#define BC_IPMI_LAN_PARAM_COMMUNITY_STRING 16u
#define BC_IPMI_LAN_PARAM_NUMBER_OF_DESTINATIONS 17u
#define BC_IPMI_LAN_PARAM_DESTINATION_TYPE 18u
#define BC_IPMI_LAN_PARAM_DESTINATION_ADDRESSES 19u
#define BC_IPMI_LAN_PARAM_VLAN_ID 20u
#define BC_IPMI_LAN_PARAM_VLAN_PRIORITY 21u
#define BC_IPMI_LAN_PARAM_CIPHER_SUITE_SUPPORT 22u
#define BC_IPMI_LAN_PARAM_CIPHER_SUITE_ENTRIES 23u
#define BC_IPMI_LAN_PARAM_CIPHER_SUITE_PRIVILEGES 24u
#define BC_IPMI_LAN_PARAM_DESTINATION_VLAN_TAGS 25u
#define BC_IPMI_LAN_PARAM_BAD_PASSWORD_THRESHOLD 26u
#define BC_IPMI_LAN_PARAM_LAST_STANDARD 26u
#define BC_IPMI_LAN_PARAM_OEM_FIRST 192u
#define BC_IPMI_LAN_MAX_CHANNELS 14u
#define BC_IPMI_LAN_MAX_PARAMETER_DATA 32u
#define BC_IPMI_LAN_MAX_CIPHER_SUITES 32u
#define BC_IPMI_LAN_MEDIUM_LAN 0x04u
#define BC_IPMI_LAN_MEDIUM_OTHER_LAN 0x05u
#define BC_IPMI_LAN_PARAM_PRESENT 1u

#define BC_IPMI_LAN_IP_SOURCE_UNKNOWN 0u
#define BC_IPMI_LAN_IP_SOURCE_STATIC 1u
#define BC_IPMI_LAN_IP_SOURCE_DHCP 2u
#define BC_IPMI_LAN_IP_SOURCE_BIOS 3u
#define BC_IPMI_LAN_IP_SOURCE_OTHER 4u

/* Selector 16 (SNMP community string) is intentionally not read: it is a
 * shared secret and dumping it through a diagnostics API would expose it. */
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    bc_status status;
    uint8_t selector;
    uint8_t block_selector;
    uint8_t completion_code;
    uint8_t revision;
    uint8_t flags;
    uint8_t reserved[3];
    uint32_t data_length;
    uint8_t data[BC_IPMI_LAN_MAX_PARAMETER_DATA];
} bc_ipmi_lan_parameter;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint8_t channel;
    uint8_t medium_type;
    uint8_t is_lan;
    uint8_t flags;
    bc_status status;
    uint8_t completion_code;
    uint8_t reserved[3];
    uint32_t supported_count;
    uint32_t unsupported_count;
    bc_ipmi_lan_parameter parameters[BC_IPMI_LAN_PARAM_LAST_STANDARD + 1];
} bc_ipmi_lan_channel;

#define BC_IPMI_LAN_CHANNEL_PRESENT 1u

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint8_t channel_count;
    uint8_t lan_channel_count;
    uint8_t reserved[2];
    bc_ipmi_lan_channel channels[BC_IPMI_LAN_MAX_CHANNELS];
} bc_ipmi_lan_config;

/* Reads one channel: channel info first, then every standard parameter (0-26,
 * skipping the community string) with block chaining for cipher suite entries
 * when the advertised count exceeds the first block. Each parameter records
 * its own status; 0x80 maps to BC_UNSUPPORTED, 0xD4 to
 * BC_AUTHENTICATION_FAILED, 0xCC to BC_INVALID_ARGUMENT, and transport
 * timeouts stay BC_TIMEOUT, so permission, missing-channel and timeout cases
 * remain distinguishable. Short parameter data is kept as returned. */
BC_IPMI_API bc_status bc_ipmi_lan_channel_get(bc_ipmi_session *, uint8_t channel, bc_ipmi_lan_channel *);
/* Enumerates channels 1..0x0E via Get Channel Info; non-LAN and missing
 * channels are recorded with their own status and skipped for parameters. */
BC_IPMI_API bc_status bc_ipmi_lan_config_scan(bc_ipmi_session *, bc_ipmi_lan_config *);
BC_IPMI_API const char *bc_ipmi_lan_ip_source_name(uint8_t);
BC_IPMI_API const char *bc_ipmi_lan_set_in_progress_name(uint8_t);
/* Formats 4-byte IPv4 parameters (IP address, subnet mask, gateways). */
BC_IPMI_API bc_status bc_ipmi_lan_ipv4_format(const bc_ipmi_lan_parameter *, char *out, uint32_t capacity);
BC_IPMI_API bc_status bc_ipmi_lan_mac_format(const bc_ipmi_lan_parameter *, char *out, uint32_t capacity);
/* VLAN ID parameter: bit 15 of the second byte enables tagging, the tag is
 * the low 12 bits of the word. Returns BC_UNSUPPORTED when the parameter was
 * not read OK. */
BC_IPMI_API bc_status bc_ipmi_lan_vlan_parse(const bc_ipmi_lan_parameter *, uint32_t *vlan_id, uint32_t *enabled);
/* Cipher suite entries parameter holds one block per read: its first data
 * byte is the number of IDs in that block. Blocks are chained while the
 * advertised count (selector 22) is not satisfied, and this helper returns the
 * concatenated standard IDs (OEM records skipped) from the stored entry. */
BC_IPMI_API uint32_t bc_ipmi_lan_cipher_suites(const bc_ipmi_lan_channel *, uint8_t *out, uint32_t capacity);
#ifdef __cplusplus
}
#endif
#endif

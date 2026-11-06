#ifndef BCONTROL_IPMI_H
#define BCONTROL_IPMI_H
#include "bcontrol.h"
#if defined(_WIN32)
# ifdef BC_IPMI_BUILD
#  define BC_IPMI_API __declspec(dllexport)
# else
#  define BC_IPMI_API __declspec(dllimport)
# endif
#else
# define BC_IPMI_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define BC_IPMI_RMCP_HEADER_SIZE 4u
#define BC_IPMI_SESSION_HEADER_SIZE 12u
#define BC_IPMI_RMCP_VERSION 0x06u
#define BC_IPMI_RMCP_CLASS_IPMI 0x07u
#define BC_IPMI_RMCP_SEQUENCE_NO_ACK 0xFFu

#define BC_IPMI_AUTH_TYPE_NONE 0x00u
#define BC_IPMI_AUTH_TYPE_RMCP_PLUS 0x06u
#define BC_IPMI_PAYLOAD_IPMI 0x00u
#define BC_IPMI_PAYLOAD_SOL 0x01u
#define BC_IPMI_PAYLOAD_OEM 0x02u
#define BC_IPMI_PAYLOAD_OPEN_SESSION_REQUEST 0x10u
#define BC_IPMI_PAYLOAD_OPEN_SESSION_RESPONSE 0x11u
#define BC_IPMI_PAYLOAD_RAKP_1 0x12u
#define BC_IPMI_PAYLOAD_RAKP_2 0x13u
#define BC_IPMI_PAYLOAD_RAKP_3 0x14u
#define BC_IPMI_PAYLOAD_RAKP_4 0x15u
#define BC_IPMI_PAYLOAD_FLAG_ENCRYPTED 0x80u
#define BC_IPMI_PAYLOAD_FLAG_AUTHENTICATED 0x40u
#define BC_IPMI_PAYLOAD_TYPE_MASK 0x3Fu

#define BC_IPMI_AUTH_ALG_NONE 0u
#define BC_IPMI_AUTH_ALG_HMAC_SHA1 1u
#define BC_IPMI_AUTH_ALG_HMAC_MD5 2u
#define BC_IPMI_AUTH_ALG_HMAC_SHA256 3u
#define BC_IPMI_INTEGRITY_ALG_NONE 0u
#define BC_IPMI_INTEGRITY_ALG_HMAC_SHA1_96 1u
#define BC_IPMI_INTEGRITY_ALG_HMAC_MD5_128 2u
#define BC_IPMI_INTEGRITY_ALG_MD5_128 3u
#define BC_IPMI_INTEGRITY_ALG_HMAC_SHA256_128 4u
#define BC_IPMI_CONFIDENTIALITY_ALG_NONE 0u
#define BC_IPMI_CONFIDENTIALITY_ALG_AES_CBC_128 1u
#define BC_IPMI_CONFIDENTIALITY_ALG_XRC4_128 2u
#define BC_IPMI_CONFIDENTIALITY_ALG_XRC4_40 3u

#define BC_IPMI_ADDRESS_BMC 0x20u
#define BC_IPMI_ADDRESS_REMOTE_CONSOLE 0x81u
#define BC_IPMI_NETFN_CHASSIS 0x00u
#define BC_IPMI_NETFN_SENSOR 0x04u
#define BC_IPMI_NETFN_STORAGE 0x0Au
#define BC_IPMI_NETFN_GROUP 0x2Eu
#define BC_IPMI_NETFN_APP 0x06u
#define BC_IPMI_CMD_GET_DEVICE_ID 0x01u
#define BC_IPMI_CMD_CHASSIS_CONTROL 0x02u
#define BC_IPMI_CMD_SET_SESSION_PRIVILEGE 0x3Bu
#define BC_IPMI_CMD_CLOSE_SESSION 0x3Cu
#define BC_IPMI_CMD_GET_CHASSIS_CAPABILITIES 0x00u
#define BC_IPMI_CMD_GET_CHASSIS_STATUS 0x01u
#define BC_IPMI_CMD_CHASSIS_CONTROL 0x02u
#define BC_IPMI_CMD_GET_SYSTEM_RESTART_CAUSE 0x07u
#define BC_IPMI_CMD_GET_SENSOR_READING 0x2Du
#define BC_IPMI_CMD_GET_SDR_REPOSITORY_INFO 0x20u
#define BC_IPMI_CMD_RESERVE_SDR_REPOSITORY 0x22u
#define BC_IPMI_CMD_GET_SDR 0x23u
#define BC_IPMI_CMD_GET_SEL_INFO 0x40u
#define BC_IPMI_CMD_RESERVE_SEL 0x42u
#define BC_IPMI_CMD_GET_SEL_ENTRY 0x43u
#define BC_IPMI_CMD_GET_FRU_INVENTORY_AREA_INFO 0x10u
#define BC_IPMI_CMD_READ_FRU_DATA 0x11u
#define BC_IPMI_CMD_GET_CHANNEL_CIPHER_SUITES 0x54u
#define BC_IPMI_COMPLETION_OK 0x00u
#define BC_IPMI_CIPHER_LIST_ALL 0x80u
#define BC_IPMI_MAX_CIPHER_SUITES 32u
#define BC_IPMI_CIPHER_SUITE_OEM 1u

#define BC_IPMI_SUITE3_DISALLOWED 0u
#define BC_IPMI_SUITE3_ALLOWED 1u
#define BC_IPMI_SUITE3_CONFIRMED 2u
#define BC_IPMI_SUITE_CONFIRMATION_REQUIRED 1u

#define BC_IPMI_PRIVILEGE_CALLBACK 1u
#define BC_IPMI_PRIVILEGE_USER 2u
#define BC_IPMI_PRIVILEGE_OPERATOR 3u
#define BC_IPMI_PRIVILEGE_ADMINISTRATOR 4u
#define BC_IPMI_PRIVILEGE_OEM 5u
#define BC_IPMI_MAX_USER_NAME 16u
#define BC_IPMI_RANDOM_SIZE 16u
#define BC_IPMI_GUID_SIZE 16u
#define BC_IPMI_OPEN_SESSION_REQUEST_SIZE 32u
#define BC_IPMI_OPEN_SESSION_RESPONSE_SIZE 36u
#define BC_IPMI_RAKP1_FIXED_SIZE 28u
#define BC_IPMI_RAKP2_FIXED_SIZE 40u
#define BC_IPMI_RAKP3_FIXED_SIZE 8u
#define BC_IPMI_RAKP4_FIXED_SIZE 8u

typedef struct {
    uint8_t target_address;
    uint8_t source_address;
    uint8_t netfn;
    uint8_t lun;
    uint8_t sequence;
    uint8_t command;
    bc_bytes data;
} bc_ipmi_request;

typedef struct {
    uint8_t target_address;
    uint8_t source_address;
    uint8_t netfn;
    uint8_t lun;
    uint8_t sequence;
    uint8_t command;
    uint8_t completion_code;
    bc_bytes data;
} bc_ipmi_response;

typedef struct {
    uint8_t auth_type;
    uint8_t payload_type;
    uint8_t flags;
    uint32_t session_id;
    uint32_t sequence;
    uint16_t payload_length;
    bc_bytes payload;
} bc_ipmi_packet;

typedef struct {
    uint32_t cipher_suite_id;
    uint8_t auth_algorithm;
    uint8_t integrity_algorithm;
    uint8_t confidentiality_algorithm;
} bc_ipmi_cipher_suite_definition;

typedef struct {
    uint32_t cipher_suite_id;
    uint32_t iana;
    uint8_t auth_algorithm;
    uint8_t integrity_algorithm;
    uint8_t confidentiality_algorithm;
    uint8_t flags;
} bc_ipmi_cipher_suite;

typedef struct {
    uint8_t channel;
    uint32_t count;
    bc_ipmi_cipher_suite suites[BC_IPMI_MAX_CIPHER_SUITES];
} bc_ipmi_cipher_suites;

typedef struct {
    uint32_t cipher_suite_id;
    uint8_t auth_algorithm;
    uint8_t integrity_algorithm;
    uint8_t confidentiality_algorithm;
    uint32_t flags;
} bc_ipmi_suite_selection;

typedef struct {
    uint8_t message_tag;
    uint8_t maximum_privilege;
    uint32_t console_session_id;
    uint8_t auth_algorithm;
    uint8_t integrity_algorithm;
    uint8_t confidentiality_algorithm;
} bc_ipmi_open_session_request;

typedef struct {
    uint8_t message_tag;
    uint8_t status;
    uint8_t maximum_privilege;
    uint32_t console_session_id;
    uint32_t bmc_session_id;
    uint8_t auth_algorithm;
    uint8_t integrity_algorithm;
    uint8_t confidentiality_algorithm;
} bc_ipmi_open_session_response;

typedef struct {
    uint8_t message_tag;
    uint32_t bmc_session_id;
    uint8_t requested_privilege;
    const uint8_t *console_random;
    bc_string user_name;
} bc_ipmi_rakp1;

typedef struct {
    uint8_t message_tag;
    uint8_t status;
    uint32_t console_session_id;
    bc_bytes bmc_random;
    bc_bytes bmc_guid;
    bc_bytes auth_code;
} bc_ipmi_rakp2;

typedef struct {
    uint8_t message_tag;
    uint8_t status;
    uint32_t bmc_session_id;
    uint8_t auth_algorithm;
    bc_bytes auth_code;
} bc_ipmi_rakp3;

typedef struct {
    uint8_t message_tag;
    uint8_t status;
    uint32_t console_session_id;
    bc_bytes integrity_check_value;
} bc_ipmi_rakp4;

BC_IPMI_API uint32_t bc_ipmi_auth_code_size(uint8_t);
BC_IPMI_API uint32_t bc_ipmi_integrity_code_size(uint8_t);
BC_IPMI_API bc_status bc_ipmi_open_session_request_encode(const bc_ipmi_open_session_request *, uint8_t *out, uint64_t capacity);
BC_IPMI_API bc_status bc_ipmi_open_session_response_decode(const uint8_t *, uint64_t size, bc_ipmi_open_session_response *);
BC_IPMI_API bc_status bc_ipmi_rakp1_encode(const bc_ipmi_rakp1 *, uint8_t *out, uint64_t capacity, uint64_t *written);
BC_IPMI_API bc_status bc_ipmi_rakp2_decode(const uint8_t *, uint64_t size, uint8_t auth_algorithm, bc_ipmi_rakp2 *);
BC_IPMI_API bc_status bc_ipmi_rakp3_encode(const bc_ipmi_rakp3 *, uint8_t *out, uint64_t capacity, uint64_t *written);
BC_IPMI_API bc_status bc_ipmi_rakp4_decode(const uint8_t *, uint64_t size, uint8_t integrity_algorithm, bc_ipmi_rakp4 *);

BC_IPMI_API bc_status bc_ipmi_message_encode(const bc_ipmi_request *, uint8_t *out, uint64_t capacity, uint64_t *written);
BC_IPMI_API bc_status bc_ipmi_message_decode(const uint8_t *, uint64_t size, bc_ipmi_response *);
BC_IPMI_API bc_status bc_ipmi_packet_encode(const bc_ipmi_packet *, uint8_t *out, uint64_t capacity, uint32_t *written);
BC_IPMI_API bc_status bc_ipmi_packet_decode(const uint8_t *, uint64_t size, bc_ipmi_packet *);
BC_IPMI_API bc_status bc_ipmi_sessionless_encode(const bc_ipmi_request *, uint8_t *out, uint64_t capacity, uint32_t *written);
BC_IPMI_API bc_status bc_ipmi_sessionless_decode(const uint8_t *, uint64_t size, bc_ipmi_response *);
BC_IPMI_API bc_status bc_ipmi_cipher_suites_request(uint8_t channel, uint8_t list_index, uint8_t sequence, uint8_t *out, uint64_t capacity, uint32_t *written);
BC_IPMI_API bc_status bc_ipmi_cipher_suites_parse(const bc_ipmi_response *, bc_ipmi_cipher_suites *);
BC_IPMI_API const bc_ipmi_cipher_suite_definition *bc_ipmi_standard_cipher_suite(uint32_t);
BC_IPMI_API bc_status bc_ipmi_select_cipher_suite(const bc_ipmi_cipher_suites *, uint32_t suite3_policy, bc_ipmi_suite_selection *);
#ifdef __cplusplus
}
#endif
#endif

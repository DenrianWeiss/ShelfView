#ifndef BCONTROL_IPMI_SESSION_H
#define BCONTROL_IPMI_SESSION_H
#include "ipmi.h"
#include "boot.h"
#ifdef __cplusplus
extern "C" {
#endif

#define BC_IPMI_DEFAULT_TIMEOUT_MS 3000u
#define BC_IPMI_DEFAULT_RETRIES 3u
#define BC_IPMI_DEFAULT_CHANNEL 0x0Eu
#define BC_IPMI_MAX_PASSWORD 20u

/* Platform crypto for RAKP, integrity and confidentiality. Inputs and outputs
 * are byte buffers; no OpenSSL type crosses this interface. */
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    void *userdata;
    bc_status (*hmac)(void *, uint8_t auth_algorithm, const uint8_t *key, uint32_t key_length,
        const uint8_t *data, uint32_t data_length, uint8_t *out, uint32_t *out_length);
    bc_status (*encrypt)(void *, uint8_t confidentiality_algorithm, const uint8_t *key, uint32_t key_length,
        const uint8_t *iv, const uint8_t *input, uint32_t input_length, uint8_t *output);
    bc_status (*decrypt)(void *, uint8_t confidentiality_algorithm, const uint8_t *key, uint32_t key_length,
        const uint8_t *iv, const uint8_t *input, uint32_t input_length, uint8_t *output);
    bc_status (*random)(void *, uint8_t *out, uint32_t length);
} bc_ipmi_crypto;

/* Datagram transport. receive returns BC_TIMEOUT when nothing arrives in time;
 * the session never retransmits non-idempotent commands. */
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    void *userdata;
    bc_status (*send)(void *, const uint8_t *data, uint32_t length);
    bc_status (*receive)(void *, uint8_t *buffer, uint32_t capacity, uint32_t *length, uint32_t timeout_ms);
} bc_ipmi_io;

#define BC_IPMI_CHASSIS_CONTROL_OFF 0u
#define BC_IPMI_CHASSIS_CONTROL_ON 1u
#define BC_IPMI_CHASSIS_CONTROL_CYCLE 2u
#define BC_IPMI_CHASSIS_CONTROL_HARD_RESET 3u
#define BC_IPMI_CHASSIS_CONTROL_DIAGNOSTIC_INTERRUPT 4u
#define BC_IPMI_CHASSIS_CONTROL_SOFT_SHUTDOWN 5u
#define BC_IPMI_CHASSIS_ACPI_PRESENT 1u
#define BC_IPMI_CHASSIS_INTRUSION_ACTIVE 2u
#define BC_IPMI_CHASSIS_FRONT_PANEL_LOCKOUT 4u
#define BC_IPMI_CHASSIS_DRIVE_FAULT 8u
#define BC_IPMI_CHASSIS_FAN_FAULT 16u
#define BC_IPMI_CHASSIS_IDENTIFY_SUPPORTED 32u
#define BC_IPMI_CHASSIS_IDENTIFY_ON 64u
#define BC_IPMI_CHASSIS_IDENTIFY_TEMPORARY 128u
#define BC_IPMI_CHASSIS_IDENTIFY_STATE_UNKNOWN 256u

#define BC_IPMI_POWER_RESTORE_ALWAYS_OFF 0u
#define BC_IPMI_POWER_RESTORE_PREVIOUS 1u
#define BC_IPMI_POWER_RESTORE_ALWAYS_ON 2u
#define BC_IPMI_POWER_RESTORE_UNKNOWN 3u

typedef struct {
    uint32_t struct_size;
    uint32_t power_state;
    uint32_t flags;
    uint8_t raw_power_state;
    uint8_t last_power_event;
    uint8_t misc_state;
    uint8_t acpi_power_state;
    uint32_t power_restore_policy;
} bc_ipmi_chassis_status;

#define BC_IPMI_CHASSIS_CAP_INTRUSION_SENSOR 1u
#define BC_IPMI_CHASSIS_CAP_FRONT_PANEL_LOCKOUT 2u
#define BC_IPMI_CHASSIS_CAP_DIAGNOSTIC_INTERRUPT 4u
#define BC_IPMI_CHASSIS_CAP_POWER_INTERLOCK 8u

typedef struct {
    uint32_t struct_size, abi_version;
    uint32_t flags;
    uint8_t fru_device_address;
    uint8_t sdr_device_address;
    uint8_t sel_device_address;
    uint8_t sm_device_address;
    uint8_t bridge_device_address;
    uint8_t bridge_present;
    uint8_t reserved[2];
} bc_ipmi_chassis_capabilities;

#define BC_IPMI_RESTART_UNKNOWN 0u
#define BC_IPMI_RESTART_CHASSIS_POWER_COMMAND 1u
#define BC_IPMI_RESTART_PUSHBUTTON_RESET 2u
#define BC_IPMI_RESTART_PUSHBUTTON_POWER_UP 3u
#define BC_IPMI_RESTART_WATCHDOG 4u
#define BC_IPMI_RESTART_OEM 5u
#define BC_IPMI_RESTART_ALWAYS_RESTORE_POLICY 6u
#define BC_IPMI_RESTART_PREVIOUS_RESTORE_POLICY 7u
#define BC_IPMI_RESTART_PEF_RESET 8u
#define BC_IPMI_RESTART_PEF_POWER_CYCLE 9u
#define BC_IPMI_RESTART_SOFT_RESET 10u
#define BC_IPMI_RESTART_RTC_WAKEUP 11u

typedef struct {
    uint32_t struct_size, abi_version;
    uint32_t cause;
    uint8_t channel;
    uint8_t reserved[3];
} bc_ipmi_restart_cause;

#define BC_IPMI_SESSION_LEGACY_1_5 1u
#define BC_IPMI_CAPABILITY_CHASSIS_STATUS 1u
#define BC_IPMI_CAPABILITY_SDR 2u
#define BC_IPMI_CAPABILITY_SEL 4u
#define BC_IPMI_CAPABILITY_FRU 8u
#define BC_IPMI_CAPABILITY_NO_GRAPHICAL_CONSOLE 16u
#define BC_IPMI_CAPABILITY_ILOM_SERIAL_CANDIDATE 32u

typedef struct {
    uint32_t cipher_suite_id;
    uint8_t auth_algorithm;
    uint8_t integrity_algorithm;
    uint8_t confidentiality_algorithm;
    uint32_t bmc_session_id;
    uint32_t console_session_id;
    uint32_t maximum_privilege;
    uint32_t flags;
} bc_ipmi_session_info;

typedef struct {
    uint32_t struct_size;
    uint32_t flags;
    uint32_t cipher_suite_id;
    uint32_t sdr_record_count;
    uint32_t chassis_power_state;
    uint32_t sel_record_count;
} bc_ipmi_capabilities;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    const bc_ipmi_io *io;
    const bc_ipmi_crypto *crypto;
    uint32_t timeout_ms;
    uint32_t retries;
    uint32_t suite3_policy;
    uint32_t channel;
    bc_string username;
    bc_string password;
} bc_ipmi_session_options;

typedef struct bc_ipmi_session bc_ipmi_session;

typedef struct {
    uint32_t struct_size;
    bc_boot_info boot;
    uint8_t raw[5];
    uint8_t reserved[3];
} bc_ipmi_boot_info;

BC_IPMI_API bc_status bc_ipmi_boot_flags_parse(const uint8_t *, uint32_t, bc_ipmi_boot_info *);
BC_IPMI_API bc_status bc_ipmi_boot_flags_build(const bc_ipmi_boot_info *, uint32_t target, uint32_t mode, uint8_t out[6]);
BC_IPMI_API bc_status bc_ipmi_boot_get(bc_ipmi_session *, bc_ipmi_boot_info *, uint8_t *completion);
#define BC_IPMI_BOOT_WRITE_ATTEMPTED 1u
#define BC_IPMI_BOOT_VERIFIED 2u
#define BC_IPMI_BOOT_CLEANUP_ATTEMPTED 4u
typedef struct {
    uint32_t struct_size, flags;
    bc_status write_status, cleanup_status, verify_status;
    uint8_t completion, cleanup_completion, reserved[2];
    bc_ipmi_boot_info before, after;
} bc_ipmi_boot_result;
/* Sets a one-time override only; never issues a chassis power command.
 * A failed write may have taken effect. Inspect flags and read back before retrying. */
BC_IPMI_API bc_status bc_ipmi_boot_set_once(bc_ipmi_session *, uint32_t target, uint32_t mode, bc_ipmi_boot_result *);


BC_IPMI_API bc_status bc_ipmi_session_create(const bc_ipmi_session_options *, bc_ipmi_session **);
/* Discovers suites, selects one, then runs Open Session and RAKP. Returns
 * BC_CONFIRMATION_REQUIRED without starting a handshake when suite 3 is the
 * only match and policy permits it but confirmation has not been given. */
BC_IPMI_API bc_status bc_ipmi_session_open(bc_ipmi_session *);
BC_IPMI_API bc_status bc_ipmi_session_confirm_suite3(bc_ipmi_session *);
BC_IPMI_API const bc_ipmi_session_info *bc_ipmi_session_info_get(const bc_ipmi_session *);
/* Probe capabilities that can be read without side effects. */
BC_IPMI_API bc_status bc_ipmi_session_probe(bc_ipmi_session *, bc_ipmi_capabilities *);
BC_IPMI_API const bc_ipmi_cipher_suites *bc_ipmi_session_cipher_suites_get(const bc_ipmi_session *);
/* completion_code is the device code; transport/protocol failures use status. */
/* Does not retry. After a successful transport submission, a missing or invalid
 * response returns OUTCOME_UNKNOWN. Pre-submission failures retain their status. */
BC_IPMI_API bc_status bc_ipmi_session_mutate(bc_ipmi_session *, uint8_t netfn, uint8_t command,
    bc_bytes request, uint8_t *completion_code, uint8_t *response, uint32_t capacity, uint32_t *response_length);
BC_IPMI_API bc_status bc_ipmi_session_command(bc_ipmi_session *, uint8_t netfn, uint8_t command,
    bc_bytes request, uint8_t *completion_code, uint8_t *response, uint32_t capacity, uint32_t *response_length);
/* Chassis status/control and vendor NetFn 0x2E group commands. */
BC_IPMI_API bc_status bc_ipmi_chassis_status_get(bc_ipmi_session *, bc_ipmi_chassis_status *);
BC_IPMI_API bc_status bc_ipmi_chassis_capabilities_get(bc_ipmi_session *, bc_ipmi_chassis_capabilities *);
BC_IPMI_API bc_status bc_ipmi_system_restart_cause_get(bc_ipmi_session *, bc_ipmi_restart_cause *);
BC_IPMI_API bc_status bc_ipmi_chassis_control(bc_ipmi_session *, uint8_t action, uint8_t *completion_code);
BC_IPMI_API bc_status bc_ipmi_session_group_command(bc_ipmi_session *, uint32_t iana, uint8_t command,
    bc_bytes request, uint8_t *completion_code, uint8_t *response, uint32_t capacity, uint32_t *response_length);
BC_IPMI_API bc_status bc_ipmi_session_close(bc_ipmi_session *);
BC_IPMI_API void bc_ipmi_session_destroy(bc_ipmi_session *);
#ifdef __cplusplus
}
#endif
#endif

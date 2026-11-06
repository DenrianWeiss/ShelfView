#ifndef BCONTROL_IPMI_FRU_H
#define BCONTROL_IPMI_FRU_H
#include "ipmi_session.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Platform Management FRU Information Storage Definition v1.0 (read-only). */
#define BC_IPMI_FRU_HEADER_SIZE 8u
#define BC_IPMI_FRU_AREA_MAX 2040u        /* area length byte is in 8-byte units */
#define BC_IPMI_FRU_FIELD_RAW_MAX 63u     /* type/length field length is 6 bits */
#define BC_IPMI_FRU_FIELD_TEXT_MAX 128u   /* worst-case decoded size plus NUL */
#define BC_IPMI_FRU_CUSTOM_MAX 8u
#define BC_IPMI_FRU_MULTI_MAX 256u        /* raw multi-record bytes kept */
#define BC_IPMI_FRU_MAX_DEVICES 16u
#define BC_IPMI_FRU_IMAGE_MAX 4096u
#define BC_IPMI_FRU_READ_CHUNK 32u
#define BC_IPMI_FRU_TRUNCATED 1u
#define BC_IPMI_FRU_AREA_PRESENT 1u
#define BC_IPMI_FRU_AREA_CUSTOM_TRUNCATED 2u

typedef struct {
    uint32_t struct_size, abi_version;
    uint32_t area_size;
    uint8_t word_access;
    uint8_t reserved[3];
} bc_ipmi_fru_area_info;

typedef struct {
    uint32_t struct_size, abi_version;
    bc_status status;
    uint8_t field_type;
    uint8_t raw_length;
    uint8_t reserved[2];
    uint8_t raw[BC_IPMI_FRU_FIELD_RAW_MAX];
    char text[BC_IPMI_FRU_FIELD_TEXT_MAX];
} bc_ipmi_fru_field;

typedef struct {
    bc_status status;
    uint8_t present;
    uint8_t chassis_type;
    uint8_t reserved[2];
    uint32_t flags;
    bc_ipmi_fru_field part_number, serial_number;
    uint32_t custom_count;
    bc_ipmi_fru_field custom[BC_IPMI_FRU_CUSTOM_MAX];
} bc_ipmi_fru_chassis;

typedef struct {
    bc_status status;
    uint8_t present;
    uint8_t language;
    uint8_t reserved[2];
    uint32_t flags;
    uint32_t mfg_date;    /* minutes since 1996-01-01, 0 = unspecified */
    bc_ipmi_fru_field manufacturer, product, serial, part_number, file_id;
    uint32_t custom_count;
    bc_ipmi_fru_field custom[BC_IPMI_FRU_CUSTOM_MAX];
} bc_ipmi_fru_board;

typedef struct {
    bc_status status;
    uint8_t present;
    uint8_t language;
    uint8_t reserved[2];
    uint32_t flags;
    bc_ipmi_fru_field manufacturer, name, part_number, version, serial, asset_tag, file_id;
    uint32_t custom_count;
    bc_ipmi_fru_field custom[BC_IPMI_FRU_CUSTOM_MAX];
} bc_ipmi_fru_product;

typedef struct {
    uint32_t struct_size, abi_version;
    bc_status status;
    uint32_t flags;
    uint8_t fru_id;
    uint8_t header_version;
    uint8_t reserved[2];
    bc_ipmi_fru_area_info area;
    bc_status internal_status;   /* internal use area: present but never decoded */
    bc_ipmi_fru_chassis chassis;
    bc_ipmi_fru_board board;
    bc_ipmi_fru_product product;
    bc_status multi_status;      /* never decoded here; raw bytes preserved */
    uint32_t multi_length;
    uint8_t multi_raw[BC_IPMI_FRU_MULTI_MAX];
} bc_ipmi_fru_info;

typedef struct {
    uint32_t struct_size, abi_version;
    bc_status status;
    uint32_t flags;
    uint32_t count;
    bc_status device_status[BC_IPMI_FRU_MAX_DEVICES];
    uint32_t device_size[BC_IPMI_FRU_MAX_DEVICES];
    uint8_t device_access[BC_IPMI_FRU_MAX_DEVICES];
} bc_ipmi_fru_inventory;

/* Get FRU Inventory Area Info for one FRU device. */
BC_IPMI_API bc_status bc_ipmi_fru_area_info_get(bc_ipmi_session *, uint8_t fru_id, bc_ipmi_fru_area_info *);
/* Chunked Read FRU Data honoring byte/word access; short reads keep making progress.
 * length is the number of bytes actually read, also on failure. */
BC_IPMI_API bc_status bc_ipmi_fru_data_read(bc_ipmi_session *, uint8_t fru_id, uint32_t offset,
    uint8_t *buffer, uint32_t capacity, uint32_t *length);
/* Probe FRU device IDs 0..BC_IPMI_FRU_MAX_DEVICES-1, stopping at the first absent ID. */
BC_IPMI_API bc_status bc_ipmi_fru_inventory_get(bc_ipmi_session *, bc_ipmi_fru_inventory *);
/* Decode one FRU field's content bytes (after the type/length byte).
 * Type 3 uses ASCII+Latin1 for English (0 or 25), UTF-16LE otherwise; output is UTF-8. */
BC_IPMI_API bc_status bc_ipmi_fru_text_decode(uint8_t type, bc_bytes data, uint8_t language,
    char *out, uint32_t capacity);
/* Parse a raw FRU image (common header + areas) without any transport.
 * Corrupt or undecodable areas keep an explicit status; verified areas survive. */
BC_IPMI_API bc_status bc_ipmi_fru_image_parse(bc_bytes image, bc_ipmi_fru_info *);
/* Read-only FRU asset info. Aggregate status reports the first area error; per-area
 * and per-field statuses stay in the result. Value type, copyable, no destroy.
 * Serialize session use across threads. */
BC_IPMI_API bc_status bc_ipmi_fru_info_get(bc_ipmi_session *, uint8_t fru_id, bc_ipmi_fru_info *);
#ifdef __cplusplus
}
#endif
#endif

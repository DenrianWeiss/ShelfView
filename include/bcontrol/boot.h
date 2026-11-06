#ifndef BCONTROL_BOOT_H
#define BCONTROL_BOOT_H
#include "bcontrol.h"
#define BC_BOOT_NONE 0u
#define BC_BOOT_PXE 1u
#define BC_BOOT_DISK 2u
#define BC_BOOT_CD 3u
#define BC_BOOT_SETUP 4u
#define BC_BOOT_USB 5u
#define BC_BOOT_UEFI_SHELL 6u
#define BC_BOOT_REMOTE_CD 7u
#define BC_BOOT_REMOTE_FLOPPY 8u
#define BC_BOOT_REMOTE_DISK 9u
#define BC_BOOT_REMOTE_PRIMARY 10u
#define BC_BOOT_FLOPPY 11u
#define BC_BOOT_UNKNOWN UINT32_MAX
#define BC_BOOT_MODE_PRESERVE 0u
#define BC_BOOT_MODE_LEGACY 1u
#define BC_BOOT_MODE_UEFI 2u
#define BC_BOOT_ENABLED 1u
#define BC_BOOT_PERSISTENT 2u
#define BC_BOOT_TARGETS_KNOWN 4u
#define BC_BOOT_LOCKED 8u
#define BC_BOOT_ONCE_SUPPORTED 16u
#define BC_BOOT_ONCE_INFERRED 32u

typedef struct {
    uint32_t struct_size;
    bc_status status;
    uint32_t target, mode, flags, supported_targets;
} bc_boot_info;
#endif

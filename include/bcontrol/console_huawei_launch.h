#ifndef BCONTROL_CONSOLE_HUAWEI_LAUNCH_H
#define BCONTROL_CONSOLE_HUAWEI_LAUNCH_H
#include "console_factory.h"
#include "huawei_kvm.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Transitional discovery bridge. Copies the negotiated startup descriptor. */
BC_CONSOLE_API bc_status bc_console_launch_from_huawei(const bc_huawei_kvm_params *, bc_console_launch **);
#ifdef __cplusplus
}
#endif
#endif

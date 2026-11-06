#include "bcontrol/console_entry.h"

bc_status bc_console_http_family_select(const bc_service_profile *hints, uint32_t count,
    bc_string export_uri, bc_string download_uri, uint32_t format, uint32_t modes, uint32_t *family) {
    if (!family) return BC_INVALID_ARGUMENT;
    *family = 0;
    if (count > 256 || (count && !hints)) return BC_INVALID_ARGUMENT;
    uint32_t selected = 0;
    if (format) {
        bc_status status = bc_huawei_launch_targets_validate(export_uri, download_uri, format);
        if (status != BC_OK) return status;
        if (!(modes & BC_HUAWEI_MODE_SHARED)) return BC_UNSUPPORTED;
        selected = BC_SERVICE_FAMILY_HUAWEI;
    }
    for (uint32_t i = 0; i < count; ++i) {
        const bc_service_profile *hint = hints + i;
        if (hint->struct_size != sizeof(*hint) || hint->service != BC_SERVICE_KVM ||
            hint->family != BC_SERVICE_FAMILY_IDRAC || hint->variant != BC_SERVICE_IDRAC_KVM_EHTML5 ||
            hint->evidence != BC_SERVICE_EVIDENCE_HINT) return BC_INVALID_ARGUMENT;
        if (selected && selected != hint->family) return BC_UNSUPPORTED;
        selected = hint->family;
    }
    if (!selected) return BC_UNSUPPORTED;
    *family = selected;
    return BC_OK;
}

int bc_console_entry_can_select_manually(bc_status status, uint32_t http_status) {
    if (status != BC_OK && status != BC_HTTP_ERROR && status != BC_UNSUPPORTED && status != BC_PROTOCOL_ERROR) return 0;
    if (http_status == 404 || http_status == 405 || http_status == 501) return 1;
    return (status == BC_UNSUPPORTED || status == BC_PROTOCOL_ERROR) &&
        (!http_status || (http_status >= 200 && http_status < 400));
}

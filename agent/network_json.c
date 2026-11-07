#include "network_json.h"

typedef struct { yyjson_mut_doc *doc; yyjson_mut_val *rows; } row_context;
static void append(const bc_redfish_network_row *row, void *userdata) {
    row_context *ctx = userdata;
    yyjson_mut_val *value = yyjson_mut_obj(ctx->doc);
    yyjson_mut_arr_add_val(ctx->rows, value);
    yyjson_mut_obj_add_uint(ctx->doc, value, "flags", row->flags);
    yyjson_mut_obj_add_strncpy(ctx->doc, value, "label", row->label.data ? row->label.data : "", (size_t)row->label.length);
    yyjson_mut_obj_add_strncpy(ctx->doc, value, "value", row->value.data ? row->value.data : "", (size_t)row->value.length);
    yyjson_mut_obj_add_strncpy(ctx->doc, value, "suffix", row->suffix.data ? row->suffix.data : "", (size_t)row->suffix.length);
}
void bc_agent_network_rows_json(yyjson_mut_doc *doc, const bc_redfish_operation *op) {
    row_context ctx = {doc, yyjson_mut_arr(doc)};
    if (bc_redfish_network_rows(op, append, &ctx) == BC_OK)
        yyjson_mut_obj_add_val(doc, yyjson_mut_doc_get_root(doc), "network_rows", ctx.rows);
}

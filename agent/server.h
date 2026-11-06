#ifndef BC_AGENT_SERVER_H
#define BC_AGENT_SERVER_H
#include <stddef.h>
#include <stdint.h>
#include "civetweb.h"
#include "yyjson.h"
int bc_agent_serve(int argc, char **argv);
int bc_agent_private_file(const char *path, const char *content, size_t length);
uint64_t bc_agent_now_ms(void);
void bc_agent_sleep(uint32_t ms);
yyjson_doc *bc_agent_read_json(struct mg_connection *);
const char *bc_agent_json_field(yyjson_val *, const char *, size_t);
int bc_agent_json_fields(yyjson_val *, const char *, const char *);
#endif

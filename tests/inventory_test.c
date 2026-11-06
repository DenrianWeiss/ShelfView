#include "bcontrol/inventory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static bc_inventory_import *parse(const char *text, uint32_t format, bc_status expected) {
    bc_inventory_import *value = NULL;
    bc_inventory_error error = {0}; error.struct_size = sizeof(error);
    CHECK(bc_inventory_parse((bc_bytes){(const uint8_t *)text, strlen(text)}, format, &value, &error) == expected);
    if (expected != BC_OK) CHECK(!value && error.code);
    return value;
}
int main(void) {
    bc_inventory_import *value = parse("{\"version\":1,\"servers\":[{\"address\":\"BMC.Example:443/\",\"name\":\"主机\"},{\"address\":\"https://bmc.example\"},{\"address\":\"[2001:DB8::1]:8443\"},{\"address\":\"192.0.2.1:623\",\"protocol\":\"ipmi\"}]}", BC_INVENTORY_JSON, BC_OK);
    CHECK(bc_inventory_count(value) == 4);
    CHECK(!strcmp(bc_inventory_entry_get(value, 0)->address.data, "https://bmc.example"));
    CHECK(bc_inventory_entry_get(value, 1)->duplicate_of == 0);
    CHECK(!strcmp(bc_inventory_entry_get(value, 2)->address.data, "https://[2001:db8::1]:8443"));
    CHECK(!strcmp(bc_inventory_entry_get(value, 3)->address.data, "ipmi://192.0.2.1"));
    CHECK(!bc_inventory_entry_get(value, 4)); bc_inventory_import_destroy(value);
    value = parse("\xef\xbb\xbf" "address,name,username\r\nBMC.EXAMPLE,\"Rack, \"\"A\"\"\",operator\r\n", BC_INVENTORY_CSV, BC_OK);
    CHECK(bc_inventory_count(value) == 1);
    CHECK(!strcmp(bc_inventory_entry_get(value, 0)->name.data, "Rack, \"A\""));
    bc_inventory_import_destroy(value);
    const char *bad_json[] = {
        "{\"version\":2,\"servers\":[]}", "{\"version\":1,\"version\":1}",
        "{\"version\":1,\"servers\":[{\"address\":\"bmc\",\"password\":\"secret\"}]}",
        "{\"version\":1,\"servers\":[{\"address\":\"bmc\",\"address\":\"other\"}]}",
        "{\"version\":1,\"servers\":[{\"address\":null}]}",
        "{\"version\":1,\"servers\":[{\"address\":\"bmc\"},{\"address\":\"http://bmc\"}]}"
    };
    for (unsigned i = 0; i < sizeof(bad_json) / sizeof(*bad_json); ++i)
        parse(bad_json[i], BC_INVENTORY_JSON, i == 0 ? BC_UNSUPPORTED : BC_INVALID_ARGUMENT);
    const char *bad_csv[] = {"address,password\nbmc,secret", "address,address\nbmc,bmc", "name\nrack", "address\nuser@bmc", "address\nbmc:65536", "address\nbmc:0", "address\n[:::1]", "address\nbmc/path", "address\nbmc?query", "address\nbmc\n\n", "address,name\nbmc", "address\n\"bmc\"x"};
    for (unsigned i = 0; i < sizeof(bad_csv) / sizeof(*bad_csv); ++i)
        parse(bad_csv[i], BC_INVENTORY_CSV, i == 11 ? BC_PROTOCOL_ERROR : BC_INVALID_ARGUMENT);
    parse("address\n\"bmc", BC_INVENTORY_CSV, BC_PROTOCOL_ERROR);
    parse("address\n\xc0\xaf", BC_INVENTORY_CSV, BC_PROTOCOL_ERROR);
    char *many = malloc(80000); CHECK(many); strcpy(many, "address\n");
    for (unsigned i = 0; i < BC_INVENTORY_MAX_ENTRIES; ++i) strcat(many, "bmc\n");
    value = parse(many, BC_INVENTORY_CSV, BC_OK); CHECK(bc_inventory_count(value) == 1000); bc_inventory_import_destroy(value);
    strcat(many, "bmc\n"); parse(many, BC_INVENTORY_CSV, BC_LIMIT_EXCEEDED); free(many);
    bc_inventory_error error = {0}; error.struct_size = sizeof(error); value = NULL;
    CHECK(bc_inventory_parse((bc_bytes){(const uint8_t *)"x", BC_INVENTORY_MAX_BYTES + 1u}, BC_INVENTORY_CSV, &value, &error) == BC_LIMIT_EXCEEDED);
    bc_inventory_import_destroy(NULL);
    puts("inventory: JSON/CSV, ownership, duplicates, malformed input and limits passed");
    return 0;
}

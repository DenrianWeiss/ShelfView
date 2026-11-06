#include "bcontrol/temperature.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
int main(void) {
    uint32_t normal = BC_TEMPERATURE_VALUE_PRESENT | BC_TEMPERATURE_ENABLED | BC_TEMPERATURE_HEALTH_OK;
    bc_temperature_reading readings[] = {
        {60, BC_TEMPERATURE_CELSIUS, normal | BC_TEMPERATURE_CPU},
        {158, BC_TEMPERATURE_FAHRENHEIT, normal | BC_TEMPERATURE_CPU},
        {348.15, BC_TEMPERATURE_KELVIN, normal},
        {95, BC_TEMPERATURE_CELSIUS, BC_TEMPERATURE_VALUE_PRESENT | BC_TEMPERATURE_ENABLED | BC_TEMPERATURE_HEALTH_ABNORMAL | BC_TEMPERATURE_CPU},
        {3000, 0, normal}, {NAN, BC_TEMPERATURE_CELSIUS, normal},
        {110, BC_TEMPERATURE_CELSIUS, BC_TEMPERATURE_ENABLED | BC_TEMPERATURE_HEALTH_OK},
        {120, BC_TEMPERATURE_CELSIUS, BC_TEMPERATURE_VALUE_PRESENT | BC_TEMPERATURE_HEALTH_OK}
    };
    bc_temperature_summary result = {0}; result.struct_size = sizeof(result);
    CHECK(bc_temperature_summarize(readings, sizeof(readings) / sizeof(readings[0]), &result) == BC_OK);
    CHECK(result.flags == 7 && result.cpu_index == 3 && result.normal_index == 2 && result.alert_index == 3);
    CHECK(result.cpu_celsius == 95 && fabs(result.normal_celsius - 75) < 0.0001);
    CHECK(bc_temperature_summarize(readings, 2, &result) == BC_OK);
    CHECK(result.cpu_index == 1 && fabs(result.cpu_celsius - 70) < 0.0001);
    CHECK(bc_temperature_summarize(NULL, 0, &result) == BC_OK);
    CHECK(result.flags == 0 && result.cpu_index == BC_TEMPERATURE_NO_INDEX && result.normal_index == BC_TEMPERATURE_NO_INDEX);
    readings[0].value = -10;
    CHECK(bc_temperature_summarize(readings, 1, &result) == BC_OK && result.normal_celsius == -10);
    readings[0].flags |= BC_TEMPERATURE_HEALTH_ABNORMAL;
    CHECK(bc_temperature_summarize(readings, 1, &result) == BC_INVALID_ARGUMENT);
    bc_temperature_selection selected = {0}; selected.struct_size = sizeof(selected);
    bc_temperature_reading choices[] = {
        {35, BC_TEMPERATURE_CELSIUS, normal | BC_TEMPERATURE_CHASSIS},
        {30, BC_TEMPERATURE_CELSIUS, normal | BC_TEMPERATURE_CPU},
        {99, BC_TEMPERATURE_CELSIUS, normal}
    };
    CHECK(bc_temperature_select(choices, 3, &selected) == BC_OK);
    CHECK(selected.index == 1 && selected.source == BC_TEMPERATURE_SOURCE_CPU && selected.flags == 0);
    choices[1].value = NAN;
    CHECK(bc_temperature_select(choices, 3, &selected) == BC_OK);
    CHECK(selected.index == 0 && selected.celsius == 35 && selected.flags == BC_TEMPERATURE_FALLBACK);
    choices[0].flags &= ~BC_TEMPERATURE_ENABLED;
    CHECK(bc_temperature_select(choices, 3, &selected) == BC_OK && selected.index == BC_TEMPERATURE_NO_INDEX);
    CHECK(bc_temperature_ipmi_role(3) == BC_TEMPERATURE_CPU);
    CHECK(bc_temperature_ipmi_role(23) == BC_TEMPERATURE_CHASSIS);
    CHECK(bc_temperature_ipmi_role(7) == 0);
    CHECK(bc_temperature_redfish_role((bc_string){"Intake", 6}) == BC_TEMPERATURE_CHASSIS);
    CHECK(bc_temperature_redfish_role((bc_string){"CPU", 3}) == BC_TEMPERATURE_CPU);
    CHECK(bc_temperature_redfish_role((bc_string){"GPU", 3}) == 0);
    puts("temperature summary: validity, units, CPU, normal maximum and alerts passed");
    return 0;
}

#ifndef BCONTROL_IRMC_REMOTE_MEDIA_H
#define BCONTROL_IRMC_REMOTE_MEDIA_H

#include "bcontrol/bcontrol.h"
#include "yyjson.h"

#define BC_IRMC_MEDIA_CONNECT_CD 1u
#define BC_IRMC_MEDIA_DISCONNECT_CD 2u

const char *bc_irmc_media_manager_system(yyjson_val *manager);
const char *bc_irmc_media_system_link(yyjson_val *system);
const char *bc_irmc_media_action(yyjson_val *system, uint32_t *state);
int bc_irmc_media_config_matches(yyjson_val *root);
bc_status bc_irmc_media_system_path(bc_string config, char *path, size_t capacity);
bc_status bc_irmc_media_report_image(yyjson_val *cd, bc_string *image);
bc_status bc_irmc_media_config_body(bc_string image, char **body, size_t *length);

#endif

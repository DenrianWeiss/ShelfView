#include "remote_media.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char media_suffix[] = "/Oem/ts_fujitsu/VirtualMedia";

static yyjson_val *fujitsu(yyjson_val *root) {
    return yyjson_obj_get(yyjson_obj_get(root, "Oem"), "ts_fujitsu");
}

static const char *text(yyjson_val *value) {
    const char *s = yyjson_get_str(value);
    return s && strlen(s) == yyjson_get_len(value) ? s : NULL;
}

const char *bc_irmc_media_manager_system(yyjson_val *manager) {
    if (!yyjson_obj_get(fujitsu(manager), "iRMCConfiguration")) return NULL;
    yyjson_val *systems = yyjson_obj_get(yyjson_obj_get(manager, "Links"), "ManagerForServers");
    return yyjson_arr_size(systems) == 1 ? text(yyjson_obj_get(yyjson_arr_get_first(systems), "@odata.id")) : NULL;
}

const char *bc_irmc_media_system_link(yyjson_val *system) {
    return text(yyjson_obj_get(yyjson_obj_get(fujitsu(system), "VirtualMedia"), "@odata.id"));
}

const char *bc_irmc_media_action(yyjson_val *system, uint32_t *state) {
    const char key[] = "http://ts.fujitsu.com/redfish-schemas/v1/FTSSchema.v1_0_0#FTSComputerSystem.VirtualMedia";
    yyjson_val *action = yyjson_obj_get(yyjson_obj_get(yyjson_obj_get(system, "Actions"), "Oem"), key);
    yyjson_val *values = yyjson_obj_get(action, "FTSVirtualMediaAction@Redfish.AllowableValues");
    if (!yyjson_is_arr(values)) return NULL;
    *state = 0;
    size_t i, count;
    yyjson_val *value;
    yyjson_arr_foreach(values, i, count, value) {
        if (yyjson_equals_str(value, "ConnectCD")) *state |= BC_IRMC_MEDIA_CONNECT_CD;
        if (yyjson_equals_str(value, "DisconnectCD")) *state |= BC_IRMC_MEDIA_DISCONNECT_CD;
    }
    return text(yyjson_obj_get(action, "target"));
}

int bc_irmc_media_config_matches(yyjson_val *root) {
    const char type[] = "http://ts.fujitsu.com/redfish-schemas/v1/FTSSchema.v1_0_0#FTSVirtualMedia.";
    const char *name = text(yyjson_obj_get(root, "@odata.type"));
    return name && !strncmp(name, type, sizeof(type) - 1) && strstr(name, ".FTSVirtualMedia");
}

bc_status bc_irmc_media_system_path(bc_string config, char *path, size_t capacity) {
    size_t suffix = sizeof(media_suffix) - 1;
    const char prefix[] = "/redfish/v1/Systems/";
    if (config.length <= sizeof(prefix) - 1 + suffix ||
        memcmp(config.data, prefix, sizeof(prefix) - 1) ||
        memcmp(config.data + config.length - suffix, media_suffix, suffix)) return BC_UNSUPPORTED;
    size_t length = (size_t)config.length - suffix;
    if (length >= capacity) return BC_LIMIT_EXCEEDED;
    if (memchr(config.data + sizeof(prefix) - 1, '/', length - (sizeof(prefix) - 1)) ||
        memchr(config.data, '?', length)) return BC_PROTOCOL_ERROR;
    memcpy(path, config.data, length);
    path[length] = 0;
    return BC_OK;
}

bc_status bc_irmc_media_report_image(yyjson_val *cd, bc_string *image) {
    const char *type = text(yyjson_obj_get(cd, "ShareType"));
    const char *server = text(yyjson_obj_get(cd, "Server"));
    const char *directory = text(yyjson_obj_get(cd, "ShareName"));
    const char *file = text(yyjson_obj_get(cd, "ImageName"));
    if (!type || !server || !*server || !directory || !file || !*file || strpbrk(server, "/@?#"))
        return BC_OK;
    const char *scheme = !strcmp(type, "HTTP") ? "http" :
        !strcmp(type, "NFS") ? "nfs" : !strcmp(type, "SMB") ? "smb" : NULL;
    if (!scheme) return BC_OK;
    if (*directory == '/') ++directory;
    size_t directory_length = strlen(directory);
    size_t length = strlen(scheme) + strlen(server) + directory_length + strlen(file) + 6;
    if (length > 8192) return BC_LIMIT_EXCEEDED;
    char *uri = malloc(length);
    if (!uri) return BC_NO_MEMORY;
    int written = snprintf(uri, length, "%s://%s/%s%s%s", scheme, server, directory,
        directory_length && directory[directory_length - 1] != '/' ? "/" : "", file);
    if (written < 0 || (size_t)written >= length) { free(uri); return BC_PROTOCOL_ERROR; }
    *image = (bc_string){uri, (uint64_t)written};
    return BC_OK;
}

bc_status bc_irmc_media_config_body(bc_string image, char **body, size_t *length) {
    static const struct { const char *scheme, *type; } protocols[] = {
        {"http://", "HTTP"}, {"nfs://", "NFS"}, {"smb://", "SMB"}, {"cifs://", "SMB"}
    };
    const char *server = NULL, *type = NULL, *end = image.data + image.length;
    for (size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); ++i) {
        size_t n = strlen(protocols[i].scheme);
        if (image.length > n && !memcmp(image.data, protocols[i].scheme, n)) {
            server = image.data + n;
            type = protocols[i].type;
            break;
        }
    }
    if (!server) return BC_UNSUPPORTED;
    if (memchr(server, '?', (size_t)(end - server)) || memchr(server, '#', (size_t)(end - server)) ||
        memchr(server, '\\', (size_t)(end - server))) return BC_INVALID_ARGUMENT;
    const char *slash = memchr(server, '/', (size_t)(end - server));
    if (!slash || slash == server || memchr(server, '@', (size_t)(slash - server))) return BC_INVALID_ARGUMENT;
    const char *file = end;
    while (file > slash && file[-1] != '/') --file;
    if (file == end) return BC_INVALID_ARGUMENT;

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return BC_NO_MEMORY;
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_val *cd = root ? yyjson_mut_obj_add_obj(doc, root, "CDImage") : NULL;
    const char *directory = file == slash + 1 ? "/" : slash + 1;
    size_t directory_length = file == slash + 1 ? 1 : (size_t)(file - slash - 2);
    int ok = cd && yyjson_mut_obj_add_strncpy(doc, cd, "Server", server, (size_t)(slash - server)) &&
        yyjson_mut_obj_add_str(doc, cd, "ShareType", type) &&
        yyjson_mut_obj_add_strncpy(doc, cd, "ShareName", directory, directory_length) &&
        yyjson_mut_obj_add_strncpy(doc, cd, "ImageName", file, (size_t)(end - file)) &&
        yyjson_mut_obj_add_str(doc, cd, "UserName", "") &&
        yyjson_mut_obj_add_str(doc, cd, "Password", "") &&
        yyjson_mut_obj_add_str(doc, cd, "UserDomain", "");
    *body = ok ? yyjson_mut_write(doc, 0, length) : NULL;
    yyjson_mut_doc_free(doc);
    return *body ? BC_OK : BC_NO_MEMORY;
}

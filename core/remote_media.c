#include "bcontrol/remote_media.h"
#include <stdlib.h>
#include <string.h>
typedef struct { char *owner, *connection, *uri; } record;
struct bc_remote_media_registry { uint32_t capacity; record *records; };
static int valid(bc_string value, uint64_t limit) {
    return value.data && value.length && value.length <= limit && !memchr(value.data, 0, (size_t)value.length);
}
static int equal(const char *left, bc_string right) {
    return left && strlen(left) == right.length && !memcmp(left, right.data, (size_t)right.length);
}
static char *copy(bc_string value) {
    char *out = malloc((size_t)value.length + 1);
    if (out) { memcpy(out, value.data, (size_t)value.length); out[value.length] = 0; }
    return out;
}
static void clear(record *entry) {
    free(entry->owner); free(entry->connection); free(entry->uri); memset(entry, 0, sizeof(*entry));
}
bc_status bc_remote_media_registry_create(uint32_t capacity, bc_remote_media_registry **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!capacity || capacity > 256) return BC_INVALID_ARGUMENT;
    bc_remote_media_registry *registry = calloc(1, sizeof(*registry));
    if (!registry) return BC_NO_MEMORY;
    registry->records = calloc(capacity, sizeof(*registry->records));
    if (!registry->records) { free(registry); return BC_NO_MEMORY; }
    registry->capacity = capacity; *out = registry; return BC_OK;
}
bc_status bc_remote_media_registry_begin(bc_remote_media_registry *registry, bc_string owner, bc_string connection, bc_string uri) {
    if (!registry || !valid(owner, 64) || !valid(connection, 64) || !valid(uri, 8192)) return BC_INVALID_ARGUMENT;
    record *empty = NULL;
    for (uint32_t i = 0; i < registry->capacity; ++i) {
        record *entry = &registry->records[i];
        if (!entry->owner) { if (!empty) empty = entry; continue; }
        if (equal(entry->uri, uri) || equal(entry->connection, connection)) return BC_BUSY;
    }
    if (!empty) return BC_LIMIT_EXCEEDED;
    record next = {copy(owner), copy(connection), copy(uri)};
    if (!next.owner || !next.connection || !next.uri) { clear(&next); return BC_NO_MEMORY; }
    *empty = next; return BC_OK;
}
bc_status bc_remote_media_registry_bind(bc_remote_media_registry *registry, bc_string owner, bc_string connection, bc_string *uri) {
    if (!registry || !uri || !valid(owner, 64) || !valid(connection, 64)) return BC_INVALID_ARGUMENT;
    *uri = (bc_string){0};
    for (uint32_t i = 0; i < registry->capacity; ++i) {
        record *entry = &registry->records[i];
        if (!equal(entry->connection, connection)) continue;
        if (!equal(entry->owner, owner)) return BC_BUSY;
        *uri = (bc_string){entry->uri, strlen(entry->uri)}; return BC_OK;
    }
    int owned = 0;
    for (uint32_t i = 0; i < registry->capacity; ++i) {
        record *entry = &registry->records[i];
        if (!equal(entry->owner, owner)) continue;
        owned = 1;
        if (entry->connection && !equal(entry->connection, connection)) continue;
        if (!entry->connection) { entry->connection = copy(connection); if (!entry->connection) return BC_NO_MEMORY; }
        *uri = (bc_string){entry->uri, strlen(entry->uri)}; return BC_OK;
    }
    return owned ? BC_BUSY : BC_UNSUPPORTED;
}
void bc_remote_media_registry_release(bc_remote_media_registry *registry, bc_string connection) {
    if (!registry || !valid(connection, 64)) return;
    for (uint32_t i = 0; i < registry->capacity; ++i) if (equal(registry->records[i].connection, connection)) {
        free(registry->records[i].connection); registry->records[i].connection = NULL;
    }
}
bc_status bc_remote_media_registry_claim_eject(bc_remote_media_registry *registry, bc_string owner, bc_string connection, bc_string uri) {
    if (!registry || !valid(owner, 64) || !valid(connection, 64) || !valid(uri, 8192)) return BC_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < registry->capacity; ++i)
        if (equal(registry->records[i].connection, connection) && !equal(registry->records[i].uri, uri)) return BC_BUSY;
    for (uint32_t i = 0; i < registry->capacity; ++i) {
        record *entry = &registry->records[i];
        if (!equal(entry->uri, uri)) continue;
        if (entry->connection) return equal(entry->connection, connection) ? BC_OK : BC_BUSY;
        entry->connection = copy(connection); return entry->connection ? BC_OK : BC_NO_MEMORY;
    }
    return bc_remote_media_registry_begin(registry, owner, connection, uri);
}
bc_status bc_remote_media_registry_can_mount(const bc_remote_media_registry *registry, bc_string uri) {
    if (!registry || !valid(uri, 8192)) return BC_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < registry->capacity; ++i) if (equal(registry->records[i].uri, uri)) return BC_BUSY;
    return BC_OK;
}
void bc_remote_media_registry_clear(bc_remote_media_registry *registry, bc_string connection) {
    if (!registry || !valid(connection, 64)) return;
    for (uint32_t i = 0; i < registry->capacity; ++i) if (equal(registry->records[i].connection, connection)) clear(&registry->records[i]);
}
void bc_remote_media_registry_destroy(bc_remote_media_registry *registry) {
    if (!registry) return;
    for (uint32_t i = 0; i < registry->capacity; ++i) clear(&registry->records[i]);
    free(registry->records); free(registry);
}

#include "bcontrol/serial_provider.h"
#include <stdlib.h>

struct bc_serial_stream { bc_serial_provider provider; void *context; int closed, owned; bc_status cleanup; };
bc_status bc_serial_wrap(const bc_serial_provider *provider, void *context, bc_serial_stream **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!provider || provider->struct_size != sizeof(*provider) || !context ||
        !provider->read || !provider->write || !provider->info || !provider->close) return BC_INVALID_ARGUMENT;
    bc_serial_stream *stream = malloc(sizeof(*stream));
    if (!stream) return BC_NO_MEMORY;
    *stream = (bc_serial_stream){.provider=*provider,.context=context,.cleanup=BC_OK};
    *out = stream;
    return BC_OK;
}
bc_status bc_serial_read(bc_serial_stream *stream, uint64_t now, uint32_t timeout,
    uint8_t *data, uint32_t capacity, uint32_t *length) {
    if (!length) return BC_INVALID_ARGUMENT;
    *length = 0;
    if (!stream || !data || !capacity) return BC_INVALID_ARGUMENT;
    if (stream->closed) return BC_SHUTTING_DOWN;
    return stream->provider.read(stream->context, now, timeout, data, capacity, length);
}
bc_status bc_serial_write(bc_serial_stream *stream, bc_bytes bytes, uint32_t *accepted) {
    if (!accepted) return BC_INVALID_ARGUMENT;
    *accepted = 0;
    if (!stream || (bytes.length && !bytes.data) || bytes.length > UINT32_MAX) return BC_INVALID_ARGUMENT;
    bc_serial_info info = {0}; info.struct_size = sizeof(info);
    bc_status status = bc_serial_info_get(stream, &info);
    if (status != BC_OK) return status;
    if (info.state != BC_SERIAL_ACTIVE) return info.status != BC_OK ? info.status : BC_SHUTTING_DOWN;
    if (!(info.capabilities & BC_SERIAL_WRITE)) return BC_BUSY;
    return stream->provider.write(stream->context, bytes, accepted);
}
bc_status bc_serial_control(bc_serial_stream *stream, uint32_t command) {
    if (!stream) return BC_INVALID_ARGUMENT;
    if (stream->closed) return BC_SHUTTING_DOWN;
    return stream->provider.control ? stream->provider.control(stream->context, command) : BC_UNSUPPORTED;
}
bc_status bc_serial_info_get(const bc_serial_stream *stream, bc_serial_info *info) {
    if (!stream || !info || info->struct_size != sizeof(*info)) return BC_INVALID_ARGUMENT;
    bc_status status = stream->provider.info(stream->context, info);
    if (status == BC_OK && stream->closed) {
        info->state = BC_SERIAL_CLOSED;
        info->capabilities &= ~BC_SERIAL_WRITE;
        if (info->cleanup_status == BC_OK) info->cleanup_status = stream->cleanup;
    }
    return status;
}
bc_status bc_serial_close(bc_serial_stream *stream) {
    if (!stream) return BC_INVALID_ARGUMENT;
    if (!stream->closed) { stream->cleanup = stream->provider.close(stream->context); stream->closed = 1; }
    return stream->cleanup;
}
void bc_serial_own(bc_serial_stream *stream) { if(stream)stream->owned=1; }
void bc_serial_destroy(bc_serial_stream *stream) { if(!stream)return;if(stream->owned&&stream->provider.destroy)stream->provider.destroy(stream->context);free(stream); }

#include "bcontrol/media_provider.h"
#include "huawei_kvm_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* iBMC VMM virtual media (websocket on the VMM port). The transport and websocket upgrade are
 * provided by the caller through bc_huawei_io; this file only speaks the VMM packet/SCSI protocol.
 * The block source is read-only: no write CDB is ever forwarded. */

#define VMM_HEADER 12u
#define VMM_ACK 0u
#define VMM_REGISTER 1u
#define VMM_CREATE 2u
#define VMM_TRANS_UFI 3u
#define VMM_TRANS_SFF 4u
#define VMM_CLOSE_VM 5u
#define VMM_HEARTBEAT 6u
#define VMM_CLOSE_DEV 7u
#define VMM_END_SFF 0xFFu
#define VMM_END_UFI 0xFEu
#define VMM_ACK_AUTH_OK 0x00u
#define VMM_ACK_DEVICE_CREATE 0x10u
#define VMM_ACK_DEVICE_FAIL 0x11u
#define VMM_ACK_BUSY 0x31u
#define VMM_DEVICE_CDROM 2u
#define VMM_DATA_TYPE 1u
#define VMM_STATE_CONTINUE 1u
#define VMM_STATE_END 3u
#define VMM_MAX_REPLY 32768u
#define VMM_BLOCK_SIZE 2048u
#define VMM_INPUT_LIMIT (VMM_HEADER + 4096u)

struct bc_huawei_media {
    bc_service_profile profile;
    bc_huawei_vmm_info info;
    bc_huawei_vmm_source source;
    bc_huawei_io io;
    bc_huawei_media_options options;
    uint32_t state;
    char error[BC_HUAWEI_ERROR_MAX];
    bc_huawei_media_statistics stats;
    uint8_t input[VMM_INPUT_LIMIT];
    uint32_t input_length;
    uint8_t sense[18];
    uint32_t present;
    uint32_t created;
    uint32_t removal_unconfirmed;
    uint32_t usb_id;
    uint64_t last_heartbeat;
    uint32_t heartbeat_ticks;
};

static void media_error(bc_huawei_media *media, const char *message) {
    if (!media) return;
    snprintf(media->error, sizeof(media->error), "%s", message ? message : "");
    media->state = BC_HUAWEI_MEDIA_STATE_ERROR;
}

static uint32_t media_read_be32(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
}
static void media_write_be32(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24); data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8); data[3] = (uint8_t)value;
}
static uint32_t media_read_be16(const uint8_t *data) { return ((uint32_t)data[0] << 8) | data[1]; }

static uint64_t media_clock(const bc_huawei_media *media) {
    if (media->options.clock && media->options.clock_user) return media->options.clock(media->options.clock_user);
    return 0;
}

static bc_status media_send(bc_huawei_media *media, const uint8_t *data, uint32_t length) {
    if (!media->io.send) return BC_INVALID_ARGUMENT;
    return media->io.send(media->io.user, data, length);
}

static void media_set_sense(bc_huawei_media *media, uint8_t key, uint8_t asc, uint8_t ascq) {
    memset(media->sense, 0, sizeof(media->sense));
    media->sense[0] = 0x70;
    media->sense[2] = key;
    media->sense[7] = 0x0A;
    media->sense[12] = asc;
    media->sense[13] = ascq;
    media->stats.sense_key = key;
    media->stats.asc = asc;
    media->stats.ascq = ascq;
}

/* ---------------------------------------------------------------------------------------------
 * VMM data packets
 * ------------------------------------------------------------------------------------------- */

static bc_status media_send_data(bc_huawei_media *media, const uint8_t *data, uint32_t length, int last) {
    uint32_t position = 0;
    while (position < length || (length == 0 && last)) {
        uint32_t chunk = length - position;
        if (chunk > VMM_MAX_REPLY) chunk = VMM_MAX_REPLY;
        int final_chunk = last && position + chunk >= length;
        uint8_t header[VMM_HEADER];
        memset(header, 0, sizeof(header));
        header[0] = VMM_TRANS_SFF;
        header[1] = (uint8_t)((final_chunk ? VMM_STATE_END : VMM_STATE_CONTINUE) * 16 + VMM_DATA_TYPE);
        header[3] = (uint8_t)media->usb_id;
        if ((media->info.flags & BC_HUAWEI_VMM_FLAG_ENCRYPTED) != 0) {
            uint32_t padded = (chunk + 15u) & ~15u;
            uint8_t *plain = (uint8_t *)calloc(1, padded);
            uint8_t *cipher = (uint8_t *)malloc(padded);
            if (!plain || !cipher) { free(plain); free(cipher); return BC_NO_MEMORY; }
            memcpy(plain, data + position, chunk);
            bc_status status = huawei_aes_cbc(media->info.key, media->info.iv, plain, padded, cipher, 1);
            free(plain);
            if (status != BC_OK) { free(cipher); return status; }
            media_write_be32(header + 4, padded + 4);
            uint8_t prefix[4];
            media_write_be32(prefix, chunk);
            if (media_send(media, header, VMM_HEADER) != BC_OK ||
                media_send(media, prefix, sizeof(prefix)) != BC_OK ||
                media_send(media, cipher, padded) != BC_OK) {
                free(cipher);
                return BC_IO_ERROR;
            }
            free(cipher);
        } else {
            media_write_be32(header + 4, chunk);
            if (media_send(media, header, VMM_HEADER) != BC_OK) return BC_IO_ERROR;
            if (chunk && media_send(media, data + position, chunk) != BC_OK) return BC_IO_ERROR;
        }
        position += chunk;
        if (length == 0) break;
    }
    return BC_OK;
}

static bc_status media_send_result(bc_huawei_media *media, uint8_t result) {
    uint8_t header[VMM_HEADER];
    memset(header, 0, sizeof(header));
    header[0] = VMM_END_SFF;
    header[1] = result;
    header[3] = (uint8_t)media->usb_id;
    return media_send(media, header, sizeof(header));
}

static bc_status media_finish(bc_huawei_media *media, const uint8_t *command, uint32_t length) {
    uint8_t sense_key = media->sense[2];
    uint8_t result = 0;
    if ((sense_key != 0 && (length == 0 || command[0] != 0x03)) || (length && command[0] == 0x4A)) result = 1;
    return media_send_result(media, result);
}

/* ---------------------------------------------------------------------------------------------
 * SCSI CDB handling (read-only)
 * ------------------------------------------------------------------------------------------- */

static uint64_t media_blocks(const bc_huawei_media *media) {
    if (media->source.size < VMM_BLOCK_SIZE) return 0;
    return media->source.size / VMM_BLOCK_SIZE;
}

static bc_status media_inquiry(bc_huawei_media *media, const uint8_t *command, uint32_t length) {
    static const uint8_t inquiry[36] = {
        0x05, 0x80, 0x00, 0x21, 0x1F, 0x00, 0x00, 0x00,
        'V','i','r','t','u','a','l',' ','D','V','D','-','R','O','M',' ',
        'V','M',' ','1','.','1','.','0',' ','2','2','5'};
    if (length > 1 && (command[1] & 0xE0)) { media_set_sense(media, 5, 0x25, 0); return media_send_result(media, 1); }
    media_set_sense(media, 0, 0, 0);
    if (media_send_data(media, inquiry, sizeof(inquiry), 1) != BC_OK) return BC_IO_ERROR;
    return media_send_result(media, 0);
}

static bc_status media_read_capacity(bc_huawei_media *media, uint32_t allocation) {
    if (!media->present || !media->source.size) { media_set_sense(media, 2, 0x3A, 0); return media_send_result(media, 1); }
    uint64_t blocks = media_blocks(media);
    uint32_t last = blocks ? (uint32_t)(blocks - 1) : 0;
    uint8_t data[8];
    media_write_be32(data, last);
    media_write_be32(data + 4, VMM_BLOCK_SIZE);
    media_set_sense(media, 0, 0, 0);
    uint32_t take = allocation < sizeof(data) ? allocation : (uint32_t)sizeof(data);
    if (media_send_data(media, data, take, 1) != BC_OK) return BC_IO_ERROR;
    return media_send_result(media, 0);
}

static bc_status media_mode_sense(bc_huawei_media *media, uint32_t allocation) {
    uint8_t data[256];
    memset(data, 0, sizeof(data));
    uint32_t size = 8;
    data[2] = media->present && media->source.size ? 0x70 : 0x01;
    data[3] = 0x00;
    /* Caching page. */
    data[size + 0] = 0x08; data[size + 1] = 0x12;
    size += 20;
    /* Write parameters: read-only media. */
    data[size + 0] = 0x05; data[size + 1] = 0x1E;
    data[size + 2] = 0x03; data[size + 3] = 0xE8;
    data[size + 4] = 0x02; data[size + 5] = 0x12;
    size += 32;
    data[0] = (uint8_t)((size - 2) >> 8);
    data[1] = (uint8_t)(size - 2);
    uint32_t take = allocation < size ? allocation : size;
    media_set_sense(media, 0, 0, 0);
    if (media_send_data(media, data, take, 1) != BC_OK) return BC_IO_ERROR;
    return media_send_result(media, 0);
}

static bc_status media_read_toc(bc_huawei_media *media, const uint8_t *command, uint32_t length) {
    uint8_t data[32];
    memset(data, 0, sizeof(data));
    uint32_t size = 4;
    int msf = length > 1 && (command[1] & 0x02) != 0;
    uint64_t blocks = media_blocks(media);
    data[2] = 1; data[3] = 1;
    /* Track 1 start. */
    data[size++] = 0; data[size++] = 0x14; data[size++] = 1; data[size++] = 0;
    data[size++] = 0; data[size++] = 0;
    data[size++] = (uint8_t)(msf ? 0x02 : 0x00);
    data[size++] = 0;
    /* Lead-out. */
    data[size++] = 0; data[size++] = 0x14; data[size++] = 0xAA; data[size++] = 0;
    if (msf) {
        data[size++] = 0; data[size++] = 0; data[size++] = 2; data[size++] = 0;
    } else {
        media_write_be32(data + size, (uint32_t)blocks);
        size += 4;
    }
    data[0] = (uint8_t)((size - 2) >> 8);
    data[1] = (uint8_t)(size - 2);
    uint32_t allocation = length > 7 ? media_read_be16(command + 7) : size;
    uint32_t take = allocation < size ? allocation : size;
    media_set_sense(media, 0, 0, 0);
    if (media_send_data(media, data, take, 1) != BC_OK) return BC_IO_ERROR;
    return media_send_result(media, 0);
}

static bc_status media_read_blocks(bc_huawei_media *media, const uint8_t *command, uint32_t opcode,
                                   uint32_t length) {
    if (length < 9) { media_set_sense(media, 5, 0x24, 0); return media_send_result(media, 1); }
    if (!media->present || !media->source.size) { media_set_sense(media, 2, 0x3A, 0); return media_send_result(media, 1); }
    uint32_t lba = ((uint32_t)command[2] << 24) | ((uint32_t)command[3] << 16)
                 | ((uint32_t)command[4] << 8) | command[5];
    uint64_t count = opcode == 0x28
        ? (((uint32_t)command[7] << 8) | command[8])
        : ((uint32_t)command[6] << 24) | ((uint32_t)command[7] << 16) | ((uint32_t)command[8] << 8) | command[9];
    if (count == 0 || count > 0xFFFF) { media_set_sense(media, 5, 0x24, 0); return media_send_result(media, 1); }
    uint64_t offset = (uint64_t)lba * VMM_BLOCK_SIZE;
    uint64_t bytes = count * VMM_BLOCK_SIZE;
    if (offset >= media->source.size || bytes > media->source.size - offset) {
        media_set_sense(media, 5, 0x21, 0);
        return media_send_result(media, 1);
    }
    uint8_t *buffer = (uint8_t *)malloc(VMM_MAX_REPLY);
    if (!buffer) { media_set_sense(media, 2, 0x04, 0); return media_send_result(media, 1); }
    media_set_sense(media, 0, 0, 0);
    uint64_t remaining = bytes;
    uint64_t position = offset;
    bc_status status = BC_OK;
    while (remaining) {
        uint32_t chunk = remaining > VMM_MAX_REPLY ? VMM_MAX_REPLY : (uint32_t)remaining;
        status = media->source.read(media->source.userdata, position, chunk, buffer);
        if (status != BC_OK) {
            free(buffer);
            media_set_sense(media, 3, 0x11, 0);
            return media_send_result(media, 1);
        }
        media->stats.bytes_read += chunk;
        int last = remaining == chunk;
        if (media_send_data(media, buffer, chunk, last) != BC_OK) { free(buffer); return BC_IO_ERROR; }
        position += chunk;
        remaining -= chunk;
    }
    free(buffer);
    return media_send_result(media, 0);
}

static void media_handle_command(bc_huawei_media *media, uint8_t usb_id, const uint8_t *command, uint32_t length) {
    media->usb_id = usb_id;
    media->stats.commands++;
    if (!length) return;
    uint32_t allocation = 0;
    if (length > 8) {
        if (command[0] == 0x12 || command[0] == 0x1A || command[0] == 0x03) allocation = (uint32_t)command[4] * 256u;
        else allocation = media_read_be16(command + 7);
    }
    switch (command[0]) {
    case 0x00: case 0x4A: /* TEST UNIT READY */
        if (!media->present || !media->source.size) media_set_sense(media, 2, 0x3A, 0);
        else media_set_sense(media, 0, 0, 0);
        (void)media_finish(media, command, length);
        break;
    case 0x03:
        (void)media_send_data(media, media->sense, sizeof(media->sense), 1);
        (void)media_send_result(media, 0);
        break;
    case 0x12: (void)media_inquiry(media, command, length); break;
    case 0x25: case 0x23: (void)media_read_capacity(media, allocation); break;
    case 0x5A: (void)media_mode_sense(media, allocation); break;
    case 0x43: (void)media_read_toc(media, command, length); break;
    case 0x28: case 0xA8: (void)media_read_blocks(media, command, command[0], length); break;
    case 0x1B: {
        if (length < 5) { media_set_sense(media, 5, 0x24, 0); (void)media_send_result(media, 1); break; }
        uint8_t control = command[4];
        if ((control & 0x02) && !(control & 0x01)) media->present = 0;
        else if (control & 0x01) media->present = 1;
        media_set_sense(media, 0, 0, 0);
        (void)media_finish(media, command, length);
        break;
    }
    case 0x04: case 0x2A: case 0xAA: case 0x2E: /* write/format: media is read-only */
        media_set_sense(media, 7, 0x27, 0);
        (void)media_finish(media, command, length);
        break;
    case 0x55: case 0x1E: case 0x2B: case 0x2F: case 0x1D: case 0x01: case 0x35:
        media_set_sense(media, 0, 0, 0);
        (void)media_finish(media, command, length);
        break;
    default:
        media_set_sense(media, 5, 0x20, 0);
        (void)media_finish(media, command, length);
        break;
    }
}

/* ---------------------------------------------------------------------------------------------
 * Frame dispatch
 * ------------------------------------------------------------------------------------------- */

static void media_send_heartbeat(bc_huawei_media *media) {
    uint8_t header[VMM_HEADER];
    memset(header, 0, sizeof(header));
    header[0] = VMM_HEARTBEAT;
    if (media_send(media, header, sizeof(header)) == BC_OK) ++media->stats.heartbeats;
}

static void media_handle_ack(bc_huawei_media *media, const uint8_t *packet) {
    uint8_t status = packet[2];
    if (media->state == BC_HUAWEI_MEDIA_STATE_CONNECTING) {
        if (status == VMM_ACK_AUTH_OK) {
            media->profile.evidence |= BC_SERVICE_EVIDENCE_HANDSHAKE;
            media->state = BC_HUAWEI_MEDIA_STATE_ESTABLISHED;
        }
        else if (status == VMM_ACK_BUSY) media_error(media, "virtual media is busy");
    } else if (status == VMM_ACK_DEVICE_CREATE) {
        media->created = 1;
    } else if (status == VMM_ACK_DEVICE_FAIL) {
        media_error(media, "virtual media device creation failed");
    } else if (status == VMM_ACK_BUSY) {
        media_error(media, "virtual media is busy");
    }
}

static bc_status media_dispatch(bc_huawei_media *media) {
    uint32_t position = 0;
    while (media->input_length - position >= VMM_HEADER) {
        uint8_t *packet = media->input + position;
        uint8_t command = packet[0];
        if (command == VMM_ACK) {
            media_handle_ack(media, packet);
            position += VMM_HEADER;
        } else if (command == VMM_CLOSE_VM || command == VMM_CLOSE_DEV) {
            media->state = BC_HUAWEI_MEDIA_STATE_CLOSED;
            position += VMM_HEADER;
        } else if (command == VMM_TRANS_SFF || command == VMM_TRANS_UFI) {
            uint32_t body = media_read_be32(packet + 4);
            if (body > VMM_INPUT_LIMIT) return BC_PROTOCOL_ERROR;
            if (media->input_length - position < VMM_HEADER + body) break;
            media_handle_command(media, packet[3], packet + VMM_HEADER, body);
            position += VMM_HEADER + body;
        } else {
            ++position;
        }
        if (media->state == BC_HUAWEI_MEDIA_STATE_ERROR) break;
    }
    if (position) {
        memmove(media->input, media->input + position, media->input_length - position);
        media->input_length -= position;
    }
    return media->state == BC_HUAWEI_MEDIA_STATE_ERROR ? BC_PROTOCOL_ERROR : BC_OK;
}

static bc_status media_receive(bc_huawei_media *media, uint32_t timeout_ms) {
    uint8_t buffer[4096];
    uint32_t received = 0;
    bc_status status = media->io.recv(media->io.user, buffer, sizeof(buffer), &received, timeout_ms);
    if (status != BC_OK) return status;
    if (!received) return BC_OK;
    if (media->input_length + received > sizeof(media->input)) return BC_LIMIT_EXCEEDED;
    memcpy(media->input + media->input_length, buffer, received);
    media->input_length += received;
    return media_dispatch(media);
}

/* ---------------------------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------------------------- */

bc_status bc_huawei_media_create(const bc_huawei_media_options *options, const bc_huawei_io *io,
                                 bc_huawei_media **out) {
    if (!options || options->struct_size != sizeof(*options) || options->abi_version != BC_ABI_VERSION ||
        !options->info || !options->source || !io || !io->send || !io->recv || !out) return BC_INVALID_ARGUMENT;
    if (!options->source->read || !options->source->size) return BC_INVALID_ARGUMENT;
    bc_huawei_media *media = (bc_huawei_media *)calloc(1, sizeof(*media));
    if (!media) return BC_NO_MEMORY;
    media->info = *options->info;
    media->source = *options->source;
    media->io = *io;
    media->options = *options;
    media->state = BC_HUAWEI_MEDIA_STATE_CREATED;
    media->profile = (bc_service_profile){sizeof(bc_service_profile), BC_SERVICE_LOCAL_MEDIA,
        BC_SERVICE_FAMILY_HUAWEI, BC_SERVICE_HUAWEI_MEDIA_VMM, 0};
    media->present = 1;
    *out = media;
    return BC_OK;
}

/* Waits for a specific ACK status while draining other packets. */
static bc_status media_await_ack(bc_huawei_media *media, uint8_t expected, uint32_t timeout_ms) {
    uint64_t deadline = media->options.clock && media->options.clock_user
        ? media_clock(media) + timeout_ms : 0;
    uint32_t iterations = timeout_ms / 100 + 1;
    while (media->state != BC_HUAWEI_MEDIA_STATE_ESTABLISHED) {
        if (media->options.clock && media->options.clock_user) {
            if (media_clock(media) > deadline) return BC_TIMEOUT;
        } else if (!iterations--) {
            return BC_TIMEOUT;
        }
        bc_status status = media_receive(media, 100);
        if (status == BC_TIMEOUT) continue;
        if (status != BC_OK) return status;
        if (media->state == BC_HUAWEI_MEDIA_STATE_ERROR) {
            media->state = BC_HUAWEI_MEDIA_STATE_CONNECTING;
            return BC_PROTOCOL_ERROR;
        }
    }
    (void)expected;
    return BC_OK;
}

bc_status bc_huawei_media_connect(bc_huawei_media *media) {
    if (!media) return BC_INVALID_ARGUMENT;
    if (media->state != BC_HUAWEI_MEDIA_STATE_CREATED) return BC_BUSY;
    media->state = BC_HUAWEI_MEDIA_STATE_CONNECTING;
    media->error[0] = 0;
    uint32_t timeout = media->options.timeout_ms ? media->options.timeout_ms : 8000;
    uint8_t auth[VMM_HEADER + 29];
    memset(auth, 0, sizeof(auth));
    auth[0] = VMM_REGISTER;
    media_write_be32(auth + 4, 29);
    auth[8] = 3; auth[9] = 1; auth[10] = 1; auth[11] = 1;
    memcpy(auth + VMM_HEADER, media->info.auth, BC_HUAWEI_AUTH_MAX);
    auth[VMM_HEADER + 24] = 0;
    bc_status status = media_send(media, auth, sizeof(auth));
    if (status != BC_OK) { media_error(media, "VMM transport send failed"); return status; }
    status = media_await_ack(media, VMM_ACK_AUTH_OK, timeout);
    if (status != BC_OK) { media_error(media, "VMM authentication failed"); return status; }
    uint8_t create[VMM_HEADER];
    memset(create, 0, sizeof(create));
    create[0] = VMM_CREATE;
    create[1] = VMM_DEVICE_CDROM;
    media->removal_unconfirmed = 1;
    status = media_send(media, create, sizeof(create));
    if (status != BC_OK) { media_error(media, "VMM transport send failed"); return status; }
    uint64_t deadline = media->options.clock && media->options.clock_user ? media_clock(media) + timeout : 0;
    uint32_t iterations = timeout / 100 + 1;
    while (!media->created) {
        if (media->options.clock && media->options.clock_user) {
            if (media_clock(media) > deadline) { media_error(media, "virtual media device open timed out"); return BC_TIMEOUT; }
        } else if (!iterations--) {
            media_error(media, "virtual media device open timed out");
            return BC_TIMEOUT;
        }
        status = media_receive(media, 100);
        if (status == BC_TIMEOUT) continue;
        if (status != BC_OK) { media_error(media, "virtual media device open failed"); return status; }
        if (media->state == BC_HUAWEI_MEDIA_STATE_ERROR) return BC_PROTOCOL_ERROR;
    }
    media->state = BC_HUAWEI_MEDIA_STATE_ESTABLISHED;
    media->last_heartbeat = media_clock(media);
    return BC_OK;
}

bc_status bc_huawei_media_poll(bc_huawei_media *media, uint32_t timeout_ms) {
    if (!media) return BC_INVALID_ARGUMENT;
    if (media->state == BC_HUAWEI_MEDIA_STATE_ERROR) return BC_PROTOCOL_ERROR;
    if (media->state != BC_HUAWEI_MEDIA_STATE_ESTABLISHED) return BC_BUSY;
    bc_status status = media_receive(media, timeout_ms);
    if (status != BC_OK && status != BC_TIMEOUT) { media_error(media, "VMM transport failed"); return status; }
    uint32_t interval = media->options.heartbeat_interval_ms ? media->options.heartbeat_interval_ms : 5000;
    if (media->options.clock && media->options.clock_user) {
        uint64_t now = media_clock(media);
        if (now - media->last_heartbeat >= interval) { media_send_heartbeat(media); media->last_heartbeat = now; }
    } else if (++media->heartbeat_ticks >= 64) {
        media_send_heartbeat(media);
        media->heartbeat_ticks = 0;
    }
    return media->state == BC_HUAWEI_MEDIA_STATE_ERROR ? BC_PROTOCOL_ERROR : BC_OK;
}

bc_status bc_huawei_media_close(bc_huawei_media *media) {
    if (!media) return BC_INVALID_ARGUMENT;
    bc_status status = BC_OK;
    if (media->state != BC_HUAWEI_MEDIA_STATE_CLOSED &&
        (media->removal_unconfirmed || media->state == BC_HUAWEI_MEDIA_STATE_CONNECTING)) {
        uint8_t packet[VMM_HEADER];
        memset(packet, 0, sizeof(packet));
        packet[0] = VMM_CLOSE_VM;
        packet[1] = VMM_DEVICE_CDROM;
        status = media_send(media, packet, sizeof(packet));
    }
    media->state = BC_HUAWEI_MEDIA_STATE_CLOSED;
    return status;
}
uint32_t bc_huawei_media_removal_unconfirmed(const bc_huawei_media *media) {
    return media ? media->removal_unconfirmed : 0;
}

bc_status bc_huawei_media_state(const bc_huawei_media *media, uint32_t *state) {
    if (!media || !state) return BC_INVALID_ARGUMENT;
    *state = media->state;
    return BC_OK;
}

bc_status bc_huawei_media_stats(const bc_huawei_media *media, bc_huawei_media_statistics *stats) {
    if (!media || !stats || stats->struct_size != sizeof(*stats) || stats->abi_version != BC_ABI_VERSION)
        return BC_INVALID_ARGUMENT;
    *stats = media->stats;
    stats->struct_size = sizeof(*stats);
    stats->abi_version = BC_ABI_VERSION;
    return BC_OK;
}

bc_status bc_huawei_media_error(const bc_huawei_media *media, char *out, uint32_t capacity) {
    if (!media || !out || !capacity) return BC_INVALID_ARGUMENT;
    snprintf(out, capacity, "%s", media->error);
    return BC_OK;
}

void bc_huawei_media_destroy(bc_huawei_media *media) {
    free(media);
}

const bc_service_profile *bc_huawei_media_profile_get(const bc_huawei_media *media) {
    return media ? &media->profile : NULL;
}

static bc_status media_session_poll(void *context, uint32_t timeout) {
    return bc_huawei_media_poll(context, timeout);
}
static bc_status media_session_control(void *context, uint32_t command) {
    if (command == BC_MEDIA_CONTROL_START) return bc_huawei_media_connect(context);
    return command == BC_MEDIA_CONTROL_KEEPALIVE ? BC_UNSUPPORTED : bc_huawei_media_close(context);
}
static bc_status media_session_info(const void *context, bc_media_session_info *out) {
    uint32_t state;
    bc_status status = bc_huawei_media_state(context, &state);
    if (status != BC_OK) return status;
    bc_huawei_media_statistics stats = {0};
    stats.struct_size = sizeof(stats); stats.abi_version = BC_ABI_VERSION;
    status = bc_huawei_media_stats(context, &stats);
    if (status != BC_OK) return status;
    out->flags = BC_MEDIA_BYTES_READ_VALID | (state == BC_HUAWEI_MEDIA_STATE_ESTABLISHED ?
        BC_MEDIA_CONNECTED | BC_MEDIA_SOURCE_ATTACHED : 0);
    out->bytes_read = stats.bytes_read;
    out->state = state; out->requests = stats.commands;
    if (bc_huawei_media_removal_unconfirmed(context)) out->flags |= BC_MEDIA_REMOVAL_UNCONFIRMED;
    if (state == BC_HUAWEI_MEDIA_STATE_ERROR) out->flags |= BC_MEDIA_FAILED;
    return BC_OK;
}
static void media_destroy(void *context) { bc_huawei_media_destroy(context); }
static const bc_service_profile *media_profile(const void *context) { return bc_huawei_media_profile_get(context); }
bc_status bc_huawei_media_wrap(bc_huawei_media *media, bc_media_session **out) {
    const bc_media_provider provider = {sizeof(provider), NULL, media_session_poll, media_session_control, media_session_info, NULL, media_destroy, media_profile, NULL};
    return bc_media_session_wrap(&provider, media, out);
}

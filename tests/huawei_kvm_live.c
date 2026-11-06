#include "bcontrol/huawei_kvm.h"
#include "bcontrol/kvm_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

/* Manual live smoke client for the native Huawei console. It performs read-only KVM/video/media
 * testing against a device; it can create KVM/Redfish sessions but never sends power or reset
 * commands, and the media source is only ever read. */

typedef struct {
    bc_kvm_transport *transport;
    uint64_t sent_bytes;
} transport_io;

static bc_status io_send(void *user, const uint8_t *data, uint32_t length) {
    transport_io *io = (transport_io *)user;
    bc_status status = bc_kvm_transport_send(io->transport, data, length);
    if (status == BC_OK) io->sent_bytes += length;
    return status;
}

static bc_status io_recv(void *user, uint8_t *data, uint32_t capacity, uint32_t *received, uint32_t timeout_ms) {
    transport_io *io = (transport_io *)user;
    return bc_kvm_transport_recv(io->transport, data, capacity, received, timeout_ms);
}

static uint64_t clock_ms(void *user) {
    (void)user;
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
#endif
}

static int open_transport_headers(transport_io *io, const char *url, const char *cookie) {
    bc_kvm_transport_options options;
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = BC_ABI_VERSION;
    options.timeout_ms = 5000;
    options.cert_policy = BC_CERT_SKIP_ALL;
    options.tls_min = BC_TLS_1_2;
    options.url.data = url;
    options.url.length = strlen(url);
    char header[512];
    bc_string headers[1];
    if (cookie && *cookie) {
        snprintf(header, sizeof(header), "Cookie: %s", cookie);
        headers[0].data = header;
        headers[0].length = strlen(header);
        options.headers = headers;
        options.header_count = 1;
    }
    bc_status status = bc_kvm_transport_connect(&options, &io->transport);
    if (status != BC_OK) {
        fprintf(stderr, "transport connect %s failed: %s\n", url, bc_status_string(status));
        return 0;
    }
    return 1;
}

static int open_transport(transport_io *io, const char *url) {
    return open_transport_headers(io, url, NULL);
}

static uint8_t *read_file(const char *path, uint64_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (size <= 0) { fclose(file); return NULL; }
    uint8_t *data = (uint8_t *)malloc((size_t)size);
    if (!data || fread(data, 1, (size_t)size, file) != (size_t)size) { free(data); fclose(file); return NULL; }
    fclose(file);
    *length = (uint64_t)size;
    return data;
}

typedef struct {
    const uint8_t *data;
    uint64_t size;
} iso_source;

static bc_status iso_read(void *userdata, uint64_t offset, uint32_t length, uint8_t *out) {
    iso_source *source = (iso_source *)userdata;
    if (offset > source->size || length > source->size - offset) return BC_IO_ERROR;
    memcpy(out, source->data + offset, length);
    return BC_OK;
}


/* ---------------------------------------------------------------------------------------------
 * Live input diagnostics (read-only console input; no power/reset/media writes)
 * ------------------------------------------------------------------------------------------- */

typedef struct {
    uint8_t *pixels;
    uint32_t width, height, stride;
} frame_copy;

static int wait_frame(bc_huawei_kvm_session *session, uint32_t timeout_ms, frame_copy *copy) {
    uint64_t deadline = clock_ms(NULL) + timeout_ms;
    while (clock_ms(NULL) < deadline) {
        if (bc_huawei_kvm_session_poll(session, 20) == BC_PROTOCOL_ERROR) return 0;
        bc_huawei_kvm_frame frame;
        memset(&frame, 0, sizeof(frame));
        if (bc_huawei_kvm_session_frame(session, &frame) == BC_OK && frame.pixels) {
            if (copy) {
                free(copy->pixels);
                copy->pixels = (uint8_t *)malloc(frame.pixel_bytes);
                if (copy->pixels) memcpy(copy->pixels, frame.pixels, frame.pixel_bytes);
                copy->width = frame.width; copy->height = frame.height; copy->stride = frame.stride;
            }
            (void)bc_huawei_kvm_session_ack_frame(session);
            return 1;
        }
    }
    return 0;
}

static uint32_t frame_diff(const frame_copy *a, const frame_copy *b) {
    if (!a->pixels || !b->pixels || a->width != b->width || a->height != b->height) return 0;
    uint32_t changed = 0;
    for (uint32_t y = 0; y < a->height; y += 2) {
        for (uint32_t x = 0; x < a->width; x += 2) {
            const uint8_t *pa = a->pixels + (size_t)y * a->stride + (size_t)x * 4;
            const uint8_t *pb = b->pixels + (size_t)y * b->stride + (size_t)x * 4;
            if (memcmp(pa, pb, 3) != 0) ++changed;
        }
    }
    return changed;
}

static void dump_frame(const frame_copy *copy, const char *prefix, const char *name) {
    if (!copy->pixels || !prefix) return;
    char path[512];
    snprintf(path, sizeof(path), "%s_%s.rgba", prefix, name);
    FILE *file = fopen(path, "wb");
    if (!file) return;
    fwrite(copy->pixels, 1, (size_t)copy->stride * copy->height, file);
    fclose(file);
}

static void report_key(bc_huawei_kvm_session *session, uint32_t keysym, const char *label, frame_copy *last,
                       const char *dump_prefix) {
    frame_copy now = {0};
    uint64_t before = 0;
    (void)before;
    int down_ok = bc_huawei_kvm_session_key(session, keysym, 1) == BC_OK;
    int got = wait_frame(session, 700, &now);
    uint32_t changed = got ? frame_diff(last, &now) : 0;
    printf("key %-10s keysym=0x%04x send=%s frames=%d changed=%u\n", label, keysym, down_ok ? "ok" : "ERR",
           got, changed);
    if (dump_prefix && got) dump_frame(&now, dump_prefix, label);
    (void)bc_huawei_kvm_session_key(session, keysym, 0);
    wait_frame(session, 300, NULL);
    frame_copy up = {0};
    if (wait_frame(session, 300, &up)) {
        if (last->pixels) { free(last->pixels); *last = up; }
        else *last = up;
    } else if (got) {
        free(last->pixels); *last = now; now.pixels = NULL;
    }
    free(now.pixels);
}

static void debounce_probe(bc_huawei_kvm_session *session, transport_io *io, frame_copy *last,
                           const char *dump_prefix) {
    printf("debounce: baseline sent_bytes=%llu\n", (unsigned long long)io->sent_bytes);
    uint64_t before = io->sent_bytes;
    (void)bc_huawei_kvm_session_key_usage(session, 0x14, 0, 1); /* 'q' down */
    uint64_t pressed = io->sent_bytes;
    printf("debounce: one press +%llu bytes\n", (unsigned long long)(pressed - before));
    for (int i = 0; i < 5; ++i) (void)bc_huawei_kvm_session_key_usage(session, 0x14, 0, 1);
    printf("debounce: five repeat down events +%llu bytes (expect 0)\n",
           (unsigned long long)(io->sent_bytes - pressed));
    uint64_t repeats = io->sent_bytes;
    (void)bc_huawei_kvm_session_key_usage(session, 0x14, 0, 0);
    printf("debounce: release +%llu bytes\n", (unsigned long long)(io->sent_bytes - repeats));
    uint64_t released = io->sent_bytes;
    (void)bc_huawei_kvm_session_key_usage(session, 0x14, 0, 0);
    printf("debounce: duplicate release +%llu bytes (expect 0)\n",
           (unsigned long long)(io->sent_bytes - released));
    if (wait_frame(session, 700, last) && dump_prefix) dump_frame(last, dump_prefix, "debounce_one_q");
    (void)bc_huawei_kvm_session_key(session, 0xFF08, 1); /* erase test character */
    (void)bc_huawei_kvm_session_key(session, 0xFF08, 0);
    wait_frame(session, 400, last);
    printf("debounce: holding 'w' for 1.2s with no repeat packets\n");
    uint64_t hold_start = io->sent_bytes;
    (void)bc_huawei_kvm_session_key_usage(session, 0x1A, 0, 1); /* 'w' down, held */
    uint64_t deadline = clock_ms(NULL) + 1200;
    while (clock_ms(NULL) < deadline) wait_frame(session, 100, last);
    printf("debounce: packets during hold=%llu\n", (unsigned long long)(io->sent_bytes - hold_start));
    (void)bc_huawei_kvm_session_key_usage(session, 0x1A, 0, 0);
    wait_frame(session, 500, last);
    if (dump_prefix) dump_frame(last, dump_prefix, "debounce_held_w");
    (void)bc_huawei_kvm_session_key(session, 0xFF08, 1);
    (void)bc_huawei_kvm_session_key(session, 0xFF08, 0);
    (void)bc_huawei_kvm_session_key(session, 0xFF0D, 1);
    (void)bc_huawei_kvm_session_key(session, 0xFF0D, 0);
    wait_frame(session, 500, last);
}

static void live_input_diagnostics(bc_huawei_kvm_session *session, transport_io *io, const char *dump_prefix, int mouse_mode) {
    frame_copy last = {0};
    if (!wait_frame(session, 4000, &last)) { printf("input diagnostics: no frame\n"); return; }
    printf("input diagnostics: baseline %ux%u stride=%u\n", last.width, last.height, last.stride);
    /* Focus the console like a user click would; harmless pointer event. */
    (void)bc_huawei_kvm_session_pointer(session, (uint16_t)(last.width / 2), (uint16_t)(last.height / 2), 0);
    wait_frame(session, 400, NULL);
    (void)bc_huawei_kvm_session_pointer(session, (uint16_t)(last.width / 2), (uint16_t)(last.height / 2), 1);
    (void)bc_huawei_kvm_session_pointer(session, (uint16_t)(last.width / 2), (uint16_t)(last.height / 2), 0);
    wait_frame(session, 400, NULL);
    if (dump_prefix) dump_frame(&last, dump_prefix, "00_baseline");
    debounce_probe(session, io, &last, dump_prefix);
    /* Enter creates a new prompt line. */
    report_key(session, 0xFF0D, "enter", &last, dump_prefix);
    /* Type "echo kbd" one key at a time. */
    const struct { uint32_t keysym; const char *label; } word[] = {
        {'e', "e"}, {'c', "c"}, {'h', "h"}, {'o', "o"}, {' ', "space"},
        {'k', "k"}, {'b', "b"}, {'d', "d"}};
    for (size_t i = 0; i < sizeof(word) / sizeof(word[0]); ++i)
        report_key(session, word[i].keysym, word[i].label, &last, dump_prefix);
    printf("input diagnostics: command typed\n");
    /* Enter executes "echo kbd" (harmless). */
    report_key(session, 0xFF0D, "enter_run", &last, dump_prefix);
    /* Backspace over typing. */
    report_key(session, 'x', "x", &last, dump_prefix);
    report_key(session, 'y', "y", &last, dump_prefix);
    report_key(session, 'z', "z", &last, dump_prefix);
    report_key(session, 0xFF08, "backspace1", &last, dump_prefix);
    report_key(session, 0xFF08, "backspace2", &last, dump_prefix);
    report_key(session, 0xFF08, "backspace3", &last, dump_prefix);
    report_key(session, 0xFF0D, "enter_clear", &last, dump_prefix);
    /* Arrow keys: Up recalls the previous command; Ctrl+C discards it. */
    report_key(session, 0xFF52, "arrow_up", &last, dump_prefix);
    (void)bc_huawei_kvm_session_key_usage(session, 0x06, 0x01, 1); /* Ctrl+C */
    (void)bc_huawei_kvm_session_key_usage(session, 0x06, 0x01, 0);
    wait_frame(session, 500, &last);
    report_key(session, 0xFF0D, "enter_after_ctrlc", &last, dump_prefix);
    /* Shift+A through the keysym mapping (uppercase keysym adds implicit shift). */
    report_key(session, 'A', "shift_A", &last, dump_prefix);
    report_key(session, 0xFF08, "backspace_shift", &last, dump_prefix);
    report_key(session, 0xFF0D, "enter_final", &last, dump_prefix);
    printf("input diagnostics: keyboard done; all keys released by session destroy\n");
    if (mouse_mode) {
        printf("mouse: requesting absolute mode\n");
        (void)bc_huawei_kvm_session_mouse_mode(session, 1);
        wait_frame(session, 500, NULL);
        double center_x = last.width / 2.0, center_y = last.height / 2.0;
        frame_copy before = {0};
        if (wait_frame(session, 500, &before)) {
            (void)bc_huawei_kvm_session_pointer(session, (uint16_t)center_x, (uint16_t)center_y, 0);
            frame_copy now = {0};
            if (wait_frame(session, 700, &now)) {
                printf("mouse: move center changed=%u\n", frame_diff(&before, &now));
                (void)bc_huawei_kvm_session_pointer(session, (uint16_t)center_x, (uint16_t)center_y, 1);
                wait_frame(session, 400, &now);
                (void)bc_huawei_kvm_session_pointer(session, (uint16_t)center_x, (uint16_t)center_y, 0);
                wait_frame(session, 400, &now);
                printf("mouse: left button down/up sent; center pixel=%u,%u\n",
                       now.pixels ? now.pixels[(now.stride * (now.height / 2) + now.width / 2 * 4) + 0] : 0,
                       now.pixels ? now.pixels[(now.stride * (now.height / 2) + now.width / 2 * 4) + 2] : 0);
                (void)bc_huawei_kvm_session_pointer(session, (uint16_t)(last.width - 2), (uint16_t)(last.height - 2), 0);
                wait_frame(session, 500, &now);
                printf("mouse: corner move sent\n");
                free(now.pixels);
            } else {
                free(before.pixels);
            }
        }
        (void)bc_huawei_kvm_session_pointer_delta(session, 20, -10, 0);
        wait_frame(session, 400, NULL);
        printf("mouse: relative delta sent\n");
    }
    free(last.pixels);
}

int main(int argc, char **argv) {
    const char *jnlp_path = NULL, *iso_path = NULL, *dump_prefix = NULL, *cookie = NULL;
    int media = 0, input = 0, mouse = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--jnlp") && i + 1 < argc) jnlp_path = argv[++i];
        else if (!strcmp(argv[i], "--vmm") && i + 1 < argc) { iso_path = argv[++i]; media = 1; }
        else if (!strcmp(argv[i], "--keys")) input = 1;
        else if (!strcmp(argv[i], "--mouse")) mouse = 1;
        else if (!strcmp(argv[i], "--dump") && i + 1 < argc) dump_prefix = argv[++i];
        else if (!strcmp(argv[i], "--cookie") && i + 1 < argc) cookie = argv[++i];
    }
    if (!jnlp_path) {
        fprintf(stderr, "usage: %s --jnlp <startup.jnlp> [--vmm <read-only.iso>]\n", argv[0]);
        return 2;
    }
    uint64_t jnlp_length = 0;
    uint8_t *jnlp = read_file(jnlp_path, &jnlp_length);
    if (!jnlp) { fprintf(stderr, "cannot read %s\n", jnlp_path); return 2; }
    bc_huawei_kvm_params params;
    memset(&params, 0, sizeof(params));
    params.struct_size = sizeof(params);
    params.abi_version = BC_ABI_VERSION;
    char error[BC_HUAWEI_ERROR_MAX] = {0};
    bc_status status = bc_huawei_kvm_params_from_jnlp(jnlp, jnlp_length, &params, error, sizeof(error));
    free(jnlp);
    if (status != BC_OK) { fprintf(stderr, "JNLP parse failed: %s\n", error); return 1; }
    printf("params host=%s port=%u vmmPort=%u privilege=%u title=%s\n", params.host, params.port,
           params.vmm_port, params.privilege, params.title);

    transport_io io;
    memset(&io, 0, sizeof(io));
    char url[192];
    snprintf(url, sizeof(url), "wss://%s:%u/websocket", params.host, params.port);
    if (!open_transport_headers(&io, url, cookie)) { bc_kvm_transport_destroy(io.transport); return 1; }
    bc_huawei_io callbacks = {&io, io_send, io_recv};
    uint8_t *framebuffer = (uint8_t *)malloc(1920 * 1200 * 4);
    if (!framebuffer) return 1;
    bc_huawei_kvm_options options;
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = BC_ABI_VERSION;
    options.handshake_timeout_ms = 8000;
    options.heartbeat_interval_ms = 5000;
    options.frame_buffer = framebuffer;
    options.frame_capacity = 1920 * 1200 * 4;
    options.clock = clock_ms;
    options.clock_user = &io;
    bc_huawei_kvm_session *session = NULL;
    status = bc_huawei_kvm_session_create(&params, &callbacks, &options, &session);
    if (status != BC_OK) { fprintf(stderr, "session create: %s\n", bc_status_string(status)); return 1; }
    status = bc_huawei_kvm_session_start(session);
    if (status != BC_OK) {
        char message[BC_HUAWEI_ERROR_MAX] = {0};
        bc_huawei_kvm_session_error(session, message, sizeof(message));
        fprintf(stderr, "session start: %s (%s)\n", bc_status_string(status), message);
        bc_huawei_kvm_session_destroy(session);
        return 1;
    }
    printf("KVM handshake ok, waiting for a frame...\n");
    int frames = 0;
    for (int attempt = 0; attempt < 400; ++attempt) {
        bc_huawei_kvm_session_poll(session, 25);
        bc_huawei_kvm_frame frame;
        if (bc_huawei_kvm_session_frame(session, &frame) == BC_OK) {
            uint64_t checksum = 0;
            uint32_t nonblack = 0;
            for (uint32_t y = 0; y < frame.height; y += 8) {
                for (uint32_t x = 0; x < frame.width; x += 8) {
                    const uint8_t *pixel = frame.pixels + (size_t)y * frame.stride + (size_t)x * 4;
                    checksum += pixel[0] + pixel[1] * 3 + pixel[2] * 7;
                    if (pixel[0] | pixel[1] | pixel[2]) ++nonblack;
                }
            }
            printf("frame %u: %ux%u stride=%u quant=%u key=%u bytes=%u checksum=%llu nonblack=%u\n", frames,
                   frame.width, frame.height, frame.stride, frame.quantization, frame.flags & BC_HUAWEI_FRAME_KEY,
                   frame.pixel_bytes, (unsigned long long)checksum, nonblack);
            if (frames == 0) {
                FILE *raw = fopen("build-huawei/frame.rgba", "wb");
                if (raw) { fwrite(frame.pixels, 1, frame.pixel_bytes, raw); fclose(raw); }
            }
            ++frames;
            bc_huawei_kvm_session_ack_frame(session);
            if (frames >= 3) break;
        }
    }
    bc_huawei_kvm_stats stats;
    memset(&stats, 0, sizeof(stats));
    stats.struct_size = sizeof(stats);
    stats.abi_version = BC_ABI_VERSION;
    bc_huawei_kvm_session_stats(session, &stats);
    printf("stats bytes=%llu imagePackets=%u decodedFrames=%u heartbeats=%u\n",
           (unsigned long long)stats.received_bytes, stats.image_packets, stats.decoded_frames, stats.heartbeats);

    if (input || mouse) live_input_diagnostics(session, &io, dump_prefix, mouse);

    if (media) {
        uint64_t iso_length = 0;
        uint8_t *iso = read_file(iso_path, &iso_length);
        if (!iso) { fprintf(stderr, "cannot read ISO %s\n", iso_path); return 1; }
        iso_source source = {iso, iso_length};
        status = bc_huawei_kvm_session_vmm_request(session);
        bc_huawei_vmm_info vmm;
        memset(&vmm, 0, sizeof(vmm));
        for (int attempt = 0; attempt < 200 && status == BC_OK; ++attempt) {
            bc_huawei_kvm_session_poll(session, 25);
            if (bc_huawei_kvm_session_vmm_info(session, &vmm) == BC_OK) break;
        }
        if (vmm.struct_size == 0) {
            fprintf(stderr, "VMM credentials not available\n");
        } else {
            printf("VMM state=%u port=%u\n", vmm.state, vmm.port);
            if (vmm.state == BC_HUAWEI_VMM_STATE_ENABLED && vmm.port) {
                transport_io media_io;
                memset(&media_io, 0, sizeof(media_io));
                snprintf(url, sizeof(url), "wss://%s:%u/websocket", params.host, vmm.port);
                if (open_transport(&media_io, url)) {
                    bc_huawei_io media_callbacks = {&media_io, io_send, io_recv};
                    bc_huawei_vmm_source block_source;
                    memset(&block_source, 0, sizeof(block_source));
                    block_source.struct_size = sizeof(block_source);
                    block_source.userdata = &source;
                    block_source.size = iso_length;
                    block_source.read = iso_read;
                    bc_huawei_media_options media_options;
                    memset(&media_options, 0, sizeof(media_options));
                    media_options.struct_size = sizeof(media_options);
                    media_options.abi_version = BC_ABI_VERSION;
                    media_options.info = &vmm;
                    media_options.source = &block_source;
                    media_options.timeout_ms = 5000;
                    media_options.clock = clock_ms;
                    media_options.clock_user = &media_io;
                    bc_huawei_media *media_session = NULL;
                    status = bc_huawei_media_create(&media_options, &media_callbacks, &media_session);
                    if (status == BC_OK) status = bc_huawei_media_connect(media_session);
                    if (status == BC_OK) {
                        printf("virtual CD-ROM opened read-only (ISO %llu bytes)\n", (unsigned long long)iso_length);
                        for (int attempt = 0; attempt < 120; ++attempt) bc_huawei_media_poll(media_session, 25);
                        bc_huawei_media_statistics media_stats;
                        memset(&media_stats, 0, sizeof(media_stats));
                        media_stats.struct_size = sizeof(media_stats);
                        media_stats.abi_version = BC_ABI_VERSION;
                        bc_huawei_media_stats(media_session, &media_stats);
                        printf("media commands=%u bytesRead=%llu heartbeats=%u sense=%u/%02x/%02x\n",
                               media_stats.commands, (unsigned long long)media_stats.bytes_read,
                               media_stats.heartbeats, media_stats.sense_key, media_stats.asc, media_stats.ascq);
                        bc_huawei_media_close(media_session);
                    } else {
                        char message[BC_HUAWEI_ERROR_MAX] = {0};
                        if (media_session) bc_huawei_media_error(media_session, message, sizeof(message));
                        fprintf(stderr, "media open failed: %s (%s)\n", bc_status_string(status), message);
                    }
                    bc_huawei_media_destroy(media_session);
                    bc_kvm_transport_destroy(media_io.transport);
                }
            }
        }
        free(iso);
    }

    bc_huawei_kvm_session_destroy(session);
    bc_kvm_transport_destroy(io.transport);
    free(framebuffer);
    return frames > 0 ? 0 : 1;
}

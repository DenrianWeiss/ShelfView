#define _POSIX_C_SOURCE 200809L
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
int bc_agent_private_file(const char *path, const char *data, size_t length) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (!n || length > MAXDWORD) return 0;
    wchar_t *name = malloc((size_t)n * sizeof(*name));
    if (!name) return 0;
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, name, n);
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)", SDDL_REVISION_1, &descriptor, NULL)) { free(name); return 0; }
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), descriptor, FALSE};
    HANDLE file = CreateFileW(name, GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    LocalFree(descriptor);
    DWORD written = 0;
    int ok = file != INVALID_HANDLE_VALUE && WriteFile(file, data, (DWORD)length, &written, NULL) && written == length;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (!ok && file != INVALID_HANDLE_VALUE) DeleteFileW(name);
    free(name); return ok;
}
uint64_t bc_agent_now_ms(void) { return GetTickCount64(); }
void bc_agent_sleep(uint32_t ms) { Sleep(ms); }
#else
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
int bc_agent_private_file(const char *path, const char *data, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 0;
    size_t done = 0;
    while (done < length) {
        ssize_t n = write(fd, data + done, length - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        done += (size_t)n;
    }
    int ok = close(fd) == 0 && done == length;
    if (!ok) unlink(path);
    return ok;
}
uint64_t bc_agent_now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
void bc_agent_sleep(uint32_t ms) {
    struct timespec t = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
#endif

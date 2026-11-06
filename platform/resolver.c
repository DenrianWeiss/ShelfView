#define _POSIX_C_SOURCE 200809L
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#endif
#include "resolver.h"
#include "monotonic.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    char host[256], service[8];
    struct addrinfo hints, *addresses;
    unsigned references, slot;
    int done, error, abandoned;
} resolve_job;
static resolve_job *pending[16];
#ifdef _WIN32
static SRWLOCK gate = SRWLOCK_INIT;
static void lock(void) { AcquireSRWLockExclusive(&gate); }
static void unlock(void) { ReleaseSRWLockExclusive(&gate); }
#else
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static void lock(void) { pthread_mutex_lock(&gate); }
static void unlock(void) { pthread_mutex_unlock(&gate); }
#endif
static void release_job(resolve_job *job) {
    lock();
    int destroy = --job->references == 0;
    unlock();
    if (destroy) {
        if (job->addresses) freeaddrinfo(job->addresses);
        free(job);
    }
}
#ifdef _WIN32
static DWORD WINAPI resolve(void *argument) {
#else
static void *resolve(void *argument) {
#endif
    resolve_job *job = argument;
    struct addrinfo *addresses = NULL;
#ifdef _WIN32
    WSADATA data;
    int started = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    int error = started ? getaddrinfo(job->host, job->service, &job->hints, &addresses) : EAI_FAIL;
#else
    int error = getaddrinfo(job->host, job->service, &job->hints, &addresses);
#endif
    lock();
    job->addresses = addresses; job->error = error; job->done = 1;
    pending[job->slot] = NULL;
    unlock();
    release_job(job);
#ifdef _WIN32
    if (started) WSACleanup();
    return 0;
#else
    return NULL;
#endif
}
bc_status bc_net_resolve(const char *host, const char *service, const struct addrinfo *hints,
    uint32_t timeout, struct addrinfo **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    if (!host || !service || !hints || !timeout || !*host || strlen(host) >= 256 ||
        !*service || strlen(service) >= 8 || hints->ai_addr || hints->ai_canonname || hints->ai_next)
        return BC_INVALID_ARGUMENT;
    uint64_t started = bc_monotonic_ms();
    struct addrinfo numeric = *hints;
    numeric.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
    if (!getaddrinfo(host, service, &numeric, out)) return BC_OK;
    resolve_job *job = calloc(1, sizeof(*job));
    if (!job) return BC_NO_MEMORY;
    strcpy(job->host, host); strcpy(job->service, service); job->hints = *hints;
    job->hints.ai_flags |= AI_NUMERICSERV;
    job->references = 2;
    lock();
    unsigned slot = 16;
    for (unsigned i = 0; i < 16; i++) {
        if (!pending[i]) slot = i;
        else if (pending[i]->abandoned && !strcmp(pending[i]->host, host)) {
            unlock(); free(job); return BC_BUSY;
        }
    }
    if (slot == 16) { unlock(); free(job); return BC_BUSY; }
    job->slot = slot; pending[slot] = job;
    unlock();
#ifdef _WIN32
    HANDLE thread = CreateThread(NULL, 0, resolve, job, 0, NULL);
    int created = thread != NULL;
    if (thread) CloseHandle(thread);
#else
    pthread_t thread;
    pthread_attr_t attributes;
    int created = 0;
    if (!pthread_attr_init(&attributes)) {
        if (!pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED))
            created = pthread_create(&thread, &attributes, resolve, job) == 0;
        pthread_attr_destroy(&attributes);
    }
#endif
    if (!created) {
        lock(); pending[job->slot] = NULL; unlock(); free(job); return BC_IO_ERROR;
    }
    bc_status status;
    for (;;) {
        uint64_t now = bc_monotonic_ms();
        if (now < started || now - started >= timeout) { status = BC_TIMEOUT; break; }
        lock();
        int done = job->done;
        if (done) {
            status = job->error ? BC_IO_ERROR : BC_OK;
            if (status == BC_OK) { *out = job->addresses; job->addresses = NULL; }
        }
        unlock();
        if (done) break;
        uint32_t delay = timeout - (uint32_t)(now - started);
        if (delay > 5) delay = 5;
#ifdef _WIN32
        Sleep(delay);
#else
        struct timespec interval = {0, (long)delay * 1000000};
        nanosleep(&interval, NULL);
#endif
    }
    lock(); job->abandoned = 1; unlock();
    release_job(job);
    return status;
}

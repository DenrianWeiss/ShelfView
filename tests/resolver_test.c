#define _POSIX_C_SOURCE 200809L
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
static pthread_mutex_t fixture_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fixture_ready = PTHREAD_COND_INITIALIZER;
static int released;
static atomic_uint freed;
static int fake_resolve(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **out) {
    (void)host; (void)service;
    if (hints->ai_flags & AI_NUMERICHOST) return EAI_NONAME;
    pthread_mutex_lock(&fixture_lock);
    while (!released) pthread_cond_wait(&fixture_ready, &fixture_lock);
    pthread_mutex_unlock(&fixture_lock);
    *out = calloc(1, sizeof(**out));
    return *out ? 0 : EAI_MEMORY;
}
static void fake_free(struct addrinfo *value) { free(value); atomic_fetch_add(&freed, 1); }
#define getaddrinfo fake_resolve
#define freeaddrinfo fake_free
#include "../platform/resolver.c"

int main(void) {
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_socktype = SOCK_STREAM;
    for (unsigned i = 0; i < 16; i++) {
        char host[32]; snprintf(host, sizeof(host), "blocked-%u.test", i);
        assert(bc_net_resolve(host, "443", &hints, 5, &result) == BC_TIMEOUT);
        assert(!result);
        assert(bc_net_resolve(host, "443", &hints, 5, &result) == BC_BUSY);
    }
    assert(bc_net_resolve("blocked.test", "443", &hints, 5, &result) == BC_BUSY);
    pthread_mutex_lock(&fixture_lock);
    released = 1;
    pthread_cond_broadcast(&fixture_ready);
    pthread_mutex_unlock(&fixture_lock);
    uint64_t until = bc_monotonic_ms() + 2000;
    while (atomic_load(&freed) != 16 && bc_monotonic_ms() < until) {
        struct timespec interval = {0, 1000000}; nanosleep(&interval, NULL);
    }
    assert(atomic_load(&freed) == 16);
    assert(bc_net_resolve("ready.test", "443", &hints, 1000, &result) == BC_OK);
    assert(result); fake_free(result);
    assert(atomic_load(&freed) == 17);
    return 0;
}

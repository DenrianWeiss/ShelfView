#ifndef BC_PLATFORM_MUTEX_H
#define BC_PLATFORM_MUTEX_H
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
typedef SRWLOCK bc_mutex;
#define BC_MUTEX_INITIALIZER SRWLOCK_INIT
static inline void bc_mutex_init(bc_mutex *m) { InitializeSRWLock(m); }
static inline void bc_mutex_lock(bc_mutex *m) { AcquireSRWLockExclusive(m); }
static inline void bc_mutex_unlock(bc_mutex *m) { ReleaseSRWLockExclusive(m); }
static inline void bc_mutex_destroy(bc_mutex *m) { (void)m; }
#else
#include <pthread.h>
typedef pthread_mutex_t bc_mutex;
#define BC_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
static inline void bc_mutex_init(bc_mutex *m) { pthread_mutex_init(m,NULL); }
static inline void bc_mutex_lock(bc_mutex *m) { pthread_mutex_lock(m); }
static inline void bc_mutex_unlock(bc_mutex *m) { pthread_mutex_unlock(m); }
static inline void bc_mutex_destroy(bc_mutex *m) { pthread_mutex_destroy(m); }
#endif
#endif

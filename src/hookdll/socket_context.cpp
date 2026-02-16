/*
 * ProxyFire - socket_context.cpp
 * Per-socket state tracking
 */

#include "socket_context.h"
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

namespace proxyfire {

#ifdef _WIN32
static SRWLOCK g_ctx_lock = SRWLOCK_INIT;
#define CTX_LOCK_READ()    AcquireSRWLockShared(&g_ctx_lock)
#define CTX_UNLOCK_READ()  ReleaseSRWLockShared(&g_ctx_lock)
#define CTX_LOCK_WRITE()   AcquireSRWLockExclusive(&g_ctx_lock)
#define CTX_UNLOCK_WRITE() ReleaseSRWLockExclusive(&g_ctx_lock)
#else
static pthread_rwlock_t g_ctx_lock = PTHREAD_RWLOCK_INITIALIZER;
#define CTX_LOCK_READ()    pthread_rwlock_rdlock(&g_ctx_lock)
#define CTX_UNLOCK_READ()  pthread_rwlock_unlock(&g_ctx_lock)
#define CTX_LOCK_WRITE()   pthread_rwlock_wrlock(&g_ctx_lock)
#define CTX_UNLOCK_WRITE() pthread_rwlock_unlock(&g_ctx_lock)
#endif

static std::unordered_map<SOCKET, SocketCtx>* g_socket_map = nullptr;

void socket_ctx_init() {
    CTX_LOCK_WRITE();
    if (!g_socket_map) {
        g_socket_map = new std::unordered_map<SOCKET, SocketCtx>();
    }
    CTX_UNLOCK_WRITE();
}

void socket_ctx_add(SOCKET sock, uint32_t dest_ip, uint16_t dest_port,
                    const char* hostname, bool proxied) {
    SocketCtx ctx = {};
    ctx.sock = sock;
    ctx.proxied = proxied;
    ctx.orig_dest_ip = dest_ip;
    ctx.orig_dest_port = dest_port;
    if (hostname) ctx.hostname = hostname;
#ifdef _WIN32
    ctx.thread_id = GetCurrentThreadId();
#endif
    ctx.bytes_sent = 0;
    ctx.bytes_recv = 0;
    ctx.is_blocking = true;

    CTX_LOCK_WRITE();
    if (g_socket_map) {
        (*g_socket_map)[sock] = ctx;
    }
    CTX_UNLOCK_WRITE();
}

SocketCtx* socket_ctx_get(SOCKET sock) {
    CTX_LOCK_READ();
    if (g_socket_map) {
        auto it = g_socket_map->find(sock);
        if (it != g_socket_map->end()) {
            SocketCtx* result = &it->second;
            CTX_UNLOCK_READ();
            return result;
        }
    }
    CTX_UNLOCK_READ();
    return nullptr;
}

void socket_ctx_add_sent(SOCKET sock, uint64_t bytes) {
    CTX_LOCK_WRITE();
    if (g_socket_map) {
        auto it = g_socket_map->find(sock);
        if (it != g_socket_map->end()) {
            it->second.bytes_sent += bytes;
        }
    }
    CTX_UNLOCK_WRITE();
}

void socket_ctx_add_recv(SOCKET sock, uint64_t bytes) {
    CTX_LOCK_WRITE();
    if (g_socket_map) {
        auto it = g_socket_map->find(sock);
        if (it != g_socket_map->end()) {
            it->second.bytes_recv += bytes;
        }
    }
    CTX_UNLOCK_WRITE();
}

void socket_ctx_remove(SOCKET sock) {
    CTX_LOCK_WRITE();
    if (g_socket_map) {
        g_socket_map->erase(sock);
    }
    CTX_UNLOCK_WRITE();
}

void socket_ctx_cleanup() {
    CTX_LOCK_WRITE();
    if (g_socket_map) {
        delete g_socket_map;
        g_socket_map = nullptr;
    }
    CTX_UNLOCK_WRITE();
}

uint32_t socket_ctx_count() {
    CTX_LOCK_READ();
    uint32_t count = g_socket_map ? (uint32_t)g_socket_map->size() : 0;
    CTX_UNLOCK_READ();
    return count;
}

} // namespace proxyfire

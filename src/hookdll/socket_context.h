/*
 * ProxyFire - socket_context.h
 * Per-socket state tracking (thread-safe)
 */

#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
typedef int SOCKET;
#endif

#include <cstdint>
#include <string>

namespace proxyfire {

struct SocketCtx {
    SOCKET      sock;
    bool        proxied;            /* Whether this socket goes through proxy */
    uint32_t    orig_dest_ip;       /* Original destination IP (network order) */
    uint16_t    orig_dest_port;     /* Original destination port (host order) */
    std::string hostname;           /* Resolved hostname (from DNS faker) */
    uint32_t    thread_id;          /* Thread that created the connection */
    uint64_t    bytes_sent;         /* Total bytes sent */
    uint64_t    bytes_recv;         /* Total bytes received */
    bool        is_blocking;        /* Original blocking state */
};

/**
 * Initialize the socket context tracking system.
 */
void socket_ctx_init();

/**
 * Register a socket that is being proxied.
 */
void socket_ctx_add(SOCKET sock, uint32_t dest_ip, uint16_t dest_port,
                    const char* hostname, bool proxied);

/**
 * Get context for a socket. Returns nullptr if not tracked.
 */
SocketCtx* socket_ctx_get(SOCKET sock);

/**
 * Update byte counters.
 */
void socket_ctx_add_sent(SOCKET sock, uint64_t bytes);
void socket_ctx_add_recv(SOCKET sock, uint64_t bytes);

/**
 * Remove a socket from tracking (on close).
 */
void socket_ctx_remove(SOCKET sock);

/**
 * Cleanup all tracked sockets.
 */
void socket_ctx_cleanup();

/**
 * Get count of tracked sockets (diagnostics).
 */
uint32_t socket_ctx_count();

} // namespace proxyfire

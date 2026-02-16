/*
 * ProxyFire - hook_udp.cpp
 * UDP traffic interception and SOCKS5 UDP ASSOCIATE relay
 *
 * Hooks sendto(), WSASendTo(), recvfrom(), and WSARecvFrom() to either:
 *
 * 1. SOCKS5 proxy available: relay ALL UDP traffic through the SOCKS5
 *    proxy using UDP ASSOCIATE (RFC 1928 Section 7). Each application
 *    UDP socket gets a transparent relay session.
 *
 * 2. Non-SOCKS5 proxy (HTTP/SOCKS4): block DNS UDP (port 53) only
 *    to prevent DNS leaks. Other UDP traffic passes through unchanged.
 *
 * The SOCKS5 UDP relay flow:
 *   - On first sendto() for a socket, establish a UDP ASSOCIATE session
 *   - Encapsulate outgoing datagrams with a SOCKS5 UDP header
 *   - Send encapsulated datagrams to the proxy's relay endpoint
 *   - On recvfrom(), receive from the relay and strip the SOCKS5 header
 */

#include "hook_udp.h"
#include "udp_relay.h"
#include "ipc_client.h"

#include <proxyfire/config.h>
#include <proxyfire/proxy_types.h>
#include <proxyfire/common.h>

#include <cstring>
#include <cstdio>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

/* Global config - set during DLL init */
extern ProxyFireConfig g_config;

/* Original function pointers - sendto/WSASendTo */
int (WSAAPI *Original_sendto)(SOCKET, const char*, int, int,
     const struct sockaddr*, int) = nullptr;
int (WSAAPI *Original_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
     const struct sockaddr*, int, LPWSAOVERLAPPED,
     LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;

/* Original function pointers - recvfrom/WSARecvFrom */
int (WSAAPI *Original_recvfrom)(SOCKET, char*, int, int,
     struct sockaddr*, int*) = nullptr;
int (WSAAPI *Original_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
     struct sockaddr*, LPINT, LPWSAOVERLAPPED,
     LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;

namespace proxyfire {

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * Check if the destination sockaddr targets DNS port 53.
 * Supports both IPv4 (AF_INET) and IPv6 (AF_INET6).
 * Returns true if the destination port is 53.
 */
static bool is_dns_port(const struct sockaddr* addr, int addrlen) {
    if (!addr) return false;

    if (addr->sa_family == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
        return ntohs(sin->sin_port) == 53;
    }

    if (addr->sa_family == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)addr;
        return ntohs(sin6->sin6_port) == 53;
    }

    return false;
}

/*
 * Format destination address as a string for logging.
 */
static void format_dest_addr(const struct sockaddr* addr, char* buf, size_t buflen) {
    if (!addr || buflen == 0) {
        if (buflen > 0) buf[0] = '\0';
        return;
    }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        _snprintf_s(buf, buflen, _TRUNCATE, "%s:%u", ip, ntohs(sin->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        _snprintf_s(buf, buflen, _TRUNCATE, "[%s]:%u", ip, ntohs(sin6->sin6_port));
    } else {
        _snprintf_s(buf, buflen, _TRUNCATE, "<unknown af=%d>", addr->sa_family);
    }
}

/*
 * Check if the first proxy in the chain is SOCKS5.
 */
static bool is_socks5_proxy_available() {
    return (g_config.proxy_count > 0 &&
            g_config.proxies[0].proto == PROXY_SOCKS5);
}

/* ------------------------------------------------------------------ */
/* Hooked sendto()                                                     */
/* ------------------------------------------------------------------ */
int WSAAPI Hooked_sendto(SOCKET s, const char* buf, int len, int flags,
                          const struct sockaddr* to, int tolen)
{
    /* If SOCKS5 proxy available, relay all UDP through it */
    if (is_socks5_proxy_available()) {
        UdpRelaySession* session = udp_relay_get_or_create(s);
        if (session) {
            int result = udp_relay_sendto(session, buf, len, to, tolen);
            if (result != SOCKET_ERROR) {
                return result;
            }
            /* If relay fails, log and fall through to original for non-DNS,
             * or block for DNS to prevent leaks */
            int relay_err = WSAGetLastError();
            ipc_client_log(PF_LOG_WARN,
                           "UDP relay sendto() failed, error %d", relay_err);
            WSASetLastError(relay_err);
        }

        /* If relay session creation failed and this is DNS, block it */
        if (is_dns_port(to, tolen)) {
            char dest[128];
            format_dest_addr(to, dest, sizeof(dest));
            ipc_client_log(PF_LOG_WARN,
                           "DNS leak prevented: blocked UDP DNS to %s (relay unavailable)",
                           dest);
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }

        /* Non-DNS UDP when relay failed: pass through */
        return Original_sendto(s, buf, len, flags, to, tolen);
    }

    /* Non-SOCKS5 proxy: block DNS UDP only (DNS leak prevention) */
    if (g_config.dns_leak_prevention && is_dns_port(to, tolen)) {
        char dest[128];
        format_dest_addr(to, dest, sizeof(dest));

        ipc_client_log(PF_LOG_DEBUG,
                       "Blocked UDP DNS query via sendto() to %s (%d bytes)",
                       dest, len);
        ipc_client_log(PF_LOG_WARN,
                       "DNS leak prevented: blocked direct UDP DNS to %s", dest);

        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }

    /* Allow all non-DNS UDP traffic through */
    return Original_sendto(s, buf, len, flags, to, tolen);
}

/* ------------------------------------------------------------------ */
/* Hooked WSASendTo()                                                  */
/* ------------------------------------------------------------------ */
int WSAAPI Hooked_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                             LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                             const struct sockaddr* lpTo, int iTolen,
                             LPWSAOVERLAPPED lpOverlapped,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    /* If SOCKS5 proxy available, relay all UDP through it */
    if (is_socks5_proxy_available()) {
        /*
         * WSASendTo uses scatter-gather buffers. We need to flatten them
         * into a single contiguous buffer for the relay.
         *
         * For overlapped I/O, we cannot easily use the relay (which is
         * synchronous). Fall through to blocking relay for non-overlapped,
         * and pass through for overlapped calls.
         */
        if (lpOverlapped) {
            /* Overlapped WSASendTo - we can't easily relay this asynchronously.
             * Block DNS to prevent leaks; pass through other UDP. */
            if (is_dns_port(lpTo, iTolen)) {
                char dest[128];
                format_dest_addr(lpTo, dest, sizeof(dest));
                ipc_client_log(PF_LOG_WARN,
                               "DNS leak prevented: blocked async UDP DNS to %s", dest);
                WSASetLastError(WSAECONNREFUSED);
                return SOCKET_ERROR;
            }
            return Original_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                                       dwFlags, lpTo, iTolen, lpOverlapped,
                                       lpCompletionRoutine);
        }

        /* Calculate total buffer size */
        DWORD total_len = 0;
        for (DWORD i = 0; i < dwBufferCount; i++) {
            total_len += lpBuffers[i].len;
        }

        if (total_len == 0) {
            if (lpNumberOfBytesSent) *lpNumberOfBytesSent = 0;
            return 0;
        }

        /* Flatten scatter-gather buffers into a single contiguous buffer */
        char stack_buf[2048];
        char* flat_buf = (total_len <= sizeof(stack_buf))
                         ? stack_buf : new char[total_len];

        DWORD offset = 0;
        for (DWORD i = 0; i < dwBufferCount; i++) {
            if (lpBuffers[i].len > 0 && lpBuffers[i].buf) {
                memcpy(flat_buf + offset, lpBuffers[i].buf, lpBuffers[i].len);
                offset += lpBuffers[i].len;
            }
        }

        UdpRelaySession* session = udp_relay_get_or_create(s);
        if (session) {
            int result = udp_relay_sendto(session, flat_buf, (int)total_len, lpTo, iTolen);

            if (flat_buf != stack_buf) delete[] flat_buf;

            if (result != SOCKET_ERROR) {
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = (DWORD)result;
                return 0;
            }

            int relay_err = WSAGetLastError();
            ipc_client_log(PF_LOG_WARN,
                           "UDP relay WSASendTo() failed, error %d", relay_err);
            WSASetLastError(relay_err);
        } else {
            if (flat_buf != stack_buf) delete[] flat_buf;
        }

        /* Relay failed: block DNS, pass through other */
        if (is_dns_port(lpTo, iTolen)) {
            char dest[128];
            format_dest_addr(lpTo, dest, sizeof(dest));
            ipc_client_log(PF_LOG_WARN,
                           "DNS leak prevented: blocked UDP DNS to %s (relay unavailable)",
                           dest);
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }

        return Original_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                                   dwFlags, lpTo, iTolen, lpOverlapped,
                                   lpCompletionRoutine);
    }

    /* Non-SOCKS5 proxy: block DNS UDP only */
    if (g_config.dns_leak_prevention && is_dns_port(lpTo, iTolen)) {
        DWORD total_len = 0;
        for (DWORD i = 0; i < dwBufferCount; i++) {
            total_len += lpBuffers[i].len;
        }

        char dest[128];
        format_dest_addr(lpTo, dest, sizeof(dest));

        ipc_client_log(PF_LOG_DEBUG,
                       "Blocked UDP DNS query via WSASendTo() to %s (%lu bytes)",
                       dest, (unsigned long)total_len);
        ipc_client_log(PF_LOG_WARN,
                       "DNS leak prevented: blocked direct UDP DNS to %s", dest);

        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }

    /* Allow all non-DNS UDP traffic through */
    return Original_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                               dwFlags, lpTo, iTolen, lpOverlapped,
                               lpCompletionRoutine);
}

/* ------------------------------------------------------------------ */
/* Hooked recvfrom()                                                   */
/* ------------------------------------------------------------------ */
int WSAAPI Hooked_recvfrom(SOCKET s, char* buf, int len, int flags,
                            struct sockaddr* from, int* fromlen)
{
    /* If a relay session exists for this socket, receive through the relay.
     * Use udp_relay_get() (not get_or_create) since recvfrom should never
     * initiate a new UDP ASSOCIATE handshake. */
    if (is_socks5_proxy_available()) {
        UdpRelaySession* session = udp_relay_get(s);
        if (session) {
            int result = udp_relay_recvfrom(session, buf, len, from, fromlen);
            if (result != SOCKET_ERROR) {
                return result;
            }
            /* On relay failure, fall through to original */
            int err = WSAGetLastError();
            ipc_client_log(PF_LOG_WARN,
                           "UDP relay recvfrom() failed, error %d", err);
            WSASetLastError(err);
        }
    }

    /* No relay session or relay failed: pass through to original */
    return Original_recvfrom(s, buf, len, flags, from, fromlen);
}

/* ------------------------------------------------------------------ */
/* Hooked WSARecvFrom()                                                */
/* ------------------------------------------------------------------ */
int WSAAPI Hooked_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                               LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
                               struct sockaddr* lpFrom, LPINT lpFromlen,
                               LPWSAOVERLAPPED lpOverlapped,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    /* If a relay session exists for this socket, receive through the relay.
     * Only handle non-overlapped (synchronous) calls through the relay.
     * Use udp_relay_get() (not get_or_create) since recvfrom should never
     * initiate a new UDP ASSOCIATE handshake. */
    if (!lpOverlapped && is_socks5_proxy_available()) {
        UdpRelaySession* session = udp_relay_get(s);
        if (session && dwBufferCount > 0 && lpBuffers && lpBuffers[0].buf) {
            int from_len = (lpFromlen) ? *lpFromlen : 0;
            int result = udp_relay_recvfrom(session,
                                             lpBuffers[0].buf,
                                             (int)lpBuffers[0].len,
                                             lpFrom, &from_len);
            if (result != SOCKET_ERROR) {
                if (lpFromlen) *lpFromlen = from_len;
                if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = (DWORD)result;
                if (lpFlags) *lpFlags = 0;
                return 0;
            }

            int err = WSAGetLastError();
            ipc_client_log(PF_LOG_WARN,
                           "UDP relay WSARecvFrom() failed, error %d", err);
            WSASetLastError(err);
        }
    }

    /* No relay session, overlapped I/O, or relay failed: pass through */
    return Original_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                                 lpFlags, lpFrom, lpFromlen, lpOverlapped,
                                 lpCompletionRoutine);
}

} // namespace proxyfire

#endif /* _WIN32 */

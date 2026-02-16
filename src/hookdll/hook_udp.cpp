/*
 * ProxyFire - hook_udp.cpp
 * UDP traffic interception for DNS leak prevention
 *
 * Hooks sendto() and WSASendTo() to block UDP DNS queries (port 53)
 * when DNS leak prevention is enabled. This closes the last remaining
 * DNS leak vector: applications that bypass getaddrinfo/gethostbyname
 * and send raw UDP DNS queries directly.
 *
 * Non-DNS UDP traffic is always allowed through unchanged.
 */

#include "hook_udp.h"
#include "ipc_client.h"

#include <proxyfire/config.h>
#include <proxyfire/common.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

/* Global config - set during DLL init */
extern proxyfire::ProxyFireConfig g_config;

/* Original function pointers */
int (WSAAPI *Original_sendto)(SOCKET, const char*, int, int,
     const struct sockaddr*, int) = nullptr;
int (WSAAPI *Original_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
     const struct sockaddr*, int, LPWSAOVERLAPPED,
     LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;

namespace proxyfire {

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
 * Hooked sendto()
 *
 * Intercepts UDP sendto() calls. If DNS leak prevention is enabled and
 * the destination is port 53 (DNS), the call is blocked with
 * WSAECONNREFUSED. All other traffic passes through to the original.
 */
int WSAAPI Hooked_sendto(SOCKET s, const char* buf, int len, int flags,
                          const struct sockaddr* to, int tolen)
{
    /* Pass through if DNS leak prevention is disabled */
    if (!g_config.dns_leak_prevention) {
        return Original_sendto(s, buf, len, flags, to, tolen);
    }

    /* Check if destination is DNS port 53 */
    if (is_dns_port(to, tolen)) {
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

/*
 * Hooked WSASendTo()
 *
 * Intercepts WSASendTo() calls (the overlapped/scatter-gather variant).
 * Same logic as sendto(): block DNS port 53, allow everything else.
 */
int WSAAPI Hooked_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                             LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                             const struct sockaddr* lpTo, int iTolen,
                             LPWSAOVERLAPPED lpOverlapped,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    /* Pass through if DNS leak prevention is disabled */
    if (!g_config.dns_leak_prevention) {
        return Original_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                                   dwFlags, lpTo, iTolen, lpOverlapped,
                                   lpCompletionRoutine);
    }

    /* Check if destination is DNS port 53 */
    if (is_dns_port(lpTo, iTolen)) {
        /* Calculate total buffer size for logging */
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

} // namespace proxyfire

#endif /* _WIN32 */

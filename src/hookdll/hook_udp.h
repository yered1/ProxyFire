/*
 * ProxyFire - hook_udp.h
 * UDP traffic interception and SOCKS5 UDP ASSOCIATE relay
 *
 * When the first proxy in the chain is SOCKS5, all UDP traffic is relayed
 * through the proxy using UDP ASSOCIATE (RFC 1928 Section 7).
 *
 * When the first proxy is not SOCKS5 (HTTP/SOCKS4), only DNS UDP (port 53)
 * is blocked to prevent DNS leaks. Other UDP traffic passes through unchanged.
 *
 * Hooks: sendto, WSASendTo, recvfrom, WSARecvFrom
 */

#pragma once

#ifdef _WIN32
#include <winsock2.h>

namespace proxyfire {

/* Hooked send functions */
int WSAAPI Hooked_sendto(SOCKET s, const char* buf, int len, int flags,
                          const struct sockaddr* to, int tolen);
int WSAAPI Hooked_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                             LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                             const struct sockaddr* lpTo, int iTolen,
                             LPWSAOVERLAPPED lpOverlapped,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

/* Hooked receive functions */
int WSAAPI Hooked_recvfrom(SOCKET s, char* buf, int len, int flags,
                            struct sockaddr* from, int* fromlen);
int WSAAPI Hooked_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                               LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
                               struct sockaddr* lpFrom, LPINT lpFromlen,
                               LPWSAOVERLAPPED lpOverlapped,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

} // namespace proxyfire

#endif

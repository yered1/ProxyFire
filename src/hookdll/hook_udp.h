/*
 * ProxyFire - hook_udp.h
 * UDP traffic interception for DNS leak prevention
 *
 * Blocks UDP traffic to port 53 (DNS) when DNS leak prevention is enabled.
 * Other UDP traffic is allowed through (we can't proxy UDP without SOCKS5
 * UDP ASSOCIATE, which most proxies don't support).
 */

#pragma once

#ifdef _WIN32
#include <winsock2.h>

namespace proxyfire {

int WSAAPI Hooked_sendto(SOCKET s, const char* buf, int len, int flags,
                          const struct sockaddr* to, int tolen);
int WSAAPI Hooked_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                             LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                             const struct sockaddr* lpTo, int iTolen,
                             LPWSAOVERLAPPED lpOverlapped,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

} // namespace proxyfire

#endif

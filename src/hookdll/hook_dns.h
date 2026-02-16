/*
 * ProxyFire - hook_dns.h
 * Hooked DNS resolution functions for DNS leak prevention
 */

#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

namespace proxyfire {

/* Hooked DNS function declarations */
int WSAAPI Hooked_getaddrinfo(const char* pNodeName, const char* pServiceName,
                               const struct addrinfo* pHints, struct addrinfo** ppResult);

int WSAAPI Hooked_GetAddrInfoW(const wchar_t* pNodeName, const wchar_t* pServiceName,
                                const ADDRINFOW* pHints, ADDRINFOW** ppResult);

struct hostent* WSAAPI Hooked_gethostbyname(const char* name);

/* Async DNS resolution hook */
int WSAAPI Hooked_GetAddrInfoExW(const wchar_t* pName, const wchar_t* pServiceName,
                                  DWORD dwNameSpace, LPGUID lpNspId,
                                  const ADDRINFOEXW* hints, PADDRINFOEXW* ppResult,
                                  struct timeval* timeout, LPOVERLAPPED lpOverlapped,
                                  LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
                                  LPHANDLE lpNameHandle);

} // namespace proxyfire

#endif

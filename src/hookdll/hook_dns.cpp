/*
 * ProxyFire - hook_dns.cpp
 * DNS resolution hooks for DNS leak prevention
 *
 * Intercepts DNS resolution calls and returns fake IPs from the
 * 240.0.0.0/4 range. When connect() sees a fake IP, it passes
 * the hostname to the SOCKS5 proxy for remote DNS resolution.
 * This prevents DNS leaks.
 */

#include "hook_dns.h"
#include "dns_faker.h"
#include "ipc_client.h"
#include "string_utils.h"

#include <proxyfire/config.h>

#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

extern ProxyFireConfig g_config;

namespace proxyfire {

/* Original function pointers */
int (WSAAPI *Original_getaddrinfo)(const char*, const char*,
     const struct addrinfo*, struct addrinfo**) = nullptr;
int (WSAAPI *Original_GetAddrInfoW)(const wchar_t*, const wchar_t*,
     const ADDRINFOW*, ADDRINFOW**) = nullptr;
struct hostent* (WSAAPI *Original_gethostbyname)(const char*) = nullptr;
int (WSAAPI *Original_GetAddrInfoExW)(const wchar_t*, const wchar_t*,
     DWORD, LPGUID, const ADDRINFOEXW*, PADDRINFOEXW*, struct timeval*,
     LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE) = nullptr;

/*
 * Check if a hostname is localhost or a localhost variant.
 */
static bool is_localhost(const char* name) {
    if (!name) return false;
    if (strcmp(name, "localhost") == 0) return true;
    if (strcmp(name, "localhost.") == 0) return true;
    if (_stricmp(name, "localhost") == 0) return true;
    return false;
}

/*
 * Check if a string is a numeric IP address (not a hostname).
 */
static bool is_numeric_address(const char* str) {
    if (!str) return false;

    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) == 1) return true;

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, str, &addr6) == 1) return true;

    return false;
}

static bool is_numeric_address_w(const wchar_t* str) {
    if (!str) return false;
    std::string narrow = to_narrow(std::wstring(str));
    return is_numeric_address(narrow.c_str());
}

/*
 * Build a synthetic addrinfo result with a fake IP.
 * Uses HeapAlloc so that freeaddrinfo (which uses HeapFree) can free it.
 * The sockaddr is allocated separately because some Windows versions'
 * freeaddrinfo implementations free ai_addr with a separate HeapFree call.
 */
static struct addrinfo* build_fake_addrinfo(uint32_t fake_ip_net, const char* service) {
    HANDLE heap = GetProcessHeap();
    struct addrinfo* ai = (struct addrinfo*)HeapAlloc(heap, HEAP_ZERO_MEMORY,
                                                       sizeof(struct addrinfo));
    if (!ai) return nullptr;

    struct sockaddr_in* sa = (struct sockaddr_in*)HeapAlloc(heap, HEAP_ZERO_MEMORY,
                                                             sizeof(struct sockaddr_in));
    if (!sa) {
        HeapFree(heap, 0, ai);
        return nullptr;
    }

    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = fake_ip_net;
    if (service) {
        sa->sin_port = htons((uint16_t)atoi(service));
    }

    ai->ai_family = AF_INET;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr*)sa;
    ai->ai_next = nullptr;
    ai->ai_canonname = nullptr;

    return ai;
}

/*
 * Build a synthetic ADDRINFOW result with a fake IP.
 * Uses HeapAlloc so that FreeAddrInfoW (which uses HeapFree) can free it.
 * The sockaddr is allocated separately because some Windows versions'
 * FreeAddrInfoW implementations free ai_addr with a separate HeapFree call.
 */
static ADDRINFOW* build_fake_addrinfow(uint32_t fake_ip_net, const wchar_t* service) {
    HANDLE heap = GetProcessHeap();
    ADDRINFOW* ai = (ADDRINFOW*)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(ADDRINFOW));
    if (!ai) return nullptr;

    struct sockaddr_in* sa = (struct sockaddr_in*)HeapAlloc(heap, HEAP_ZERO_MEMORY,
                                                             sizeof(struct sockaddr_in));
    if (!sa) {
        HeapFree(heap, 0, ai);
        return nullptr;
    }

    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = fake_ip_net;
    if (service) {
        sa->sin_port = htons((uint16_t)_wtoi(service));
    }

    ai->ai_family = AF_INET;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr*)sa;
    ai->ai_next = nullptr;
    ai->ai_canonname = nullptr;

    return ai;
}

/*
 * Build a synthetic ADDRINFOEXW result with a fake IP.
 * Uses HeapAlloc so that FreeAddrInfoExW (which uses HeapFree) can free it.
 */
static ADDRINFOEXW* build_fake_addrinfoexw(uint32_t fake_ip_net, const wchar_t* service) {
    HANDLE heap = GetProcessHeap();
    ADDRINFOEXW* ai = (ADDRINFOEXW*)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(ADDRINFOEXW));
    if (!ai) return nullptr;

    struct sockaddr_in* sa = (struct sockaddr_in*)HeapAlloc(heap, HEAP_ZERO_MEMORY,
                                                             sizeof(struct sockaddr_in));
    if (!sa) {
        HeapFree(heap, 0, ai);
        return nullptr;
    }

    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = fake_ip_net;
    if (service) {
        sa->sin_port = htons((uint16_t)_wtoi(service));
    }

    ai->ai_family = AF_INET;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr*)sa;
    ai->ai_next = nullptr;
    ai->ai_canonname = nullptr;

    return ai;
}

/*
 * Thread-local storage for gethostbyname fake results.
 * gethostbyname returns a pointer to a static buffer, so we need TLS.
 */
static __declspec(thread) struct hostent tls_hostent;
static __declspec(thread) char* tls_addr_list[2];
static __declspec(thread) struct in_addr tls_addr;

/*
 * Hooked getaddrinfo()
 *
 * If DNS leak prevention is enabled and the name is a hostname (not IP),
 * return a fake IP instead of doing a real DNS lookup.
 */
int WSAAPI Hooked_getaddrinfo(const char* pNodeName, const char* pServiceName,
                               const struct addrinfo* pHints, struct addrinfo** ppResult)
{
    /* Pass through if DNS leak prevention is disabled */
    if (!g_config.dns_leak_prevention) {
        return Original_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }

    /* Pass through for null or numeric addresses */
    if (!pNodeName || is_numeric_address(pNodeName)) {
        return Original_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }

    /* Pass through for localhost */
    if (is_localhost(pNodeName)) {
        return Original_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }

    /* If caller explicitly requests IPv6 only, pass through (we can't fake IPv6) */
    if (pHints && pHints->ai_family == AF_INET6) {
        return Original_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }

    /* Allocate a fake IP for this hostname */
    uint32_t fake_ip = dns_faker_allocate(pNodeName);
    if (fake_ip == 0) {
        /* Fallback to real resolution if faker is exhausted */
        return Original_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    }

    /* Notify launcher about the mapping */
    ipc_client_dns_register(fake_ip, pNodeName);

    if (g_config.verbose) {
        ipc_client_log(PF_LOG_DEBUG, "getaddrinfo(%s) -> fake IP %s",
                      pNodeName, ip_to_string(fake_ip).c_str());
    }

    /* Build synthetic result */
    *ppResult = build_fake_addrinfo(fake_ip, pServiceName);
    if (!*ppResult) {
        return EAI_MEMORY;
    }

    return 0;
}

/*
 * Hooked GetAddrInfoW() - Wide string version
 */
int WSAAPI Hooked_GetAddrInfoW(const wchar_t* pNodeName, const wchar_t* pServiceName,
                                const ADDRINFOW* pHints, ADDRINFOW** ppResult)
{
    if (!g_config.dns_leak_prevention) {
        return Original_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    if (!pNodeName || is_numeric_address_w(pNodeName)) {
        return Original_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    std::string narrow_name = to_narrow(std::wstring(pNodeName));

    /* Pass through for localhost */
    if (is_localhost(narrow_name.c_str())) {
        return Original_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    /* If caller explicitly requests IPv6 only, pass through */
    if (pHints && pHints->ai_family == AF_INET6) {
        return Original_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    uint32_t fake_ip = dns_faker_allocate(narrow_name.c_str());
    if (fake_ip == 0) {
        return Original_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    ipc_client_dns_register(fake_ip, narrow_name.c_str());

    if (g_config.verbose) {
        ipc_client_log(PF_LOG_DEBUG, "GetAddrInfoW(%s) -> fake IP %s",
                      narrow_name.c_str(), ip_to_string(fake_ip).c_str());
    }

    *ppResult = build_fake_addrinfow(fake_ip, pServiceName);
    if (!*ppResult) {
        return EAI_MEMORY;
    }

    return 0;
}

/*
 * Hooked gethostbyname()
 *
 * Legacy DNS resolution function. Returns a hostent with fake IP.
 */
struct hostent* WSAAPI Hooked_gethostbyname(const char* name) {
    if (!g_config.dns_leak_prevention) {
        return Original_gethostbyname(name);
    }

    if (!name || is_numeric_address(name)) {
        return Original_gethostbyname(name);
    }

    if (is_localhost(name)) {
        return Original_gethostbyname(name);
    }

    uint32_t fake_ip = dns_faker_allocate(name);
    if (fake_ip == 0) {
        return Original_gethostbyname(name);
    }

    ipc_client_dns_register(fake_ip, name);

    if (g_config.verbose) {
        ipc_client_log(PF_LOG_DEBUG, "gethostbyname(%s) -> fake IP %s",
                      name, ip_to_string(fake_ip).c_str());
    }

    /* Build a synthetic hostent using thread-local storage */
    tls_addr.s_addr = fake_ip;
    tls_addr_list[0] = (char*)&tls_addr;
    tls_addr_list[1] = nullptr;

    memset(&tls_hostent, 0, sizeof(tls_hostent));
    tls_hostent.h_name = (char*)name;  /* Points to caller's buffer */
    tls_hostent.h_aliases = nullptr;
    tls_hostent.h_addrtype = AF_INET;
    tls_hostent.h_length = sizeof(struct in_addr);
    tls_hostent.h_addr_list = tls_addr_list;

    return &tls_hostent;
}

/*
 * Hooked GetAddrInfoExW() - Async DNS resolution
 *
 * Used by modern Windows apps (UWP, Edge, .NET Core) for async DNS.
 * Supports both synchronous and overlapped (async) calls.
 */
int WSAAPI Hooked_GetAddrInfoExW(const wchar_t* pName, const wchar_t* pServiceName,
                                  DWORD dwNameSpace, LPGUID lpNspId,
                                  const ADDRINFOEXW* hints, PADDRINFOEXW* ppResult,
                                  struct timeval* timeout, LPOVERLAPPED lpOverlapped,
                                  LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
                                  LPHANDLE lpNameHandle)
{
    if (!g_config.dns_leak_prevention) {
        return Original_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                        hints, ppResult, timeout, lpOverlapped,
                                        lpCompletionRoutine, lpNameHandle);
    }

    if (!pName || is_numeric_address_w(pName)) {
        return Original_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                        hints, ppResult, timeout, lpOverlapped,
                                        lpCompletionRoutine, lpNameHandle);
    }

    std::string narrow_name = to_narrow(std::wstring(pName));

    if (is_localhost(narrow_name.c_str())) {
        return Original_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                        hints, ppResult, timeout, lpOverlapped,
                                        lpCompletionRoutine, lpNameHandle);
    }

    /* If caller explicitly requests IPv6 only, pass through */
    if (hints && hints->ai_family == AF_INET6) {
        return Original_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                        hints, ppResult, timeout, lpOverlapped,
                                        lpCompletionRoutine, lpNameHandle);
    }

    uint32_t fake_ip = dns_faker_allocate(narrow_name.c_str());
    if (fake_ip == 0) {
        return Original_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                        hints, ppResult, timeout, lpOverlapped,
                                        lpCompletionRoutine, lpNameHandle);
    }

    ipc_client_dns_register(fake_ip, narrow_name.c_str());

    if (g_config.verbose) {
        ipc_client_log(PF_LOG_DEBUG, "GetAddrInfoExW(%s) -> fake IP %s",
                      narrow_name.c_str(), ip_to_string(fake_ip).c_str());
    }

    /* Build the synthetic result */
    ADDRINFOEXW* result = build_fake_addrinfoexw(fake_ip, pServiceName);
    if (!result) {
        if (lpOverlapped) {
            lpOverlapped->Internal = WSAENOMORE;
            if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);
            if (lpCompletionRoutine) {
                lpCompletionRoutine(WSAENOMORE, 0, lpOverlapped);
            }
            return WSA_IO_PENDING;
        }
        WSASetLastError(WSA_NOT_ENOUGH_MEMORY);
        return SOCKET_ERROR;
    }

    *ppResult = result;

    /* Handle async completion if overlapped was provided */
    if (lpOverlapped) {
        /* Signal synchronous completion: set Internal to NO_ERROR */
        lpOverlapped->Internal = NO_ERROR;
        lpOverlapped->InternalHigh = 0;
        if (lpOverlapped->hEvent) {
            SetEvent(lpOverlapped->hEvent);
        }
        if (lpCompletionRoutine) {
            lpCompletionRoutine(NO_ERROR, 0, lpOverlapped);
        }
        /* Return NO_ERROR for synchronous completion (not WSA_IO_PENDING) */
    }

    return NO_ERROR;
}

} // namespace proxyfire

#endif /* _WIN32 */

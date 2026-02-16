/*
 * ProxyFire - hook_winsock.cpp
 * Hooked Winsock2 connection functions
 *
 * These hooks intercept all outgoing TCP connections and redirect
 * them through the configured proxy chain.
 */

#include "hook_winsock.h"
#include "proxy_chain.h"
#include "dns_faker.h"
#include "socket_context.h"
#include "udp_relay.h"
#include "ipc_client.h"
#include "string_utils.h"

#include <proxyfire/config.h>

#include <cstring>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#pragma comment(lib, "ws2_32.lib")

/* Global config - set during DLL init */
extern ProxyFireConfig g_config;

namespace proxyfire {

/* Original function pointers */
int (WSAAPI *Original_connect)(SOCKET, const struct sockaddr*, int) = nullptr;
int (WSAAPI *Original_WSAConnect)(SOCKET, const struct sockaddr*, int,
     LPWSABUF, LPWSABUF, LPQOS, LPQOS) = nullptr;
int (WSAAPI *Original_closesocket)(SOCKET) = nullptr;
int (WSAAPI *Original_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD,
     LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
BOOL (WSAAPI *Original_WSAConnectByNameW)(SOCKET, LPWSTR, LPWSTR,
     LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
     const struct timeval*, LPWSAOVERLAPPED) = nullptr;
BOOL (WSAAPI *Original_WSAConnectByNameA)(SOCKET, LPCSTR, LPCSTR,
     LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
     const struct timeval*, LPWSAOVERLAPPED) = nullptr;

/* Real ConnectEx function pointer (discovered via WSAIoctl) */
static LPFN_CONNECTEX Real_ConnectEx = nullptr;

/* Forward declaration for is_numeric_address (used by WSAConnectByName hooks) */
static bool is_numeric_address(const char* str) {
    if (!str) return false;
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) == 1) return true;
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, str, &addr6) == 1) return true;
    return false;
}

/*
 * Helper: query the current non-blocking state of a socket via getsockopt.
 * Returns true if the socket is non-blocking.
 *
 * Note: There's no direct API to query FIONBIO state on Windows.
 * We track it in socket context when possible. As a fallback, we use
 * a zero-timeout select trick: attempt a connect test isn't feasible,
 * so we just save the state before we change it by attempting to read
 * the socket options we can.
 */
struct SocketBlockingState {
    bool was_nonblocking;
    DWORD original_send_timeout;
    DWORD original_recv_timeout;
};

static SocketBlockingState save_and_set_blocking(SOCKET sock) {
    SocketBlockingState state = {};
    state.was_nonblocking = false;

    /* Save original timeouts */
    int optlen = sizeof(DWORD);
    getsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&state.original_send_timeout, &optlen);
    optlen = sizeof(DWORD);
    getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&state.original_recv_timeout, &optlen);

    /*
     * Detect non-blocking state: try a zero-byte recv with MSG_PEEK.
     * On a freshly created non-connected socket:
     * - Blocking socket: recv would block (but socket isn't connected, so WSAENOTCONN)
     * - Non-blocking socket: returns WSAEWOULDBLOCK
     *
     * However, this is unreliable before connect. Instead, we use the
     * WSAEventSelect detection: if WSAEventSelect was called, the socket
     * is in non-blocking mode. We check by trying ioctlsocket to read.
     *
     * Safest approach: always save that we changed it, and always restore
     * to blocking after handshake. If app was non-blocking, it likely
     * called ioctlsocket(FIONBIO) or WSAEventSelect, and will do so
     * again after connect returns.
     *
     * We use a pragmatic approach: set to blocking unconditionally for
     * the handshake. Track in SocketCtx whether the caller was using
     * non-blocking patterns (we'll know if connect was called on a socket
     * where ioctlsocket was already called).
     */

    /* Force blocking mode for proxy handshake */
    u_long mode = 0;  /* 0 = blocking */
    ioctlsocket(sock, FIONBIO, &mode);

    return state;
}

static void restore_socket_state(SOCKET sock, const SocketBlockingState& state) {
    /* Restore original timeouts */
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
               (const char*)&state.original_send_timeout, sizeof(DWORD));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&state.original_recv_timeout, sizeof(DWORD));

    /*
     * Do NOT force back to non-blocking here. The proxy handshake is done
     * on a now-connected socket. If the app was using non-blocking mode,
     * it will call ioctlsocket(FIONBIO, 1) or WSAAsyncSelect/WSAEventSelect
     * again after connect() returns. Setting it back blindly could cause
     * issues if the app was actually blocking.
     *
     * The socket is left in blocking mode, which is the default state
     * after socket creation. Applications that need non-blocking will
     * set it themselves.
     */
}

/*
 * Core proxy routing logic - shared between connect/WSAConnect/ConnectEx.
 * Returns 0 on success, SOCKET_ERROR on failure.
 */
static int route_through_proxy(SOCKET s, const struct sockaddr* name, int namelen) {
    uint32_t dest_ip = 0;
    uint16_t dest_port = 0;
    uint8_t dest_ipv6[16] = {};
    bool is_ipv6 = false;

    if (name->sa_family == AF_INET) {
        const struct sockaddr_in* addr4 = (const struct sockaddr_in*)name;
        dest_ip = addr4->sin_addr.s_addr;
        dest_port = ntohs(addr4->sin_port);
    } else if (name->sa_family == AF_INET6) {
        const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*)name;

        /* Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) */
        const uint8_t* b = addr6->sin6_addr.s6_addr;
        bool is_v4mapped = (memcmp(b, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0);

        if (is_v4mapped) {
            /* Extract the IPv4 address from bytes 12-15 */
            memcpy(&dest_ip, b + 12, 4);
            dest_port = ntohs(addr6->sin6_port);
        } else {
            /* Pure IPv6 - proxy through SOCKS5/HTTP CONNECT (both support IPv6) */
            if (g_config.proxy_count == 0) {
                return -2; /* No proxy configured, pass through */
            }
            /* Check if first proxy supports IPv6 (SOCKS4/4a does not) */
            if (g_config.proxies[0].proto == PROXY_SOCKS4 ||
                g_config.proxies[0].proto == PROXY_SOCKS4A) {
                if (g_config.dns_leak_prevention) {
                    ipc_client_log(PF_LOG_WARN,
                        "Blocked IPv6 connection: SOCKS4 does not support IPv6");
                    WSASetLastError(WSAECONNREFUSED);
                    return SOCKET_ERROR;
                }
                return -2; /* Can't proxy IPv6 via SOCKS4, pass through */
            }
            is_ipv6 = true;
            memcpy(dest_ipv6, addr6->sin6_addr.s6_addr, 16);
            dest_port = ntohs(addr6->sin6_port);
        }
    } else {
        return -2;  /* Not IP, pass through */
    }

    /* Check bypass rules (IPv4 only; IPv6 bypass TBD) */
    if (!is_ipv6 && should_bypass(&g_config, dest_ip, dest_port)) {
        return -2;  /* Signal caller to pass through */
    }

    /* Check if no proxies configured */
    if (g_config.proxy_count == 0) {
        return -2;
    }

    /* Check if this is a fake DNS IP -> get hostname (IPv4 only, no fake IPs for IPv6) */
    const char* hostname = nullptr;
    if (!is_ipv6 && dns_faker_is_fake(dest_ip)) {
        hostname = dns_faker_lookup(dest_ip);
    }

    /* Log the connection attempt */
    if (g_config.verbose) {
        if (is_ipv6) {
            char ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, dest_ipv6, ipv6_str, sizeof(ipv6_str));
            ipc_client_log(PF_LOG_INFO, "connect() -> [%s]:%u via %s proxy %s:%u",
                          ipv6_str, dest_port,
                          proxy_proto_name(g_config.proxies[0].proto),
                          g_config.proxies[0].host, g_config.proxies[0].port);
        } else {
            ipc_client_log(PF_LOG_INFO, "connect() -> %s:%u via %s proxy %s:%u",
                          hostname ? hostname : ip_to_string(dest_ip).c_str(),
                          dest_port,
                          proxy_proto_name(g_config.proxies[0].proto),
                          g_config.proxies[0].host, g_config.proxies[0].port);
        }
    }

    /* Save socket state and force blocking for handshake */
    SocketBlockingState saved_state = save_and_set_blocking(s);

    /* Connect through the proxy chain */
    int result = proxy_chain_connect(s, &g_config, dest_ip, dest_port, hostname,
                                      is_ipv6 ? dest_ipv6 : nullptr);

    /* Restore socket state */
    restore_socket_state(s, saved_state);

    /* Track this socket only on success; don't leak context on failure */
    if (result == 0) {
        socket_ctx_add(s, dest_ip, dest_port, hostname, true);
    } else {
        if (is_ipv6) {
            char ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, dest_ipv6, ipv6_str, sizeof(ipv6_str));
            ipc_client_log(PF_LOG_ERROR, "Proxy connection failed for [%s]:%u",
                          ipv6_str, dest_port);
        } else {
            ipc_client_log(PF_LOG_ERROR, "Proxy connection failed for %s:%u",
                          hostname ? hostname : ip_to_string(dest_ip).c_str(),
                          dest_port);
        }
    }

    return result;
}

/*
 * Hooked connect()
 */
int WSAAPI Hooked_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (!name || (name->sa_family != AF_INET && name->sa_family != AF_INET6)) {
        return Original_connect(s, name, namelen);
    }

    int result = route_through_proxy(s, name, namelen);
    if (result == -2) {
        /* Pass through to original */
        return Original_connect(s, name, namelen);
    }
    return result;
}

/*
 * Hooked WSAConnect()
 */
int WSAAPI Hooked_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen,
                              LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                              LPQOS lpSQOS, LPQOS lpGQOS)
{
    if (!name || (name->sa_family != AF_INET && name->sa_family != AF_INET6)) {
        return Original_WSAConnect(s, name, namelen, lpCallerData,
                                   lpCalleeData, lpSQOS, lpGQOS);
    }

    int result = route_through_proxy(s, name, namelen);
    if (result == -2) {
        return Original_WSAConnect(s, name, namelen, lpCallerData,
                                   lpCalleeData, lpSQOS, lpGQOS);
    }
    return result;
}

/*
 * Hooked ConnectEx()
 *
 * ConnectEx is obtained by applications via WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER).
 * We intercept WSAIoctl to return our hooked ConnectEx instead.
 * Used by .NET, IOCP-based apps, and async connection patterns.
 */
BOOL PASCAL Hooked_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen,
                              PVOID lpSendBuffer, DWORD dwSendDataLength,
                              LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped)
{
    if (!name || (name->sa_family != AF_INET && name->sa_family != AF_INET6)) {
        if (Real_ConnectEx) {
            return Real_ConnectEx(s, name, namelen, lpSendBuffer,
                                  dwSendDataLength, lpdwBytesSent, lpOverlapped);
        }
        WSASetLastError(WSAENOTSOCK);
        return FALSE;
    }

    int result = route_through_proxy(s, name, namelen);
    if (result == -2) {
        /* Pass through to real ConnectEx */
        if (Real_ConnectEx) {
            return Real_ConnectEx(s, name, namelen, lpSendBuffer,
                                  dwSendDataLength, lpdwBytesSent, lpOverlapped);
        }
        WSASetLastError(WSAENOTSOCK);
        return FALSE;
    }

    if (result == 0) {
        /*
         * Proxy handshake succeeded synchronously. For ConnectEx callers,
         * we need to signal completion on the overlapped structure.
         */
        if (lpdwBytesSent) *lpdwBytesSent = 0;

        if (lpOverlapped) {
            lpOverlapped->Internal = 0;       /* STATUS_SUCCESS */
            lpOverlapped->InternalHigh = 0;   /* Bytes transferred */

            if (lpOverlapped->hEvent) {
                SetEvent(lpOverlapped->hEvent);
            }

            /* If socket is bound to an IOCP, post completion */
            /* Note: PostQueuedCompletionStatus would need the IOCP handle,
             * which we don't have. Setting the event is the best we can do.
             * Most apps check the overlapped result via GetOverlappedResult. */
        }

        /* Send any initial data if provided */
        if (lpSendBuffer && dwSendDataLength > 0) {
            int sent = send(s, (const char*)lpSendBuffer, dwSendDataLength, 0);
            if (sent > 0 && lpdwBytesSent) {
                *lpdwBytesSent = (DWORD)sent;
            }
        }

        return TRUE;
    }

    /* Proxy connection failed */
    return FALSE;
}

/*
 * Hooked WSAIoctl()
 *
 * Intercepts requests for ConnectEx function pointer.
 * When an app asks for ConnectEx via SIO_GET_EXTENSION_FUNCTION_POINTER,
 * we return our hooked version instead.
 */
int WSAAPI Hooked_WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer,
                            DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
                            LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped,
                            LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    /* Check if this is a request for ConnectEx */
    if (dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        cbInBuffer >= sizeof(GUID) && lpvInBuffer &&
        cbOutBuffer >= sizeof(LPFN_CONNECTEX) && lpvOutBuffer)
    {
        GUID connectex_guid = WSAID_CONNECTEX;
        if (memcmp(lpvInBuffer, &connectex_guid, sizeof(GUID)) == 0) {
            /* First, get the real ConnectEx if we don't have it */
            if (!Real_ConnectEx) {
                int rc = Original_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer,
                                            &Real_ConnectEx, sizeof(Real_ConnectEx),
                                            lpcbBytesReturned, lpOverlapped,
                                            lpCompletionRoutine);
                if (rc != 0 || !Real_ConnectEx) {
                    return rc;
                }
            }

            /* Return our hooked ConnectEx */
            *(LPFN_CONNECTEX*)lpvOutBuffer = (LPFN_CONNECTEX)Hooked_ConnectEx;
            if (lpcbBytesReturned) {
                *lpcbBytesReturned = sizeof(LPFN_CONNECTEX);
            }

            ipc_client_log(PF_LOG_DEBUG, "Intercepted ConnectEx function pointer request");
            return 0;
        }
    }

    /* Pass through all other WSAIoctl calls */
    return Original_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer,
                              lpvOutBuffer, cbOutBuffer, lpcbBytesReturned,
                              lpOverlapped, lpCompletionRoutine);
}

/*
 * Hooked WSAConnectByNameW()
 *
 * This API connects to a host by name, bypassing the normal
 * getaddrinfo -> connect flow. We intercept it to route through proxy.
 * The approach: resolve the hostname to a fake IP, then use our
 * normal route_through_proxy path with the hostname passed through.
 */
BOOL WSAAPI Hooked_WSAConnectByNameW(SOCKET s, LPWSTR nodename, LPWSTR servicename,
                                      LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
                                      LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
                                      const struct timeval* timeout, LPWSAOVERLAPPED Reserved)
{
    if (!nodename || g_config.proxy_count == 0) {
        return Original_WSAConnectByNameW(s, nodename, servicename,
                                           LocalAddressLength, LocalAddress,
                                           RemoteAddressLength, RemoteAddress,
                                           timeout, Reserved);
    }

    /* Convert wide name to narrow */
    std::string host = to_narrow(std::wstring(nodename));
    uint16_t port = 0;
    if (servicename) {
        port = (uint16_t)_wtoi(servicename);
    }

    /* Allocate fake IP and route through proxy */
    uint32_t fake_ip = 0;
    if (g_config.dns_leak_prevention && !is_numeric_address(host.c_str())) {
        fake_ip = dns_faker_allocate(host.c_str());
        if (fake_ip) {
            ipc_client_dns_register(fake_ip, host.c_str());
        }
    } else {
        /* Numeric address - parse it */
        struct in_addr addr;
        if (inet_pton(AF_INET, host.c_str(), &addr) == 1) {
            fake_ip = addr.s_addr;
        }
    }

    if (fake_ip == 0) {
        /* Fallback to original if we can't handle it */
        return Original_WSAConnectByNameW(s, nodename, servicename,
                                           LocalAddressLength, LocalAddress,
                                           RemoteAddressLength, RemoteAddress,
                                           timeout, Reserved);
    }

    /* Build a sockaddr_in and use our proxy routing */
    struct sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = fake_ip;
    dest_addr.sin_port = htons(port);

    int result = route_through_proxy(s, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (result == -2) {
        /* Bypass - use original */
        return Original_WSAConnectByNameW(s, nodename, servicename,
                                           LocalAddressLength, LocalAddress,
                                           RemoteAddressLength, RemoteAddress,
                                           timeout, Reserved);
    }

    if (result == 0) {
        /* Fill in remote address if requested */
        if (RemoteAddress && RemoteAddressLength && *RemoteAddressLength >= sizeof(struct sockaddr_in)) {
            memcpy(RemoteAddress, &dest_addr, sizeof(struct sockaddr_in));
            *RemoteAddressLength = sizeof(struct sockaddr_in);
        }
        return TRUE;
    }

    return FALSE;
}

BOOL WSAAPI Hooked_WSAConnectByNameA(SOCKET s, LPCSTR nodename, LPCSTR servicename,
                                      LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
                                      LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
                                      const struct timeval* timeout, LPWSAOVERLAPPED Reserved)
{
    if (!nodename || g_config.proxy_count == 0) {
        return Original_WSAConnectByNameA(s, nodename, servicename,
                                           LocalAddressLength, LocalAddress,
                                           RemoteAddressLength, RemoteAddress,
                                           timeout, Reserved);
    }

    uint16_t port = 0;
    if (servicename) {
        port = (uint16_t)atoi(servicename);
    }

    uint32_t fake_ip = 0;
    if (g_config.dns_leak_prevention && !is_numeric_address(nodename)) {
        fake_ip = dns_faker_allocate(nodename);
        if (fake_ip) {
            ipc_client_dns_register(fake_ip, nodename);
        }
    } else {
        struct in_addr addr;
        if (inet_pton(AF_INET, nodename, &addr) == 1) {
            fake_ip = addr.s_addr;
        }
    }

    if (fake_ip == 0) {
        return Original_WSAConnectByNameA(s, nodename, servicename,
                                           LocalAddressLength, LocalAddress,
                                           RemoteAddressLength, RemoteAddress,
                                           timeout, Reserved);
    }

    struct sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = fake_ip;
    dest_addr.sin_port = htons(port);

    int result = route_through_proxy(s, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (result == -2) {
        return Original_WSAConnectByNameA(s, nodename, servicename,
                                           LocalAddressLength, LocalAddress,
                                           RemoteAddressLength, RemoteAddress,
                                           timeout, Reserved);
    }

    if (result == 0) {
        if (RemoteAddress && RemoteAddressLength && *RemoteAddressLength >= sizeof(struct sockaddr_in)) {
            memcpy(RemoteAddress, &dest_addr, sizeof(struct sockaddr_in));
            *RemoteAddressLength = sizeof(struct sockaddr_in);
        }
        return TRUE;
    }

    return FALSE;
}

/*
 * Hooked closesocket()
 */
int WSAAPI Hooked_closesocket(SOCKET s) {
    udp_relay_close(s);
    socket_ctx_remove(s);
    return Original_closesocket(s);
}

} // namespace proxyfire

#endif /* _WIN32 */

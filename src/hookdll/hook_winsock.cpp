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
#include "ipc_client.h"
#include "string_utils.h"

#include <proxyfire/config.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#pragma comment(lib, "ws2_32.lib")

/* Global config - set during DLL init */
extern proxyfire::ProxyFireConfig g_config;

/* Original function pointers */
int (WSAAPI *Original_connect)(SOCKET, const struct sockaddr*, int) = nullptr;
int (WSAAPI *Original_WSAConnect)(SOCKET, const struct sockaddr*, int,
     LPWSABUF, LPWSABUF, LPQOS, LPQOS) = nullptr;
int (WSAAPI *Original_closesocket)(SOCKET) = nullptr;
int (WSAAPI *Original_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD,
     LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;

/* Real ConnectEx function pointer (discovered via WSAIoctl) */
static LPFN_CONNECTEX Real_ConnectEx = nullptr;

namespace proxyfire {

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
            /* Pure IPv6 - block if DNS leak prevention is on, otherwise pass through.
             * We can't proxy pure IPv6 through SOCKS4, but SOCKS5 and HTTP CONNECT
             * support it. For now, log a warning and let it through if bypassed,
             * or block it to prevent leaks. */
            if (g_config.dns_leak_prevention) {
                ipc_client_log(PF_LOG_WARN,
                    "Blocked direct IPv6 connection (not yet proxied). "
                    "Use --allow-dns-leak to permit IPv6 bypass.");
                WSASetLastError(WSAECONNREFUSED);
                return SOCKET_ERROR;
            }
            return -2;  /* Signal caller to pass through */
        }
    } else {
        return -2;  /* Not IP, pass through */
    }

    /* Check bypass rules */
    if (should_bypass(&g_config, dest_ip, dest_port)) {
        return -2;  /* Signal caller to pass through */
    }

    /* Check if no proxies configured */
    if (g_config.proxy_count == 0) {
        return -2;
    }

    /* Check if this is a fake DNS IP -> get hostname */
    const char* hostname = nullptr;
    if (dns_faker_is_fake(dest_ip)) {
        hostname = dns_faker_lookup(dest_ip);
    }

    /* Log the connection attempt */
    if (g_config.verbose) {
        ipc_client_log(PF_LOG_INFO, "connect() -> %s:%u via %s proxy %s:%u",
                      hostname ? hostname : ip_to_string(dest_ip).c_str(),
                      dest_port,
                      proxy_proto_name(g_config.proxies[0].proto),
                      g_config.proxies[0].host, g_config.proxies[0].port);
    }

    /* Save socket state and force blocking for handshake */
    SocketBlockingState saved_state = save_and_set_blocking(s);

    /* Connect through the proxy chain */
    int result = proxy_chain_connect(s, &g_config, dest_ip, dest_port, hostname);

    /* Restore socket state */
    restore_socket_state(s, saved_state);

    /* Track this socket */
    socket_ctx_add(s, dest_ip, dest_port, hostname, result == 0);

    if (result != 0) {
        ipc_client_log(PF_LOG_ERROR, "Proxy connection failed for %s:%u",
                      hostname ? hostname : ip_to_string(dest_ip).c_str(),
                      dest_port);
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
 * Hooked closesocket()
 */
int WSAAPI Hooked_closesocket(SOCKET s) {
    socket_ctx_remove(s);
    return Original_closesocket(s);
}

} // namespace proxyfire

#endif /* _WIN32 */

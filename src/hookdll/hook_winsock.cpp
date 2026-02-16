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

namespace proxyfire {

/*
 * Helper: save and set socket to blocking mode for handshake.
 * Returns the original non-blocking state.
 */
static bool set_blocking(SOCKET sock) {
    u_long mode = 0;  /* 0 = blocking */
    ioctlsocket(sock, FIONBIO, &mode);
    return true;
}

/*
 * Helper: restore non-blocking mode if needed.
 */
static void restore_nonblocking(SOCKET sock, bool was_nonblocking) {
    if (was_nonblocking) {
        u_long mode = 1;  /* 1 = non-blocking */
        ioctlsocket(sock, FIONBIO, &mode);
    }
}

/*
 * Hooked connect()
 *
 * This is the main interception point. When an application calls connect():
 * 1. Check if it's an AF_INET/AF_INET6 TCP socket
 * 2. Check bypass rules (loopback, LAN, proxy addresses)
 * 3. If the IP is a fake DNS IP, resolve to hostname for remote DNS
 * 4. Connect through the proxy chain instead
 */
int WSAAPI Hooked_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    /* Only intercept AF_INET TCP sockets */
    if (!name || (name->sa_family != AF_INET && name->sa_family != AF_INET6)) {
        return Original_connect(s, name, namelen);
    }

    /* Extract destination address */
    uint32_t dest_ip = 0;
    uint16_t dest_port = 0;

    if (name->sa_family == AF_INET) {
        const struct sockaddr_in* addr4 = (const struct sockaddr_in*)name;
        dest_ip = addr4->sin_addr.s_addr;
        dest_port = ntohs(addr4->sin_port);
    } else {
        /* TODO: IPv6 support - for now pass through */
        return Original_connect(s, name, namelen);
    }

    /* Check bypass rules */
    if (should_bypass(&g_config, dest_ip, dest_port)) {
        return Original_connect(s, name, namelen);
    }

    /* Check if no proxies configured */
    if (g_config.proxy_count == 0) {
        return Original_connect(s, name, namelen);
    }

    /* Check if this is a fake DNS IP -> get hostname */
    const char* hostname = nullptr;
    if (dns_faker_is_fake(dest_ip)) {
        hostname = dns_faker_lookup(dest_ip);
    }

    /* Log the connection attempt */
    if (g_config.verbose) {
        if (hostname) {
            ipc_client_log(PF_LOG_INFO, "connect() -> %s:%u via %s proxy %s:%u",
                          hostname, dest_port,
                          proxy_proto_name(g_config.proxies[0].proto),
                          g_config.proxies[0].host, g_config.proxies[0].port);
        } else {
            ipc_client_log(PF_LOG_INFO, "connect() -> %s:%u via %s proxy %s:%u",
                          ip_to_string(dest_ip).c_str(), dest_port,
                          proxy_proto_name(g_config.proxies[0].proto),
                          g_config.proxies[0].host, g_config.proxies[0].port);
        }
    }

    /* Temporarily force blocking mode for the proxy handshake */
    set_blocking(s);

    /* Connect through the proxy chain */
    int result = proxy_chain_connect(s, &g_config, dest_ip, dest_port, hostname);

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
 * Hooked WSAConnect()
 *
 * Same as connect() but with additional Winsock-specific parameters.
 */
int WSAAPI Hooked_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen,
                              LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                              LPQOS lpSQOS, LPQOS lpGQOS)
{
    (void)lpCallerData;
    (void)lpCalleeData;
    (void)lpSQOS;
    (void)lpGQOS;

    /* Only intercept AF_INET TCP sockets */
    if (!name || (name->sa_family != AF_INET && name->sa_family != AF_INET6)) {
        return Original_WSAConnect(s, name, namelen, lpCallerData,
                                   lpCalleeData, lpSQOS, lpGQOS);
    }

    uint32_t dest_ip = 0;
    uint16_t dest_port = 0;

    if (name->sa_family == AF_INET) {
        const struct sockaddr_in* addr4 = (const struct sockaddr_in*)name;
        dest_ip = addr4->sin_addr.s_addr;
        dest_port = ntohs(addr4->sin_port);
    } else {
        return Original_WSAConnect(s, name, namelen, lpCallerData,
                                   lpCalleeData, lpSQOS, lpGQOS);
    }

    /* Check bypass rules */
    if (should_bypass(&g_config, dest_ip, dest_port)) {
        return Original_WSAConnect(s, name, namelen, lpCallerData,
                                   lpCalleeData, lpSQOS, lpGQOS);
    }

    if (g_config.proxy_count == 0) {
        return Original_WSAConnect(s, name, namelen, lpCallerData,
                                   lpCalleeData, lpSQOS, lpGQOS);
    }

    const char* hostname = nullptr;
    if (dns_faker_is_fake(dest_ip)) {
        hostname = dns_faker_lookup(dest_ip);
    }

    if (g_config.verbose) {
        ipc_client_log(PF_LOG_INFO, "WSAConnect() -> %s:%u via proxy",
                      hostname ? hostname : ip_to_string(dest_ip).c_str(),
                      dest_port);
    }

    set_blocking(s);
    int result = proxy_chain_connect(s, &g_config, dest_ip, dest_port, hostname);
    socket_ctx_add(s, dest_ip, dest_port, hostname, result == 0);

    return result;
}

/*
 * Hooked closesocket()
 *
 * Clean up socket tracking on close.
 */
int WSAAPI Hooked_closesocket(SOCKET s) {
    socket_ctx_remove(s);
    return Original_closesocket(s);
}

} // namespace proxyfire

#endif /* _WIN32 */

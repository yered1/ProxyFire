/*
 * ProxyFire - proxy_connector.h
 * Proxy protocol handshake implementations (SOCKS4/4a/5, HTTP CONNECT)
 */

#pragma once

#include <proxyfire/proxy_types.h>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#else
/* For development/testing on non-Windows */
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

namespace proxyfire {

/**
 * Perform a proxy handshake on an already-connected socket.
 *
 * The socket must be connected to the proxy server before calling this.
 * After success, the socket is tunneled to the destination.
 *
 * @param sock          Socket connected to the proxy
 * @param proto         Proxy protocol type
 * @param dest_host     Destination hostname (NULL if IP-only)
 * @param dest_ip       Destination IP (network byte order)
 * @param dest_port     Destination port (host byte order)
 * @param username      Proxy username (NULL if no auth)
 * @param password      Proxy password (NULL if no auth)
 * @param timeout_ms    Handshake timeout in milliseconds
 *
 * @return 0 on success, -1 on failure (WSAGetLastError set)
 */
int proxy_handshake(
    SOCKET          sock,
    ProxyProto      proto,
    const char*     dest_host,
    uint32_t        dest_ip,
    uint16_t        dest_port,
    const char*     username,
    const char*     password,
    uint32_t        timeout_ms
);

/* Individual protocol implementations */
int socks5_handshake(
    SOCKET sock, const char* dest_host, uint32_t dest_ip, uint16_t dest_port,
    const char* username, const char* password, uint32_t timeout_ms);

int socks4_handshake(
    SOCKET sock, uint32_t dest_ip, uint16_t dest_port,
    const char* username, uint32_t timeout_ms);

int socks4a_handshake(
    SOCKET sock, const char* dest_host, uint32_t dest_ip, uint16_t dest_port,
    const char* username, uint32_t timeout_ms);

int http_connect_handshake(
    SOCKET sock, const char* dest_host, uint32_t dest_ip, uint16_t dest_port,
    const char* username, const char* password, uint32_t timeout_ms);

} // namespace proxyfire

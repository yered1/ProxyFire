/*
 * ProxyFire - proxy_chain.h
 * Multi-hop proxy chain connection logic
 */

#pragma once

#include <proxyfire/config.h>
#include <proxyfire/proxy_types.h>

#ifdef _WIN32
#include <winsock2.h>
#else
typedef int SOCKET;
#endif

namespace proxyfire {

/**
 * Connect a socket through the entire proxy chain to the destination.
 *
 * This performs:
 * 1. TCP connect to first proxy
 * 2. Handshake through each proxy to the next
 * 3. Final handshake to actual destination
 *
 * @param sock          The socket to use
 * @param config        ProxyFire configuration with proxy chain
 * @param dest_ip       Final destination IP (network byte order)
 * @param dest_port     Final destination port (host byte order)
 * @param dest_hostname Final destination hostname (NULL if IP-only)
 *
 * @return 0 on success, SOCKET_ERROR on failure
 */
int proxy_chain_connect(
    SOCKET              sock,
    const ProxyFireConfig* config,
    uint32_t            dest_ip,
    uint16_t            dest_port,
    const char*         dest_hostname
);

/**
 * Check if a destination should bypass the proxy.
 * Returns true if the connection should go direct.
 */
bool should_bypass(const ProxyFireConfig* config, uint32_t dest_ip, uint16_t dest_port);

} // namespace proxyfire

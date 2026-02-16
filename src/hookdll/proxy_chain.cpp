/*
 * ProxyFire - proxy_chain.cpp
 * Multi-hop proxy chain connection logic
 */

#include "proxy_chain.h"
#include "proxy_connector.h"
#include "string_utils.h"

#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

/* We need the original connect - declared in hook_winsock.h */
extern int (WSAAPI *Original_connect)(SOCKET s, const struct sockaddr* name, int namelen);
#else
#include <sys/socket.h>
#include <netinet/in.h>
#define WSAAPI
static int (*Original_connect)(int s, const struct sockaddr* name, int namelen) = nullptr;
#endif

namespace proxyfire {

bool should_bypass(const ProxyFireConfig* config, uint32_t dest_ip, uint16_t dest_port) {
    (void)dest_port;

    if (!config) return false;

    unsigned char* b = (unsigned char*)&dest_ip;

    /* Always bypass loopback 127.0.0.0/8 */
    if (b[0] == 127) return true;

    /* Always bypass 0.0.0.0 (bind address) */
    if (dest_ip == 0) return true;

    /* Always bypass link-local 169.254.0.0/16 */
    if (b[0] == 169 && b[1] == 254) return true;

    /* Always bypass multicast 224.0.0.0/4 (224.x.x.x - 239.x.x.x) */
    if ((b[0] & 0xF0) == 0xE0) return true;

    /* Always bypass broadcast 255.255.255.255 */
    if (dest_ip == 0xFFFFFFFF) return true;

    /* Bypass proxy server addresses themselves (prevent loops) */
    for (uint32_t i = 0; i < config->proxy_count; i++) {
        if (config->proxies[i].ip == dest_ip) {
            return true;
        }
    }

    /* Check user-defined bypass rules */
    for (uint32_t i = 0; i < config->bypass_count; i++) {
        if (ip_matches_cidr(dest_ip, config->bypass_rules[i].ip,
                            config->bypass_rules[i].mask)) {
            return true;
        }
    }

    return false;
}

int proxy_chain_connect(
    SOCKET              sock,
    const ProxyFireConfig* config,
    uint32_t            dest_ip,
    uint16_t            dest_port,
    const char*         dest_hostname,
    const uint8_t*      dest_ipv6)
{
    if (!config || config->proxy_count == 0) {
        /* No proxy configured - this shouldn't happen */
#ifdef _WIN32
        WSASetLastError(WSAECONNREFUSED);
#endif
        return -1;
    }

    /*
     * Step 1: TCP connect to first proxy in the chain.
     * We use Original_connect to avoid recursive hooking.
     */
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = config->proxies[0].ip;
    proxy_addr.sin_port = htons(config->proxies[0].port);

    int rc;
    if (Original_connect) {
        rc = Original_connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr));
    } else {
        rc = connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr));
    }

    if (rc != 0) {
        return rc;
    }

    /*
     * Step 2: Handshake through each proxy to the next.
     *
     * For a chain [P1, P2, P3] connecting to destination D:
     *   - Handshake with P1 to connect to P2
     *   - Through P1, handshake with P2 to connect to P3
     *   - Through P1->P2, handshake with P3 to connect to D
     */
    for (uint32_t i = 0; i < config->proxy_count; i++) {
        const ProxyEntry* proxy = &config->proxies[i];
        const char* next_host = nullptr;
        uint32_t    next_ip = 0;
        uint16_t    next_port = 0;
        const uint8_t* next_ipv6 = nullptr;

        if (i + 1 < config->proxy_count) {
            /* Connect to next proxy in chain */
            const ProxyEntry* next_proxy = &config->proxies[i + 1];
            next_host = next_proxy->host;
            next_ip   = next_proxy->ip;
            next_port = next_proxy->port;
            /* Intermediate hops are always IPv4 proxies, no IPv6 needed */
        } else {
            /* Last proxy - connect to actual destination */
            next_host = dest_hostname;
            next_ip   = dest_ip;
            next_port = dest_port;
            next_ipv6 = dest_ipv6;
        }

        rc = proxy_handshake(
            sock,
            proxy->proto,
            next_host,
            next_ip,
            next_port,
            proxy->username[0] ? proxy->username : nullptr,
            proxy->password[0] ? proxy->password : nullptr,
            config->connect_timeout_ms,
            next_ipv6
        );

        if (rc != 0) {
            return rc;
        }
    }

    return 0;
}

} // namespace proxyfire

/*
 * ProxyFire - udp_relay.h
 * SOCKS5 UDP ASSOCIATE relay session management (RFC 1928 Section 7)
 *
 * When the first proxy in the chain is SOCKS5, UDP traffic is relayed
 * through the proxy using the UDP ASSOCIATE command. Each application
 * UDP socket gets its own relay session consisting of:
 *   - A TCP control connection to the SOCKS5 proxy
 *   - A local UDP socket that communicates with the proxy's relay endpoint
 *
 * The relay encapsulates outgoing datagrams with a SOCKS5 UDP header and
 * strips the header from incoming datagrams, making the proxying transparent
 * to the application.
 */

#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>

namespace proxyfire {

struct UdpRelaySession {
    SOCKET control_sock;           /* TCP control connection to SOCKS5 proxy */
    SOCKET relay_sock;             /* Local UDP socket for relay communication */
    struct sockaddr_in relay_addr; /* Proxy's UDP relay address (BND.ADDR:BND.PORT) */
    SOCKET app_sock;               /* The application's original UDP socket */
    bool active;
};

/* Initialize the UDP relay system */
void udp_relay_init();

/* Get or create a UDP relay session for a given app socket.
 * Creates the TCP control connection and UDP ASSOCIATE handshake on first call.
 * Returns nullptr if SOCKS5 is not configured or UDP ASSOCIATE fails. */
UdpRelaySession* udp_relay_get_or_create(SOCKET app_sock);

/* Send a UDP datagram through the relay (encapsulates with SOCKS5 header) */
int udp_relay_sendto(UdpRelaySession* session, const char* buf, int len,
                     const struct sockaddr* dest_addr, int dest_addrlen);

/* Receive a UDP datagram from the relay (strips SOCKS5 header) */
int udp_relay_recvfrom(UdpRelaySession* session, char* buf, int len,
                       struct sockaddr* from_addr, int* from_addrlen);

/* Close a relay session */
void udp_relay_close(SOCKET app_sock);

/* Cleanup all relay sessions */
void udp_relay_cleanup();

/* Check if a relay session exists for a socket (shared-lock lookup) */
bool udp_relay_has_session(SOCKET app_sock);

/* Get an existing relay session without creating one.
 * Returns nullptr if no active session exists. Used by recvfrom hooks
 * which should never initiate new sessions. */
UdpRelaySession* udp_relay_get(SOCKET app_sock);

} // namespace proxyfire
#endif

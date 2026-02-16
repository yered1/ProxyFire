/*
 * ProxyFire - udp_relay.cpp
 * SOCKS5 UDP ASSOCIATE relay session management (RFC 1928 Section 7)
 *
 * Manages per-socket relay sessions that tunnel UDP traffic through a
 * SOCKS5 proxy. Each session maintains:
 *   - A TCP control connection (keeps the UDP association alive)
 *   - A local UDP socket paired with the proxy's relay endpoint
 *
 * Thread safety is provided by an SRWLOCK protecting the session map.
 * The map is keyed by the application's original UDP socket handle.
 *
 * SOCKS5 UDP request header format (prepended to each datagram):
 * +------+------+------+----------+----------+----------+
 * | RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 * +------+------+------+----------+----------+----------+
 * |  2   |  1   |  1   | Variable |    2     | Variable |
 * +------+------+------+----------+----------+----------+
 */

#include "udp_relay.h"
#include "ipc_client.h"

#include <proxyfire/config.h>
#include <proxyfire/proxy_types.h>
#include <proxyfire/common.h>

#include <cstring>
#include <cstdio>
#include <map>
#include <memory>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

/* Original connect - declared in hook_winsock.cpp, needed to avoid recursive hooks */
extern int (WSAAPI *Original_connect)(SOCKET, const struct sockaddr*, int);

/* Original sendto - declared in hook_udp.cpp, needed to avoid recursive hooks */
extern int (WSAAPI *Original_sendto)(SOCKET, const char*, int, int,
                                      const struct sockaddr*, int);

/* Original recvfrom - declared in hook_udp.cpp, needed to avoid recursive hooks */
extern int (WSAAPI *Original_recvfrom)(SOCKET, char*, int, int,
                                        struct sockaddr*, int*);

/* Global config - set during DLL init */
extern ProxyFireConfig g_config;

namespace proxyfire {

/* Maximum UDP datagram size including SOCKS5 header overhead */
static const int UDP_RELAY_BUFSIZE = 65536;

/* Session map: app_sock -> UdpRelaySession */
static std::map<SOCKET, UdpRelaySession*> g_sessions;
static SRWLOCK g_sessions_lock;
static bool g_initialized = false;

/* ------------------------------------------------------------------ */
/* Helper: send all bytes on a TCP socket with timeout                */
/* ------------------------------------------------------------------ */
static int relay_send_all(SOCKET sock, const void* data, int len, uint32_t timeout_ms) {
    const char* ptr = (const char*)data;
    int remaining = len;

    if (timeout_ms > 0) {
        DWORD tv = timeout_ms;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    }

    while (remaining > 0) {
        int sent = send(sock, ptr, remaining, 0);
        if (sent <= 0) return -1;
        ptr += sent;
        remaining -= sent;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Helper: receive exactly N bytes from a TCP socket with timeout     */
/* ------------------------------------------------------------------ */
static int relay_recv_exact(SOCKET sock, void* buf, int len, uint32_t timeout_ms) {
    char* ptr = (char*)buf;
    int remaining = len;

    if (timeout_ms > 0) {
        DWORD tv = timeout_ms;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    }

    while (remaining > 0) {
        int received = recv(sock, ptr, remaining, 0);
        if (received <= 0) return -1;
        ptr += received;
        remaining -= received;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Helper: perform SOCKS5 greeting and optional authentication        */
/* Returns 0 on success, -1 on failure.                               */
/* ------------------------------------------------------------------ */
static int socks5_greet_and_auth(SOCKET sock, const char* username,
                                  const char* password, uint32_t timeout_ms) {
    uint8_t buf[515];
    bool need_auth = (username && username[0] != '\0');

    /* Phase 1: Greeting */
    if (need_auth) {
        buf[0] = 0x05;  /* SOCKS version */
        buf[1] = 0x02;  /* 2 methods */
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = SOCKS5_AUTH_USERPASS;
        if (relay_send_all(sock, buf, 4, timeout_ms) != 0) return -1;
    } else {
        buf[0] = 0x05;
        buf[1] = 0x01;  /* 1 method */
        buf[2] = SOCKS5_AUTH_NONE;
        if (relay_send_all(sock, buf, 3, timeout_ms) != 0) return -1;
    }

    /* Receive greeting response */
    if (relay_recv_exact(sock, buf, 2, timeout_ms) != 0) return -1;
    if (buf[0] != 0x05) return -1;

    uint8_t selected_method = buf[1];
    if (selected_method == SOCKS5_AUTH_REJECT) return -1;

    /* Phase 2: Authentication (if required) */
    if (selected_method == SOCKS5_AUTH_USERPASS) {
        if (!username || !password) return -1;

        uint8_t ulen = (uint8_t)strlen(username);
        uint8_t plen = (uint8_t)strlen(password);

        int pos = 0;
        buf[pos++] = 0x01;  /* Subnegotiation version */
        buf[pos++] = ulen;
        memcpy(buf + pos, username, ulen);
        pos += ulen;
        buf[pos++] = plen;
        memcpy(buf + pos, password, plen);
        pos += plen;

        if (relay_send_all(sock, buf, pos, timeout_ms) != 0) return -1;
        if (relay_recv_exact(sock, buf, 2, timeout_ms) != 0) return -1;
        if (buf[1] != 0x00) return -1;  /* Auth failed */
    } else if (selected_method != SOCKS5_AUTH_NONE) {
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Helper: send UDP ASSOCIATE command and parse BND.ADDR:BND.PORT     */
/* Returns 0 on success, fills relay_addr with the proxy's UDP relay. */
/* ------------------------------------------------------------------ */
static int socks5_udp_associate(SOCKET sock, struct sockaddr_in* relay_addr,
                                 uint32_t proxy_ip, uint32_t timeout_ms) {
    uint8_t buf[512];
    int pos = 0;

    /*
     * Send UDP ASSOCIATE request.
     * Client address is 0.0.0.0:0 meaning "the client will send from any address".
     * The proxy should accept datagrams from the TCP client's source IP.
     */
    buf[pos++] = 0x05;                       /* SOCKS version */
    buf[pos++] = SOCKS5_CMD_UDP_ASSOCIATE;   /* Command: UDP ASSOCIATE */
    buf[pos++] = 0x00;                       /* Reserved */
    buf[pos++] = SOCKS5_ATYP_IPV4;           /* Address type: IPv4 */
    buf[pos++] = 0x00; buf[pos++] = 0x00;    /* 0.0.0.0 */
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x00;    /* Port 0 */

    if (relay_send_all(sock, buf, pos, timeout_ms) != 0) {
        ipc_client_log(PF_LOG_ERROR, "UDP ASSOCIATE: failed to send request");
        return -1;
    }

    /* Receive response header: VER(1) + REP(1) + RSV(1) + ATYP(1) */
    if (relay_recv_exact(sock, buf, 4, timeout_ms) != 0) {
        ipc_client_log(PF_LOG_ERROR, "UDP ASSOCIATE: failed to receive response header");
        return -1;
    }

    if (buf[0] != 0x05) {
        ipc_client_log(PF_LOG_ERROR, "UDP ASSOCIATE: invalid SOCKS version in response: 0x%02X",
                       buf[0]);
        return -1;
    }

    if (buf[1] != SOCKS5_REPLY_SUCCESS) {
        ipc_client_log(PF_LOG_ERROR, "UDP ASSOCIATE: proxy returned error code 0x%02X", buf[1]);
        return -1;
    }

    uint8_t atyp = buf[3];

    memset(relay_addr, 0, sizeof(*relay_addr));
    relay_addr->sin_family = AF_INET;

    if (atyp == SOCKS5_ATYP_IPV4) {
        /* 4 bytes IP + 2 bytes port */
        uint8_t addr_buf[6];
        if (relay_recv_exact(sock, addr_buf, 6, timeout_ms) != 0) {
            ipc_client_log(PF_LOG_ERROR, "UDP ASSOCIATE: failed to read IPv4 bind address");
            return -1;
        }
        memcpy(&relay_addr->sin_addr.s_addr, addr_buf, 4);
        memcpy(&relay_addr->sin_port, addr_buf + 4, 2);  /* Already network byte order */
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        /* 1 byte length + domain + 2 bytes port */
        uint8_t dlen;
        if (relay_recv_exact(sock, &dlen, 1, timeout_ms) != 0) return -1;

        char domain[256];
        if (dlen >= sizeof(domain)) return -1;
        if (relay_recv_exact(sock, domain, dlen, timeout_ms) != 0) return -1;
        domain[dlen] = '\0';

        uint8_t port_buf[2];
        if (relay_recv_exact(sock, port_buf, 2, timeout_ms) != 0) return -1;
        memcpy(&relay_addr->sin_port, port_buf, 2);

        /* Resolve the domain - use the proxy's IP as fallback for 0.0.0.0 */
        struct in_addr resolved;
        if (inet_pton(AF_INET, domain, &resolved) == 1) {
            relay_addr->sin_addr.s_addr = resolved.s_addr;
        } else {
            /* Domain name - cannot resolve here, use proxy IP */
            relay_addr->sin_addr.s_addr = proxy_ip;
        }
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        /* 16 bytes IP + 2 bytes port - we don't support IPv6 relay addresses */
        ipc_client_log(PF_LOG_ERROR, "UDP ASSOCIATE: IPv6 bind address not supported");
        uint8_t skip[18];
        relay_recv_exact(sock, skip, 18, timeout_ms);
        return -1;
    } else {
        ipc_client_log(PF_LOG_ERROR, "UDP ASSOCIATE: unknown address type 0x%02X", atyp);
        return -1;
    }

    /*
     * If the proxy returns 0.0.0.0 as the bind address, it means "use the
     * proxy server's IP address" (common behavior per RFC 1928).
     */
    if (relay_addr->sin_addr.s_addr == 0) {
        relay_addr->sin_addr.s_addr = proxy_ip;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Helper: destroy a single session and free its resources            */
/* ------------------------------------------------------------------ */
static void destroy_session(UdpRelaySession* session) {
    if (!session) return;

    session->active = false;

    if (session->control_sock != INVALID_SOCKET) {
        closesocket(session->control_sock);
        session->control_sock = INVALID_SOCKET;
    }
    if (session->relay_sock != INVALID_SOCKET) {
        closesocket(session->relay_sock);
        session->relay_sock = INVALID_SOCKET;
    }

    delete session;
}

/* ================================================================== */
/* Public API                                                          */
/* ================================================================== */

void udp_relay_init() {
    InitializeSRWLock(&g_sessions_lock);
    g_initialized = true;
}

UdpRelaySession* udp_relay_get_or_create(SOCKET app_sock) {
    if (!g_initialized) return nullptr;

    /* Check if first proxy is SOCKS5 */
    if (g_config.proxy_count == 0 || g_config.proxies[0].proto != PROXY_SOCKS5) {
        return nullptr;
    }

    /* Fast path: check existing session under shared lock */
    AcquireSRWLockShared(&g_sessions_lock);
    auto it = g_sessions.find(app_sock);
    if (it != g_sessions.end() && it->second->active) {
        UdpRelaySession* session = it->second;
        ReleaseSRWLockShared(&g_sessions_lock);
        return session;
    }
    ReleaseSRWLockShared(&g_sessions_lock);

    /* Slow path: create a new session under exclusive lock */
    AcquireSRWLockExclusive(&g_sessions_lock);

    /* Double-check after acquiring exclusive lock */
    it = g_sessions.find(app_sock);
    if (it != g_sessions.end() && it->second->active) {
        UdpRelaySession* session = it->second;
        ReleaseSRWLockExclusive(&g_sessions_lock);
        return session;
    }

    /* Clean up any stale session for this socket */
    if (it != g_sessions.end()) {
        destroy_session(it->second);
        g_sessions.erase(it);
    }

    const ProxyEntry* proxy = &g_config.proxies[0];
    const char* username = proxy->username[0] ? proxy->username : nullptr;
    const char* password = proxy->password[0] ? proxy->password : nullptr;
    uint32_t timeout_ms = g_config.connect_timeout_ms;

    /* Step 1: Create TCP control connection to the SOCKS5 proxy */
    SOCKET control_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (control_sock == INVALID_SOCKET) {
        ipc_client_log(PF_LOG_ERROR, "UDP relay: failed to create TCP control socket");
        ReleaseSRWLockExclusive(&g_sessions_lock);
        return nullptr;
    }

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = proxy->ip;
    proxy_addr.sin_port = htons(proxy->port);

    int rc;
    if (Original_connect) {
        rc = Original_connect(control_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr));
    } else {
        rc = connect(control_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr));
    }

    if (rc != 0) {
        ipc_client_log(PF_LOG_ERROR, "UDP relay: failed to connect to SOCKS5 proxy %s:%u",
                       proxy->host, proxy->port);
        closesocket(control_sock);
        ReleaseSRWLockExclusive(&g_sessions_lock);
        return nullptr;
    }

    /* Step 2: SOCKS5 greeting + authentication */
    if (socks5_greet_and_auth(control_sock, username, password, timeout_ms) != 0) {
        ipc_client_log(PF_LOG_ERROR, "UDP relay: SOCKS5 greeting/auth failed");
        closesocket(control_sock);
        ReleaseSRWLockExclusive(&g_sessions_lock);
        return nullptr;
    }

    /* Step 3: Send UDP ASSOCIATE command */
    struct sockaddr_in relay_addr;
    if (socks5_udp_associate(control_sock, &relay_addr, proxy->ip, timeout_ms) != 0) {
        ipc_client_log(PF_LOG_ERROR, "UDP relay: UDP ASSOCIATE failed");
        closesocket(control_sock);
        ReleaseSRWLockExclusive(&g_sessions_lock);
        return nullptr;
    }

    /* Step 4: Create local UDP socket for relay communication */
    SOCKET relay_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (relay_sock == INVALID_SOCKET) {
        ipc_client_log(PF_LOG_ERROR, "UDP relay: failed to create relay UDP socket");
        closesocket(control_sock);
        ReleaseSRWLockExclusive(&g_sessions_lock);
        return nullptr;
    }

    /* Bind relay socket to any available port */
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0;
    if (bind(relay_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) != 0) {
        ipc_client_log(PF_LOG_ERROR, "UDP relay: failed to bind relay UDP socket");
        closesocket(relay_sock);
        closesocket(control_sock);
        ReleaseSRWLockExclusive(&g_sessions_lock);
        return nullptr;
    }

    /* Step 5: Store session in map */
    UdpRelaySession* session = new UdpRelaySession();
    session->control_sock = control_sock;
    session->relay_sock = relay_sock;
    session->relay_addr = relay_addr;
    session->app_sock = app_sock;
    session->active = true;

    g_sessions[app_sock] = session;

    char relay_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &relay_addr.sin_addr, relay_ip, sizeof(relay_ip));
    ipc_client_log(PF_LOG_INFO,
                   "UDP relay session created for socket %llu -> relay %s:%u",
                   (unsigned long long)app_sock, relay_ip, ntohs(relay_addr.sin_port));

    ReleaseSRWLockExclusive(&g_sessions_lock);
    return session;
}

int udp_relay_sendto(UdpRelaySession* session, const char* buf, int len,
                     const struct sockaddr* dest_addr, int dest_addrlen) {
    if (!session || !session->active) {
        WSASetLastError(WSAENOTCONN);
        return SOCKET_ERROR;
    }

    if (len < 0) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    /*
     * Build SOCKS5 UDP request header:
     * +------+------+------+----------+----------+----------+
     * | RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +------+------+------+----------+----------+----------+
     * |  2   |  1   |  1   | Variable |    2     | Variable |
     * +------+------+------+----------+----------+----------+
     */
    uint8_t header[512];
    int hdr_len = 0;

    /* RSV: 2 bytes reserved, must be 0x0000 */
    header[hdr_len++] = 0x00;
    header[hdr_len++] = 0x00;

    /* FRAG: fragment number, 0 = standalone datagram (no fragmentation) */
    header[hdr_len++] = 0x00;

    if (dest_addr && dest_addr->sa_family == AF_INET &&
        dest_addrlen >= (int)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)dest_addr;

        /* ATYP: IPv4 */
        header[hdr_len++] = SOCKS5_ATYP_IPV4;

        /* DST.ADDR: 4 bytes IPv4 address */
        memcpy(header + hdr_len, &sin->sin_addr.s_addr, 4);
        hdr_len += 4;

        /* DST.PORT: 2 bytes, network byte order */
        memcpy(header + hdr_len, &sin->sin_port, 2);
        hdr_len += 2;
    } else if (dest_addr && dest_addr->sa_family == AF_INET6 &&
               dest_addrlen >= (int)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)dest_addr;

        /* Check for IPv4-mapped IPv6 address */
        const uint8_t* b = sin6->sin6_addr.s6_addr;
        bool is_v4mapped = (memcmp(b, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0);

        if (is_v4mapped) {
            header[hdr_len++] = SOCKS5_ATYP_IPV4;
            memcpy(header + hdr_len, b + 12, 4);
            hdr_len += 4;
        } else {
            header[hdr_len++] = SOCKS5_ATYP_IPV6;
            memcpy(header + hdr_len, sin6->sin6_addr.s6_addr, 16);
            hdr_len += 16;
        }

        memcpy(header + hdr_len, &sin6->sin6_port, 2);
        hdr_len += 2;
    } else {
        WSASetLastError(WSAEAFNOSUPPORT);
        return SOCKET_ERROR;
    }

    /* Build combined buffer: header + application data */
    int total_len = hdr_len + len;
    if (total_len > UDP_RELAY_BUFSIZE) {
        WSASetLastError(WSAEMSGSIZE);
        return SOCKET_ERROR;
    }

    /* Use stack allocation for typical datagrams, heap for large ones */
    uint8_t stack_buf[2048];
    uint8_t* pkt_buf = (total_len <= (int)sizeof(stack_buf))
                       ? stack_buf : new uint8_t[total_len];

    memcpy(pkt_buf, header, hdr_len);
    memcpy(pkt_buf + hdr_len, buf, len);

    /* Send through the relay socket to the proxy's relay endpoint.
     * Use Original_sendto to avoid recursive hook invocation. */
    int sent;
    if (Original_sendto) {
        sent = Original_sendto(session->relay_sock, (const char*)pkt_buf, total_len, 0,
                               (struct sockaddr*)&session->relay_addr,
                               sizeof(session->relay_addr));
    } else {
        sent = sendto(session->relay_sock, (const char*)pkt_buf, total_len, 0,
                      (struct sockaddr*)&session->relay_addr,
                      sizeof(session->relay_addr));
    }

    if (pkt_buf != stack_buf) {
        delete[] pkt_buf;
    }

    if (sent == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }

    /* Return the number of application data bytes sent (not including header) */
    return len;
}

int udp_relay_recvfrom(UdpRelaySession* session, char* buf, int len,
                       struct sockaddr* from_addr, int* from_addrlen) {
    if (!session || !session->active) {
        WSASetLastError(WSAENOTCONN);
        return SOCKET_ERROR;
    }

    /* Receive from the relay socket.
     * Use heap allocation instead of a 64KB stack buffer to avoid
     * stack overflow on application threads with deep call stacks. */
    std::unique_ptr<uint8_t[]> recv_buf(new (std::nothrow) uint8_t[UDP_RELAY_BUFSIZE]);
    if (!recv_buf) {
        WSASetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }

    struct sockaddr_in sender;
    int sender_len = sizeof(sender);

    int received;
    if (Original_recvfrom) {
        received = Original_recvfrom(session->relay_sock, (char*)recv_buf.get(),
                                      UDP_RELAY_BUFSIZE, 0,
                                      (struct sockaddr*)&sender, &sender_len);
    } else {
        received = recvfrom(session->relay_sock, (char*)recv_buf.get(),
                            UDP_RELAY_BUFSIZE, 0,
                            (struct sockaddr*)&sender, &sender_len);
    }

    if (received == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }

    /*
     * Parse SOCKS5 UDP response header:
     * +------+------+------+----------+----------+----------+
     * | RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +------+------+------+----------+----------+----------+
     *
     * Minimum header: 2 (RSV) + 1 (FRAG) + 1 (ATYP) + 4 (IPv4) + 2 (PORT) = 10
     */
    if (received < 10) {
        ipc_client_log(PF_LOG_WARN, "UDP relay: received datagram too short (%d bytes)",
                       received);
        WSASetLastError(WSAEMSGSIZE);
        return SOCKET_ERROR;
    }

    /* Skip RSV (2 bytes) */
    int pos = 2;

    /* FRAG: we don't support reassembly; drop non-zero fragments */
    uint8_t frag = recv_buf[pos++];
    if (frag != 0x00) {
        ipc_client_log(PF_LOG_DEBUG, "UDP relay: dropping fragmented datagram (frag=%u)", frag);
        WSASetLastError(WSAEWOULDBLOCK);
        return SOCKET_ERROR;
    }

    /* ATYP */
    uint8_t atyp = recv_buf[pos++];

    struct sockaddr_in src_v4;
    memset(&src_v4, 0, sizeof(src_v4));
    src_v4.sin_family = AF_INET;

    if (atyp == SOCKS5_ATYP_IPV4) {
        if (pos + 6 > received) {
            WSASetLastError(WSAEMSGSIZE);
            return SOCKET_ERROR;
        }
        memcpy(&src_v4.sin_addr.s_addr, recv_buf.get() + pos, 4);
        pos += 4;
        memcpy(&src_v4.sin_port, recv_buf.get() + pos, 2);
        pos += 2;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        if (pos + 1 > received) {
            WSASetLastError(WSAEMSGSIZE);
            return SOCKET_ERROR;
        }
        uint8_t dlen = recv_buf[pos++];
        if (pos + dlen + 2 > received) {
            WSASetLastError(WSAEMSGSIZE);
            return SOCKET_ERROR;
        }
        /* We can't convert domain back to IP easily; use 0.0.0.0 */
        src_v4.sin_addr.s_addr = 0;
        pos += dlen;
        memcpy(&src_v4.sin_port, recv_buf.get() + pos, 2);
        pos += 2;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        if (pos + 18 > received) {
            WSASetLastError(WSAEMSGSIZE);
            return SOCKET_ERROR;
        }
        /* Store first 4 bytes as a rough source hint for IPv4-only callers */
        src_v4.sin_addr.s_addr = 0;
        pos += 16;
        memcpy(&src_v4.sin_port, recv_buf.get() + pos, 2);
        pos += 2;
    } else {
        ipc_client_log(PF_LOG_WARN, "UDP relay: unknown ATYP 0x%02X in response", atyp);
        WSASetLastError(WSAEMSGSIZE);
        return SOCKET_ERROR;
    }

    /* Copy source address to caller */
    if (from_addr && from_addrlen) {
        int copy_len = (*from_addrlen < (int)sizeof(src_v4))
                       ? *from_addrlen : (int)sizeof(src_v4);
        memcpy(from_addr, &src_v4, copy_len);
        *from_addrlen = sizeof(src_v4);
    }

    /* Copy application data to caller's buffer */
    int data_len = received - pos;
    if (data_len < 0) {
        ipc_client_log(PF_LOG_WARN, "UDP relay: malformed SOCKS5 header (pos=%d > received=%d)",
                       pos, received);
        WSASetLastError(WSAEMSGSIZE);
        return SOCKET_ERROR;
    }

    int copy_len = (data_len < len) ? data_len : len;
    memcpy(buf, recv_buf.get() + pos, copy_len);

    return copy_len;
}

void udp_relay_close(SOCKET app_sock) {
    if (!g_initialized) return;

    AcquireSRWLockExclusive(&g_sessions_lock);
    auto it = g_sessions.find(app_sock);
    if (it != g_sessions.end()) {
        destroy_session(it->second);
        g_sessions.erase(it);
        ipc_client_log(PF_LOG_DEBUG, "UDP relay session closed for socket %llu",
                       (unsigned long long)app_sock);
    }
    ReleaseSRWLockExclusive(&g_sessions_lock);
}

void udp_relay_cleanup() {
    if (!g_initialized) return;

    AcquireSRWLockExclusive(&g_sessions_lock);
    for (auto& pair : g_sessions) {
        destroy_session(pair.second);
    }
    g_sessions.clear();
    ReleaseSRWLockExclusive(&g_sessions_lock);

    g_initialized = false;
    ipc_client_log(PF_LOG_DEBUG, "UDP relay system cleaned up");
}

bool udp_relay_has_session(SOCKET app_sock) {
    if (!g_initialized) return false;

    AcquireSRWLockShared(&g_sessions_lock);
    auto it = g_sessions.find(app_sock);
    bool found = (it != g_sessions.end() && it->second->active);
    ReleaseSRWLockShared(&g_sessions_lock);
    return found;
}

UdpRelaySession* udp_relay_get(SOCKET app_sock) {
    if (!g_initialized) return nullptr;

    AcquireSRWLockShared(&g_sessions_lock);
    auto it = g_sessions.find(app_sock);
    UdpRelaySession* session = nullptr;
    if (it != g_sessions.end() && it->second->active) {
        session = it->second;
    }
    ReleaseSRWLockShared(&g_sessions_lock);
    return session;
}

} // namespace proxyfire

#endif /* _WIN32 */

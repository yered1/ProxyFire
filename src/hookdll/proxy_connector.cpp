/*
 * ProxyFire - proxy_connector.cpp
 * Proxy protocol handshake implementations
 *
 * Implements RFC 1928 (SOCKS5), RFC 1929 (SOCKS5 auth),
 * SOCKS4/4a, and HTTP CONNECT proxy protocols.
 */

#include "proxy_connector.h"
#include "string_utils.h"

#include <cstring>
#include <cstdio>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#define SecureZeroMemory(p, s) memset(p, 0, s)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#define WSASetLastError(e)
#define WSAGetLastError() errno
#define WSAECONNREFUSED ECONNREFUSED
#define WSAETIMEDOUT ETIMEDOUT
#define closesocket close
#endif

namespace proxyfire {

/* Helper: send all bytes with timeout */
static int send_all(SOCKET sock, const void* data, int len, uint32_t timeout_ms) {
    const char* ptr = (const char*)data;
    int remaining = len;

    /* Set send timeout */
    if (timeout_ms > 0) {
#ifdef _WIN32
        DWORD tv = timeout_ms;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
    }

    while (remaining > 0) {
        int sent = send(sock, ptr, remaining, 0);
        if (sent <= 0) return -1;
        ptr += sent;
        remaining -= sent;
    }
    return 0;
}

/* Helper: receive exactly N bytes with timeout */
static int recv_exact(SOCKET sock, void* buf, int len, uint32_t timeout_ms) {
    char* ptr = (char*)buf;
    int remaining = len;

    /* Set receive timeout */
    if (timeout_ms > 0) {
#ifdef _WIN32
        DWORD tv = timeout_ms;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
    }

    while (remaining > 0) {
        int received = recv(sock, ptr, remaining, 0);
        if (received <= 0) return -1;
        ptr += received;
        remaining -= received;
    }
    return 0;
}

/* Helper: receive a line (up to \r\n) for HTTP */
static int recv_line(SOCKET sock, char* buf, int maxlen, uint32_t timeout_ms) {
    int pos = 0;

    if (timeout_ms > 0) {
#ifdef _WIN32
        DWORD tv = timeout_ms;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
    }

    while (pos < maxlen - 1) {
        char c;
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) return -1;

        buf[pos++] = c;
        if (pos >= 2 && buf[pos - 2] == '\r' && buf[pos - 1] == '\n') {
            buf[pos] = '\0';
            return pos;
        }
    }

    buf[pos] = '\0';
    return pos;
}

/*
 * SOCKS5 Handshake (RFC 1928 + RFC 1929)
 *
 * Phase 1 - Greeting:
 *   Client -> Proxy:  05 <nmethods> <methods...>
 *   Proxy -> Client:  05 <method>
 *
 * Phase 2 - Auth (if method 0x02):
 *   Client -> Proxy:  01 <ulen> <user> <plen> <pass>
 *   Proxy -> Client:  01 <status>
 *
 * Phase 3 - Connect:
 *   Client -> Proxy:  05 01 00 <atyp> <addr> <port>
 *   Proxy -> Client:  05 <rep> 00 <atyp> <addr> <port>
 */
int socks5_handshake(
    SOCKET sock, const char* dest_host, uint32_t dest_ip, uint16_t dest_port,
    const char* username, const char* password, uint32_t timeout_ms,
    const uint8_t* dest_ipv6)
{
    uint8_t buf[512];
    bool need_auth = (username && username[0] != '\0');

    /* Phase 1: Greeting */
    if (need_auth) {
        buf[0] = 0x05;  /* SOCKS version */
        buf[1] = 0x02;  /* 2 methods */
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = SOCKS5_AUTH_USERPASS;
        if (send_all(sock, buf, 4, timeout_ms) != 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }
    } else {
        buf[0] = 0x05;
        buf[1] = 0x01;  /* 1 method */
        buf[2] = SOCKS5_AUTH_NONE;
        if (send_all(sock, buf, 3, timeout_ms) != 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }
    }

    /* Receive greeting response */
    if (recv_exact(sock, buf, 2, timeout_ms) != 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    if (buf[0] != 0x05) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    uint8_t selected_method = buf[1];

    if (selected_method == SOCKS5_AUTH_REJECT) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    /* Phase 2: Authentication (if required) */
    if (selected_method == SOCKS5_AUTH_USERPASS) {
        if (!username || !password) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }

        uint8_t ulen = (uint8_t)strlen(username);
        uint8_t plen = (uint8_t)strlen(password);

        uint8_t auth_buf[515];
        int pos = 0;
        auth_buf[pos++] = 0x01;  /* Subnegotiation version */
        auth_buf[pos++] = ulen;
        memcpy(auth_buf + pos, username, ulen);
        pos += ulen;
        auth_buf[pos++] = plen;
        memcpy(auth_buf + pos, password, plen);
        pos += plen;

        if (send_all(sock, auth_buf, pos, timeout_ms) != 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }

        if (recv_exact(sock, buf, 2, timeout_ms) != 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }

        if (buf[1] != 0x00) {
            /* Authentication failed */
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }
    } else if (selected_method != SOCKS5_AUTH_NONE) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    /* Phase 3: Connect request */
    int pos = 0;
    buf[pos++] = 0x05;                  /* SOCKS version */
    buf[pos++] = SOCKS5_CMD_CONNECT;    /* Command: CONNECT */
    buf[pos++] = 0x00;                  /* Reserved */

    if (dest_ipv6) {
        /* Use IPv6 address (16 bytes) */
        buf[pos++] = SOCKS5_ATYP_IPV6;
        memcpy(buf + pos, dest_ipv6, 16);
        pos += 16;
    } else if (dest_host && dest_host[0] != '\0') {
        /* Use domain name (remote DNS resolution) */
        size_t host_len = strlen(dest_host);
        if (host_len > 255) {
            /* SOCKS5 domain length is a single byte - max 255 */
            WSASetLastError(WSAENAMETOOLONG);
            return -1;
        }
        uint8_t dlen = (uint8_t)host_len;
        buf[pos++] = SOCKS5_ATYP_DOMAIN;
        buf[pos++] = dlen;
        memcpy(buf + pos, dest_host, dlen);
        pos += dlen;
    } else {
        /* Use IPv4 address */
        buf[pos++] = SOCKS5_ATYP_IPV4;
        memcpy(buf + pos, &dest_ip, 4);
        pos += 4;
    }

    /* Port (network byte order) */
    uint16_t port_net = htons(dest_port);
    memcpy(buf + pos, &port_net, 2);
    pos += 2;

    if (send_all(sock, buf, pos, timeout_ms) != 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    /* Receive connect response (at least 10 bytes for IPv4) */
    if (recv_exact(sock, buf, 4, timeout_ms) != 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    if (buf[0] != 0x05 || buf[1] != SOCKS5_REPLY_SUCCESS) {
        /* Map SOCKS5 error to Winsock error */
        switch (buf[1]) {
            case SOCKS5_REPLY_CONN_REFUSED:
                WSASetLastError(WSAECONNREFUSED);
                break;
            case SOCKS5_REPLY_NET_UNREACHABLE:
            case SOCKS5_REPLY_HOST_UNREACHABLE:
                WSASetLastError(WSAECONNREFUSED);
                break;
            case SOCKS5_REPLY_TTL_EXPIRED:
                WSASetLastError(WSAETIMEDOUT);
                break;
            default:
                WSASetLastError(WSAECONNREFUSED);
                break;
        }
        return -1;
    }

    /* Read remaining bind address based on address type */
    uint8_t atyp = buf[3];
    if (atyp == SOCKS5_ATYP_IPV4) {
        /* 4 bytes IP + 2 bytes port */
        if (recv_exact(sock, buf, 6, timeout_ms) != 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        /* 16 bytes IP + 2 bytes port */
        if (recv_exact(sock, buf, 18, timeout_ms) != 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        /* 1 byte len + domain + 2 bytes port */
        uint8_t dlen;
        if (recv_exact(sock, &dlen, 1, timeout_ms) != 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }
        if (recv_exact(sock, buf, dlen + 2, timeout_ms) != 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }
    } else {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    return 0;
}

/*
 * SOCKS4 Handshake
 *
 * Client -> Proxy:  04 01 <port:2> <ip:4> <userid> 00
 * Proxy -> Client:  00 <status> <port:2> <ip:4>
 */
int socks4_handshake(
    SOCKET sock, uint32_t dest_ip, uint16_t dest_port,
    const char* username, uint32_t timeout_ms)
{
    uint8_t buf[512];
    int pos = 0;

    buf[pos++] = 0x04;          /* SOCKS version */
    buf[pos++] = 0x01;          /* CONNECT command */

    /* Port (network byte order) */
    uint16_t port_net = htons(dest_port);
    memcpy(buf + pos, &port_net, 2);
    pos += 2;

    /* Destination IP (already network byte order) */
    memcpy(buf + pos, &dest_ip, 4);
    pos += 4;

    /* User ID (can be empty) */
    if (username && username[0] != '\0') {
        size_t ulen = strlen(username);
        memcpy(buf + pos, username, ulen);
        pos += (int)ulen;
    }
    buf[pos++] = 0x00;  /* Null terminator for userid */

    if (send_all(sock, buf, pos, timeout_ms) != 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    /* Receive response: 8 bytes */
    if (recv_exact(sock, buf, 8, timeout_ms) != 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    if (buf[1] != SOCKS4_REPLY_GRANTED) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    return 0;
}

/*
 * SOCKS4a Handshake
 *
 * Like SOCKS4 but with hostname support:
 * Client -> Proxy:  04 01 <port:2> 00 00 00 <nonzero> <userid> 00 <hostname> 00
 * Proxy -> Client:  00 <status> <port:2> <ip:4>
 */
int socks4a_handshake(
    SOCKET sock, const char* dest_host, uint32_t dest_ip, uint16_t dest_port,
    const char* username, uint32_t timeout_ms)
{
    uint8_t buf[512];
    int pos = 0;

    buf[pos++] = 0x04;          /* SOCKS version */
    buf[pos++] = 0x01;          /* CONNECT command */

    /* Port (network byte order) */
    uint16_t port_net = htons(dest_port);
    memcpy(buf + pos, &port_net, 2);
    pos += 2;

    if (dest_host && dest_host[0] != '\0') {
        /* SOCKS4a: Use deliberate invalid IP 0.0.0.x where x > 0 */
        buf[pos++] = 0x00;
        buf[pos++] = 0x00;
        buf[pos++] = 0x00;
        buf[pos++] = 0x01;  /* 0.0.0.1 = trigger SOCKS4a hostname mode */
    } else {
        /* Use real IP */
        memcpy(buf + pos, &dest_ip, 4);
        pos += 4;
    }

    /* User ID */
    if (username && username[0] != '\0') {
        size_t ulen = strlen(username);
        memcpy(buf + pos, username, ulen);
        pos += (int)ulen;
    }
    buf[pos++] = 0x00;  /* Null terminator for userid */

    /* Append hostname for SOCKS4a */
    if (dest_host && dest_host[0] != '\0') {
        size_t hlen = strlen(dest_host);
        if (pos + hlen + 1 > sizeof(buf)) {
            /* Hostname too long for SOCKS4a packet buffer */
            WSASetLastError(WSAENAMETOOLONG);
            return -1;
        }
        memcpy(buf + pos, dest_host, hlen);
        pos += (int)hlen;
        buf[pos++] = 0x00;  /* Null terminator for hostname */
    }

    if (send_all(sock, buf, pos, timeout_ms) != 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    /* Receive response: 8 bytes */
    if (recv_exact(sock, buf, 8, timeout_ms) != 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    if (buf[1] != SOCKS4_REPLY_GRANTED) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    return 0;
}

/*
 * HTTP CONNECT Handshake
 *
 * Client -> Proxy:
 *   CONNECT host:port HTTP/1.1\r\n
 *   Host: host:port\r\n
 *   [Proxy-Authorization: Basic base64(user:pass)\r\n]
 *   \r\n
 *
 * Proxy -> Client:
 *   HTTP/1.x 200 ...\r\n
 *   ...\r\n
 *   \r\n
 */
int http_connect_handshake(
    SOCKET sock, const char* dest_host, uint32_t dest_ip, uint16_t dest_port,
    const char* username, const char* password, uint32_t timeout_ms,
    const uint8_t* dest_ipv6)
{
    /* Build target string */
    std::string target;
    if (dest_ipv6) {
        /* IPv6: use bracket notation [addr]:port */
        char ipv6_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, dest_ipv6, ipv6_str, sizeof(ipv6_str));
        target = "[" + std::string(ipv6_str) + "]:" + std::to_string(dest_port);
    } else if (dest_host && dest_host[0] != '\0') {
        target = std::string(dest_host) + ":" + std::to_string(dest_port);
    } else {
        target = ip_to_string(dest_ip) + ":" + std::to_string(dest_port);
    }

    /* Build HTTP CONNECT request */
    std::string request;
    request = "CONNECT " + target + " HTTP/1.1\r\n";
    request += "Host: " + target + "\r\n";

    /* Add proxy authentication if provided */
    if (username && username[0] != '\0') {
        std::string credentials = std::string(username);
        if (password && password[0] != '\0') {
            credentials += ":" + std::string(password);
        }
        std::string encoded = base64_encode(credentials);
        request += "Proxy-Authorization: Basic " + encoded + "\r\n";
        /* Securely clear credentials from memory */
        SecureZeroMemory(&credentials[0], credentials.size());
        SecureZeroMemory(&encoded[0], encoded.size());
    }

    request += "Proxy-Connection: keep-alive\r\n";
    request += "\r\n";

    if (send_all(sock, request.c_str(), (int)request.size(), timeout_ms) != 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    /* Read response status line */
    char line[1024];
    if (recv_line(sock, line, sizeof(line), timeout_ms) < 0) {
        WSASetLastError(WSAECONNREFUSED);
        return -1;
    }

    /*
     * Parse HTTP status code from status line.
     * Accept both HTTP/1.x and HTTP/2 response formats.
     * Format: "HTTP/X.Y NNN reason\r\n" or "HTTP/X NNN reason\r\n"
     */
    int status_code = 0;
    if (strncmp(line, "HTTP/", 5) == 0) {
        /* Find the space before the status code */
        const char* space = strchr(line + 5, ' ');
        if (space) {
            status_code = atoi(space + 1);
        }
    }

    if (status_code < 200 || status_code >= 300) {
        if (status_code == 407) {
            /* Proxy authentication required */
            WSASetLastError(WSAEACCES);
        } else if (status_code == 403) {
            WSASetLastError(WSAEACCES);
        } else {
            WSASetLastError(WSAECONNREFUSED);
        }
        return -1;
    }

    /* Read remaining headers until empty line.
     * Limit to 64 headers to prevent infinite loops from malformed proxies. */
    int max_headers = 64;
    while (max_headers-- > 0) {
        if (recv_line(sock, line, sizeof(line), timeout_ms) < 0) {
            WSASetLastError(WSAECONNREFUSED);
            return -1;
        }
        /* Empty line (just \r\n) means end of headers */
        if (strcmp(line, "\r\n") == 0 || strcmp(line, "\n") == 0) {
            break;
        }
    }

    return 0;
}

/*
 * Main proxy_handshake dispatcher
 */
int proxy_handshake(
    SOCKET          sock,
    ProxyProto      proto,
    const char*     dest_host,
    uint32_t        dest_ip,
    uint16_t        dest_port,
    const char*     username,
    const char*     password,
    uint32_t        timeout_ms,
    const uint8_t*  dest_ipv6)
{
    switch (proto) {
        case PROXY_SOCKS5:
            return socks5_handshake(sock, dest_host, dest_ip, dest_port,
                                    username, password, timeout_ms, dest_ipv6);

        case PROXY_SOCKS4:
            return socks4_handshake(sock, dest_ip, dest_port,
                                    username, timeout_ms);

        case PROXY_SOCKS4A:
            return socks4a_handshake(sock, dest_host, dest_ip, dest_port,
                                     username, timeout_ms);

        case PROXY_HTTP:
            return http_connect_handshake(sock, dest_host, dest_ip, dest_port,
                                          username, password, timeout_ms,
                                          dest_ipv6);

        default:
            WSASetLastError(WSAECONNREFUSED);
            return -1;
    }
}

} // namespace proxyfire

/*
 * ProxyFire - proxy_uri.cpp
 * Parse proxy URI strings
 */

#include "proxy_uri.h"
#include <cstring>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

namespace proxyfire {

bool parse_proxy_uri(const char* uri, ProxyEntry* out, std::string* error) {
    if (!uri || !out) {
        if (error) *error = "null argument";
        return false;
    }

    memset(out, 0, sizeof(ProxyEntry));
    std::string s(uri);

    /* Parse scheme */
    size_t scheme_end = s.find("://");
    if (scheme_end == std::string::npos) {
        if (error) *error = "missing :// in URI";
        return false;
    }

    std::string scheme = s.substr(0, scheme_end);
    if (scheme == "socks5") {
        out->proto = PROXY_SOCKS5;
    } else if (scheme == "socks4a") {
        out->proto = PROXY_SOCKS4A;
    } else if (scheme == "socks4") {
        out->proto = PROXY_SOCKS4;
    } else if (scheme == "http" || scheme == "https") {
        out->proto = PROXY_HTTP;
    } else {
        if (error) *error = "unsupported scheme: " + scheme;
        return false;
    }

    std::string rest = s.substr(scheme_end + 3);

    /* Parse user:pass@ if present */
    size_t at_pos = rest.find('@');
    if (at_pos != std::string::npos) {
        std::string userpass = rest.substr(0, at_pos);
        rest = rest.substr(at_pos + 1);

        size_t colon = userpass.find(':');
        if (colon != std::string::npos) {
            std::string user = userpass.substr(0, colon);
            std::string pass = userpass.substr(colon + 1);

            if (user.length() >= sizeof(out->username)) {
                if (error) *error = "username too long";
                return false;
            }
            if (pass.length() >= sizeof(out->password)) {
                if (error) *error = "password too long";
                return false;
            }

            strncpy(out->username, user.c_str(), sizeof(out->username) - 1);
            strncpy(out->password, pass.c_str(), sizeof(out->password) - 1);
        } else {
            /* Username only, no password */
            if (userpass.length() >= sizeof(out->username)) {
                if (error) *error = "username too long";
                return false;
            }
            strncpy(out->username, userpass.c_str(), sizeof(out->username) - 1);
        }
    }

    /* Parse host:port */
    /* Handle IPv6 bracket notation: [::1]:port */
    std::string host;
    std::string port_str;

    if (!rest.empty() && rest[0] == '[') {
        /* IPv6 address */
        size_t bracket_end = rest.find(']');
        if (bracket_end == std::string::npos) {
            if (error) *error = "missing closing bracket for IPv6 address";
            return false;
        }
        host = rest.substr(1, bracket_end - 1);
        if (bracket_end + 1 < rest.length() && rest[bracket_end + 1] == ':') {
            port_str = rest.substr(bracket_end + 2);
        }
    } else {
        /* IPv4 or hostname */
        size_t last_colon = rest.rfind(':');
        if (last_colon == std::string::npos) {
            if (error) *error = "missing port number";
            return false;
        }
        host = rest.substr(0, last_colon);
        port_str = rest.substr(last_colon + 1);
    }

    /* Remove trailing slash if present */
    while (!port_str.empty() && port_str.back() == '/') {
        port_str.pop_back();
    }

    if (host.empty()) {
        if (error) *error = "empty host";
        return false;
    }
    if (port_str.empty()) {
        if (error) *error = "empty port";
        return false;
    }

    if (host.length() >= sizeof(out->host)) {
        if (error) *error = "hostname too long";
        return false;
    }
    strncpy(out->host, host.c_str(), sizeof(out->host) - 1);

    int port = atoi(port_str.c_str());
    if (port <= 0 || port > 65535) {
        if (error) *error = "invalid port number: " + port_str;
        return false;
    }
    out->port = (uint16_t)port;

    return true;
}

std::string format_proxy_uri(const ProxyEntry& entry) {
    std::string result;

    switch (entry.proto) {
        case PROXY_SOCKS4:  result = "socks4://"; break;
        case PROXY_SOCKS4A: result = "socks4a://"; break;
        case PROXY_SOCKS5:  result = "socks5://"; break;
        case PROXY_HTTP:    result = "http://"; break;
        default:            result = "unknown://"; break;
    }

    result += entry.host;
    result += ":";
    result += std::to_string(entry.port);

    return result;
}

uint32_t resolve_hostname(const char* hostname) {
    if (!hostname) return 0;

    /* Try as numeric IP first */
    uint32_t addr = inet_addr(hostname);
    if (addr != INADDR_NONE) {
        return addr;
    }

#ifdef _WIN32
    struct addrinfo hints = {};
    struct addrinfo* result = nullptr;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0) {
        return 0;
    }

    uint32_t ip = 0;
    if (result && result->ai_addr) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)result->ai_addr;
        ip = addr4->sin_addr.s_addr;
    }

    freeaddrinfo(result);
    return ip;
#else
    struct hostent* he = gethostbyname(hostname);
    if (!he || !he->h_addr_list[0]) return 0;
    return *(uint32_t*)he->h_addr_list[0];
#endif
}

} // namespace proxyfire

/*
 * ProxyFire - string_utils.cpp
 * String conversion and formatting utilities
 */

#include "string_utils.h"

#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace proxyfire {

std::wstring to_wide(const std::string& str) {
    if (str.empty()) return {};
#ifdef _WIN32
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring result(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], sz);
    return result;
#else
    /* Simple ASCII conversion for non-Windows */
    return std::wstring(str.begin(), str.end());
#endif
}

std::string to_narrow(const std::wstring& wstr) {
    if (wstr.empty()) return {};
#ifdef _WIN32
    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string result(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], sz, nullptr, nullptr);
    return result;
#else
    return std::string(wstr.begin(), wstr.end());
#endif
}

std::string ip_to_string(uint32_t ip_network_order) {
    unsigned char* b = (unsigned char*)&ip_network_order;
    char buf[32];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

uint32_t string_to_ip(const char* str) {
    if (!str) return 0;
    return inet_addr(str);
}

std::string format_endpoint(uint32_t ip_network_order, uint16_t port_host_order) {
    return ip_to_string(ip_network_order) + ":" + std::to_string(port_host_order);
}

bool parse_cidr(const char* cidr, uint32_t* ip, uint32_t* mask) {
    if (!cidr || !ip || !mask) return false;

    std::string s(cidr);
    size_t slash = s.find('/');

    if (slash == std::string::npos) {
        /* No CIDR prefix - treat as /32 */
        *ip = inet_addr(s.c_str());
        *mask = 0xFFFFFFFF;
        return *ip != INADDR_NONE;
    }

    std::string ip_str = s.substr(0, slash);
    std::string prefix_str = s.substr(slash + 1);

    *ip = inet_addr(ip_str.c_str());
    if (*ip == INADDR_NONE && ip_str != "255.255.255.255") {
        return false;
    }

    int prefix = atoi(prefix_str.c_str());
    if (prefix < 0 || prefix > 32) return false;

    if (prefix == 0) {
        *mask = 0;
    } else {
        *mask = htonl(0xFFFFFFFF << (32 - prefix));
    }

    /* Normalize IP to network address */
    *ip = *ip & *mask;

    return true;
}

bool ip_matches_cidr(uint32_t ip, uint32_t rule_ip, uint32_t rule_mask) {
    return (ip & rule_mask) == (rule_ip & rule_mask);
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& input) {
    std::string result;
    result.reserve(((input.size() + 2) / 3) * 4);

    const unsigned char* bytes = (const unsigned char*)input.c_str();
    size_t len = input.size();

    for (size_t i = 0; i < len; i += 3) {
        unsigned int triple = (bytes[i] << 16);
        if (i + 1 < len) triple |= (bytes[i + 1] << 8);
        if (i + 2 < len) triple |= bytes[i + 2];

        result += base64_chars[(triple >> 18) & 0x3F];
        result += base64_chars[(triple >> 12) & 0x3F];
        result += (i + 1 < len) ? base64_chars[(triple >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? base64_chars[triple & 0x3F] : '=';
    }

    return result;
}

std::string timestamp_now() {
    time_t now = time(nullptr);
    struct tm* tm_info = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

#ifdef _WIN32
std::string format_win_error(unsigned long error_code) {
    char* msg = nullptr;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msg, 0, nullptr);

    std::string result;
    if (msg) {
        result = msg;
        LocalFree(msg);
        /* Remove trailing newline */
        while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
            result.pop_back();
        }
    } else {
        result = "Unknown error " + std::to_string(error_code);
    }
    return result;
}
#endif

} // namespace proxyfire

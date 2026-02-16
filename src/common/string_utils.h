/*
 * ProxyFire - string_utils.h
 * String conversion and formatting utilities
 */

#pragma once

#include <string>
#include <cstdint>

namespace proxyfire {

/* Wide string <-> narrow string conversion */
std::wstring to_wide(const std::string& str);
std::string to_narrow(const std::wstring& wstr);

/* Format an IPv4 address (network byte order) as string */
std::string ip_to_string(uint32_t ip_network_order);

/* Parse an IPv4 string to network byte order */
uint32_t string_to_ip(const char* str);

/* Format ip:port */
std::string format_endpoint(uint32_t ip_network_order, uint16_t port_host_order);

/* Parse CIDR notation: "192.168.1.0/24" -> ip and mask */
bool parse_cidr(const char* cidr, uint32_t* ip, uint32_t* mask);

/* Check if an IP matches a CIDR rule */
bool ip_matches_cidr(uint32_t ip, uint32_t rule_ip, uint32_t rule_mask);

/* Trim whitespace from string */
std::string trim(const std::string& s);

/* Base64 encode (for HTTP Proxy-Authorization) */
std::string base64_encode(const std::string& input);

/* Get current timestamp as string */
std::string timestamp_now();

/* Format Windows error code to string */
#ifdef _WIN32
std::string format_win_error(unsigned long error_code);
#endif

} // namespace proxyfire

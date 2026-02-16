/*
 * ProxyFire - proxy_uri.h
 * Parse proxy URI strings: protocol://[user:pass@]host:port
 */

#pragma once

#include <proxyfire/proxy_types.h>
#include <string>

namespace proxyfire {

/**
 * Parse a proxy URI string into a ProxyEntry.
 *
 * Supported schemes:
 *   socks5://[user:pass@]host:port
 *   socks4://host:port
 *   socks4a://host:port
 *   http://[user:pass@]host:port
 *
 * Returns true on success, false on parse error.
 */
bool parse_proxy_uri(const char* uri, ProxyEntry* out, std::string* error = nullptr);

/**
 * Format a ProxyEntry back to a URI string (without credentials).
 */
std::string format_proxy_uri(const ProxyEntry& entry);

/**
 * Resolve a hostname to an IPv4 address.
 * Returns the IP in network byte order, or 0 on failure.
 */
uint32_t resolve_hostname(const char* hostname);

} // namespace proxyfire

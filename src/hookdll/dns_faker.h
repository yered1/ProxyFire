/*
 * ProxyFire - dns_faker.h
 * Fake DNS IP allocation and lookup for DNS leak prevention
 *
 * Allocates fake IPs from the 240.0.0.0/4 range for hostnames.
 * When connect() sees a fake IP, it looks up the original hostname
 * and passes it to the SOCKS5 proxy for remote DNS resolution.
 */

#pragma once

#include <cstdint>

namespace proxyfire {

/**
 * Initialize the DNS faker system.
 */
void dns_faker_init();

/**
 * Allocate a fake IP for a hostname.
 * Returns the fake IP in network byte order.
 * If the hostname already has a mapping, returns the existing fake IP.
 * Thread-safe.
 */
uint32_t dns_faker_allocate(const char* hostname);

/**
 * Look up the hostname for a fake IP.
 * Returns the hostname string, or NULL if the IP is not a known fake IP.
 * Thread-safe. The returned pointer is valid for the lifetime of the mapping.
 */
const char* dns_faker_lookup(uint32_t fake_ip_network_order);

/**
 * Check if an IP is in the fake IP range.
 */
bool dns_faker_is_fake(uint32_t ip_network_order);

/**
 * Get current allocation count (for diagnostics).
 */
uint32_t dns_faker_count();

/**
 * Cleanup all allocations.
 */
void dns_faker_cleanup();

} // namespace proxyfire

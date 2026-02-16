/*
 * ProxyFire - dns_faker.cpp
 * Fake DNS IP allocation and lookup
 */

#include "dns_faker.h"
#include <proxyfire/common.h>

#include <cstring>
#include <string>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <pthread.h>
#endif

namespace proxyfire {

/* Thread-safe lock */
#ifdef _WIN32
static SRWLOCK g_dns_lock = SRWLOCK_INIT;
#define DNS_LOCK_READ()    AcquireSRWLockShared(&g_dns_lock)
#define DNS_UNLOCK_READ()  ReleaseSRWLockShared(&g_dns_lock)
#define DNS_LOCK_WRITE()   AcquireSRWLockExclusive(&g_dns_lock)
#define DNS_UNLOCK_WRITE() ReleaseSRWLockExclusive(&g_dns_lock)
#else
static pthread_rwlock_t g_dns_lock = PTHREAD_RWLOCK_INITIALIZER;
#define DNS_LOCK_READ()    pthread_rwlock_rdlock(&g_dns_lock)
#define DNS_UNLOCK_READ()  pthread_rwlock_unlock(&g_dns_lock)
#define DNS_LOCK_WRITE()   pthread_rwlock_wrlock(&g_dns_lock)
#define DNS_UNLOCK_WRITE() pthread_rwlock_unlock(&g_dns_lock)
#endif

/* Maps: hostname -> fake_ip (host byte order) */
static std::unordered_map<std::string, uint32_t>* g_hostname_to_ip = nullptr;

/* Maps: fake_ip (host byte order) -> hostname */
static std::unordered_map<uint32_t, std::string>* g_ip_to_hostname = nullptr;

/* Next available fake IP (host byte order) */
static uint32_t g_next_fake_ip = PROXYFIRE_FAKE_IP_BASE;

void dns_faker_init() {
    DNS_LOCK_WRITE();
    if (!g_hostname_to_ip) {
        g_hostname_to_ip = new std::unordered_map<std::string, uint32_t>();
    }
    if (!g_ip_to_hostname) {
        g_ip_to_hostname = new std::unordered_map<uint32_t, std::string>();
    }
    g_next_fake_ip = PROXYFIRE_FAKE_IP_BASE;
    DNS_UNLOCK_WRITE();
}

uint32_t dns_faker_allocate(const char* hostname) {
    if (!hostname || hostname[0] == '\0') return 0;

    std::string host(hostname);

    /* Check if already allocated (shared lock) */
    DNS_LOCK_READ();
    if (g_hostname_to_ip) {
        auto it = g_hostname_to_ip->find(host);
        if (it != g_hostname_to_ip->end()) {
            uint32_t ip = htonl(it->second);
            DNS_UNLOCK_READ();
            return ip;
        }
    }
    DNS_UNLOCK_READ();

    /* Allocate new (exclusive lock) */
    DNS_LOCK_WRITE();

    /* Double-check after acquiring write lock */
    if (g_hostname_to_ip) {
        auto it = g_hostname_to_ip->find(host);
        if (it != g_hostname_to_ip->end()) {
            uint32_t ip = htonl(it->second);
            DNS_UNLOCK_WRITE();
            return ip;
        }
    }

    if (g_next_fake_ip >= PROXYFIRE_FAKE_IP_MAX) {
        /* Exhausted fake IP range (very unlikely) */
        DNS_UNLOCK_WRITE();
        return 0;
    }

    /*
     * Memory management: if maps grow beyond 100k entries, clear and
     * restart. This prevents unbounded memory growth in long-running
     * processes that resolve many unique hostnames. The trade-off is
     * that previously cached hostnames need re-allocation, but this
     * is acceptable since the proxy handles DNS resolution anyway.
     */
    if (g_hostname_to_ip && g_hostname_to_ip->size() > 100000) {
        g_hostname_to_ip->clear();
        g_ip_to_hostname->clear();
        g_next_fake_ip = PROXYFIRE_FAKE_IP_BASE;
    }

    uint32_t fake_ip_host = g_next_fake_ip++;

    if (g_hostname_to_ip) {
        (*g_hostname_to_ip)[host] = fake_ip_host;
    }
    if (g_ip_to_hostname) {
        (*g_ip_to_hostname)[fake_ip_host] = host;
    }

    DNS_UNLOCK_WRITE();

    return htonl(fake_ip_host);
}

const char* dns_faker_lookup(uint32_t fake_ip_network_order) {
    uint32_t ip_host = ntohl(fake_ip_network_order);

    DNS_LOCK_READ();
    if (g_ip_to_hostname) {
        auto it = g_ip_to_hostname->find(ip_host);
        if (it != g_ip_to_hostname->end()) {
            /*
             * Copy to thread-local storage so the pointer remains valid after
             * releasing the lock. Without this, concurrent map inserts could
             * trigger a rehash, invalidating the returned c_str() pointer.
             */
            thread_local std::string tls_result;
            tls_result = it->second;
            DNS_UNLOCK_READ();
            return tls_result.c_str();
        }
    }
    DNS_UNLOCK_READ();

    return nullptr;
}

bool dns_faker_is_fake(uint32_t ip_network_order) {
    uint32_t ip_host = ntohl(ip_network_order);
    return (ip_host >= PROXYFIRE_FAKE_IP_BASE && ip_host <= PROXYFIRE_FAKE_IP_MAX);
}

uint32_t dns_faker_count() {
    DNS_LOCK_READ();
    uint32_t count = g_hostname_to_ip ? (uint32_t)g_hostname_to_ip->size() : 0;
    DNS_UNLOCK_READ();
    return count;
}

void dns_faker_cleanup() {
    DNS_LOCK_WRITE();
    if (g_hostname_to_ip) {
        delete g_hostname_to_ip;
        g_hostname_to_ip = nullptr;
    }
    if (g_ip_to_hostname) {
        delete g_ip_to_hostname;
        g_ip_to_hostname = nullptr;
    }
    g_next_fake_ip = PROXYFIRE_FAKE_IP_BASE;
    DNS_UNLOCK_WRITE();
}

} // namespace proxyfire

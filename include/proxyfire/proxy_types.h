/*
 * ProxyFire - Transparent Proxy Wrapper for Windows
 *
 * proxy_types.h - Proxy protocol types and data structures
 */

#pragma once

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

/* Proxy protocol types */
typedef enum ProxyProto {
    PROXY_SOCKS4     = 0,
    PROXY_SOCKS4A    = 1,
    PROXY_SOCKS5     = 2,
    PROXY_HTTP       = 3   /* HTTP CONNECT */
} ProxyProto;

/* Single proxy entry in a chain */
typedef struct ProxyEntry {
    ProxyProto  proto;
    char        host[256];
    uint32_t    ip;             /* Network byte order, resolved by launcher */
    uint16_t    port;           /* Host byte order */
    char        username[256];
    char        password[256];
} ProxyEntry;

/* SOCKS5 authentication methods */
#define SOCKS5_AUTH_NONE     0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_REJECT   0xFF

/* SOCKS5 address types */
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6   0x04

/* SOCKS5 command types */
#define SOCKS5_CMD_CONNECT       0x01
#define SOCKS5_CMD_BIND          0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/* SOCKS5 reply codes */
#define SOCKS5_REPLY_SUCCESS          0x00
#define SOCKS5_REPLY_GENERAL_FAILURE  0x01
#define SOCKS5_REPLY_NOT_ALLOWED      0x02
#define SOCKS5_REPLY_NET_UNREACHABLE  0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_CONN_REFUSED     0x05
#define SOCKS5_REPLY_TTL_EXPIRED      0x06
#define SOCKS5_REPLY_CMD_NOT_SUPPORT  0x07
#define SOCKS5_REPLY_ADDR_NOT_SUPPORT 0x08

/* SOCKS4 reply codes */
#define SOCKS4_REPLY_GRANTED 0x5A
#define SOCKS4_REPLY_REJECTED 0x5B

/* Convert ProxyProto to string */
#ifdef __cplusplus
inline const char* proxy_proto_name(ProxyProto p) {
    switch (p) {
        case PROXY_SOCKS4:  return "SOCKS4";
        case PROXY_SOCKS4A: return "SOCKS4a";
        case PROXY_SOCKS5:  return "SOCKS5";
        case PROXY_HTTP:    return "HTTP";
        default:            return "UNKNOWN";
    }
}
#endif

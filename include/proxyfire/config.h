/*
 * ProxyFire - Transparent Proxy Wrapper for Windows
 *
 * config.h - Configuration structures
 */

#pragma once

#include "common.h"
#include "proxy_types.h"

#ifdef _WIN32
#include <windows.h>
#else
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#endif

#ifdef __cplusplus
#include <cstdint>
#include <cstring>
#else
#include <stdint.h>
#include <string.h>
#endif

/* Bypass rule: IP/CIDR */
typedef struct BypassRule {
    uint32_t ip;    /* Network byte order */
    uint32_t mask;  /* Network byte order (CIDR mask) */
} BypassRule;

/* Full ProxyFire configuration - shared between launcher and hook DLL */
typedef struct ProxyFireConfig {
    /* Proxy chain (ordered list) */
    uint32_t    proxy_count;
    ProxyEntry  proxies[PROXYFIRE_MAX_PROXIES];

    /* Behavior flags */
    uint8_t     dns_leak_prevention;    /* 1 = intercept DNS and use remote resolution */
    uint8_t     inject_children;        /* 1 = inject hook DLL into child processes */
    uint8_t     verbose;                /* 1 = verbose logging */
    uint32_t    connect_timeout_ms;     /* Timeout for proxy connections */

    /* Bypass rules */
    uint32_t    bypass_count;
    BypassRule  bypass_rules[PROXYFIRE_MAX_BYPASS_RULES];

    /* IPC pipe name (for child processes to connect) */
    wchar_t     pipe_name[256];

    /* Logging */
    uint8_t     log_level;              /* ProxyFireLogLevel */
    char        log_file[MAX_PATH];     /* Empty = no file logging */
} ProxyFireConfig;

#ifdef __cplusplus
/* Initialize config with defaults */
inline void pf_config_init(ProxyFireConfig* cfg) {
    memset(cfg, 0, sizeof(ProxyFireConfig));
    cfg->dns_leak_prevention = 1;
    cfg->inject_children = 0;
    cfg->verbose = 0;
    cfg->connect_timeout_ms = PROXYFIRE_DEFAULT_TIMEOUT;
    cfg->log_level = PF_LOG_INFO;
}
#endif

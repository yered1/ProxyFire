/*
 * ProxyFire - Transparent Proxy Wrapper for Windows
 * Copyright (c) 2026. All rights reserved.
 *
 * common.h - Shared types, constants, and version info
 */

#pragma once

#ifndef PROXYFIRE_VERSION
#define PROXYFIRE_VERSION "1.0.0"
#endif

#ifndef PROXYFIRE_ARCH
#define PROXYFIRE_ARCH "unknown"
#endif

#ifndef PROXYFIRE_ARCH_SUFFIX
#define PROXYFIRE_ARCH_SUFFIX ""
#endif

/* IPC Magic number: "PXFI" */
#define PROXYFIRE_IPC_MAGIC 0x50584649

/* Maximum proxy chain length */
#define PROXYFIRE_MAX_PROXIES 16

/* Maximum bypass rules */
#define PROXYFIRE_MAX_BYPASS_RULES 64

/* Pipe name format */
#define PROXYFIRE_PIPE_PREFIX L"\\\\.\\pipe\\proxyfire_"

/* Environment variable for pipe name */
#define PROXYFIRE_ENV_PIPE L"PROXYFIRE_PIPE"

/* Environment variable for ready event name (synchronization) */
#define PROXYFIRE_ENV_READY_EVENT L"PROXYFIRE_READY_EVENT"

/* Environment variable for config (fallback) */
#define PROXYFIRE_ENV_CONFIG L"PROXYFIRE_CONFIG"

/* Fake DNS IP range: 240.0.0.0/4 (class E, reserved, never routed) */
#define PROXYFIRE_FAKE_IP_BASE  0xF0000001  /* 240.0.0.1 */
#define PROXYFIRE_FAKE_IP_MAX   0xFEFFFFFE  /* 254.255.255.254 */

/* Hook DLL names */
#define PROXYFIRE_HOOK_DLL_32 L"proxyfire_hook32.dll"
#define PROXYFIRE_HOOK_DLL_64 L"proxyfire_hook64.dll"

/* Default connect timeout (ms) */
#define PROXYFIRE_DEFAULT_TIMEOUT 30000

/* Log levels */
typedef enum ProxyFireLogLevel {
    PF_LOG_TRACE = 0,
    PF_LOG_DEBUG = 1,
    PF_LOG_INFO  = 2,
    PF_LOG_WARN  = 3,
    PF_LOG_ERROR = 4,
    PF_LOG_NONE  = 5
} ProxyFireLogLevel;

/*
 * ProxyFire - ipc_client.h
 * Named pipe IPC client (hook DLL side)
 */

#pragma once

#include <proxyfire/common.h>
#include <proxyfire/config.h>
#include <cstdint>

namespace proxyfire {

/**
 * Initialize IPC client connection to the launcher.
 * Reads pipe name from PROXYFIRE_PIPE environment variable.
 * Returns true on success.
 */
bool ipc_client_init();

/**
 * Send a registration message to the launcher.
 */
bool ipc_client_register(uint32_t pid, uint32_t tid);

/**
 * Request configuration from launcher.
 * Fills the provided config structure.
 */
bool ipc_client_get_config(ProxyFireConfig* config);

/**
 * Send a log message to the launcher.
 */
void ipc_client_log(ProxyFireLogLevel level, const char* fmt, ...);

/**
 * Notify launcher about a child process.
 */
bool ipc_client_notify_child(uint32_t child_pid, uint32_t child_tid);

/**
 * Register a DNS fake IP mapping with the launcher.
 */
bool ipc_client_dns_register(uint32_t fake_ip, const char* hostname);

/**
 * Check if IPC is connected.
 */
bool ipc_client_connected();

/**
 * Cleanup IPC connection.
 */
void ipc_client_cleanup();

} // namespace proxyfire

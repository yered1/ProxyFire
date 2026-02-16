/*
 * ProxyFire - ipc_server.h
 * Named pipe IPC server (launcher side)
 */

#pragma once

#include <proxyfire/config.h>
#include <string>
#include <functional>

namespace proxyfire {

/* Callback for log messages received from hook DLL */
using LogCallback = std::function<void(int level, uint32_t pid, const char* message)>;

/**
 * Create and start the IPC server.
 * Returns the pipe name for the hook DLL to connect to.
 */
std::wstring ipc_server_start(const ProxyFireConfig* config, LogCallback log_cb);

/**
 * Run the IPC server message pump.
 * Blocks until the server is stopped.
 * Call from a dedicated thread.
 */
void ipc_server_run();

/**
 * Stop the IPC server.
 */
void ipc_server_stop();

/**
 * Check if any clients are connected.
 */
bool ipc_server_has_clients();

} // namespace proxyfire

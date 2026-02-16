/*
 * ProxyFire - hook_installer.h
 * Table-driven MinHook installation for all Winsock/DNS/Process hooks
 */

#pragma once

namespace proxyfire {

/**
 * Install all hooks using MinHook.
 * Must be called after MH_Initialize().
 * Returns true if all hooks were installed successfully.
 */
bool install_all_hooks();

/**
 * Enable all installed hooks.
 * Returns true on success.
 */
bool enable_all_hooks();

/**
 * Disable all installed hooks.
 * Returns true on success.
 */
bool disable_all_hooks();

} // namespace proxyfire

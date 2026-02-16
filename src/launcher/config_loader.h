/*
 * ProxyFire - config_loader.h
 * Configuration file parser (simple INI/TOML-like format)
 */

#pragma once

#include <proxyfire/config.h>
#include <string>

namespace proxyfire {

/**
 * Load configuration from a TOML-like config file.
 *
 * Format:
 *   [general]
 *   verbose = true
 *   dns_leak_prevention = true
 *   inject_children = false
 *   log_file = proxyfire.log
 *   log_level = info
 *   timeout = 30000
 *
 *   [[proxy]]
 *   uri = socks5://user:pass@host:port
 *
 *   [[proxy]]
 *   uri = http://host:port
 *
 *   [bypass]
 *   rules = 127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16
 *
 * Returns true on success.
 */
bool load_config_file(const char* path, ProxyFireConfig* config, std::string* error);

} // namespace proxyfire

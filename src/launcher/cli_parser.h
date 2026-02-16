/*
 * ProxyFire - cli_parser.h
 * Command line argument parsing
 */

#pragma once

#include <proxyfire/config.h>
#include <proxyfire/proxy_types.h>
#include <string>
#include <vector>

namespace proxyfire {

struct CliOptions {
    /* Proxy URIs (can be multiple for chaining) */
    std::vector<std::string> proxy_uris;

    /* Config file path */
    std::string config_file;

    /* Target executable and arguments */
    std::string target_exe;
    std::vector<std::string> target_args;

    /* Flags */
    bool verbose;
    bool dns_leak_prevention;
    bool inject_children;
    bool show_help;
    bool show_version;

    /* Log settings */
    std::string log_file;
    int log_level;

    /* Timeouts */
    uint32_t connect_timeout_ms;

    CliOptions()
        : verbose(false)
        , dns_leak_prevention(true)
        , inject_children(false)
        , show_help(false)
        , show_version(false)
        , log_level(-1)  /* -1 = not set */
        , connect_timeout_ms(0)  /* 0 = use default */
    {}
};

/**
 * Parse command line arguments.
 *
 * Format: proxyfire [options] -- <target.exe> [target args...]
 *
 * Returns true on success, false on error.
 */
bool parse_cli(int argc, char* argv[], CliOptions* opts, std::string* error);

/**
 * Print usage/help text to stderr.
 */
void print_usage();

/**
 * Print version info to stderr.
 */
void print_version();

} // namespace proxyfire

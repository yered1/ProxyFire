/*
 * ProxyFire - cli_parser.cpp
 * Command line argument parsing
 */

#include "cli_parser.h"
#include <cstring>
#include <cstdio>

namespace proxyfire {

void print_usage() {
    fprintf(stderr,
        "ProxyFire v" PROXYFIRE_VERSION " - Transparent Proxy Wrapper for Windows\n"
        "\n"
        "Usage: proxyfire [options] -- <target.exe> [target args...]\n"
        "\n"
        "Options:\n"
        "  --proxy <uri>         Proxy URI (repeatable for chaining)\n"
        "                        Formats: socks5://[user:pass@]host:port\n"
        "                                 socks4://host:port\n"
        "                                 socks4a://host:port\n"
        "                                 http://[user:pass@]host:port\n"
        "  --config <file>       Load configuration from TOML file\n"
        "  --verbose, -v         Enable verbose logging\n"
        "  --quiet, -q           Suppress all output except errors\n"
        "  --log-file <file>     Write logs to file\n"
        "  --log-level <level>   Log level: trace, debug, info, warn, error\n"
        "  --no-dns-leak         Enable DNS leak prevention (default: on)\n"
        "  --allow-dns-leak      Disable DNS leak prevention\n"
        "  --inject-children     Also inject into child processes\n"
        "  --timeout <ms>        Proxy connection timeout in milliseconds\n"
        "  --help, -h            Show this help message\n"
        "  --version             Show version information\n"
        "\n"
        "Examples:\n"
        "  proxyfire --proxy socks5://1.2.3.4:1080 -- curl.exe https://example.com\n"
        "  proxyfire --proxy socks5://user:pass@proxy:1080 -- firefox.exe\n"
        "  proxyfire --proxy socks5://p1:1080 --proxy http://p2:8080 -- app.exe\n"
        "  proxyfire --config proxyfire.toml -- myapp.exe --arg1 --arg2\n"
        "\n"
    );
}

void print_version() {
    fprintf(stderr, "ProxyFire v%s (%s)\n", PROXYFIRE_VERSION, PROXYFIRE_ARCH);
}

bool parse_cli(int argc, char* argv[], CliOptions* opts, std::string* error) {
    if (!opts) {
        if (error) *error = "null options";
        return false;
    }

    bool found_separator = false;

    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];

        if (found_separator) {
            /* Everything after -- is the target command */
            if (opts->target_exe.empty()) {
                opts->target_exe = arg;
            } else {
                opts->target_args.push_back(arg);
            }
            continue;
        }

        if (strcmp(arg, "--") == 0) {
            found_separator = true;
            continue;
        }

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            opts->show_help = true;
            return true;
        }

        if (strcmp(arg, "--version") == 0) {
            opts->show_version = true;
            return true;
        }

        if (strcmp(arg, "--proxy") == 0 || strcmp(arg, "-p") == 0) {
            if (i + 1 >= argc) {
                if (error) *error = "--proxy requires an argument";
                return false;
            }
            opts->proxy_uris.push_back(argv[++i]);
            continue;
        }

        if (strcmp(arg, "--config") == 0 || strcmp(arg, "-c") == 0) {
            if (i + 1 >= argc) {
                if (error) *error = "--config requires an argument";
                return false;
            }
            opts->config_file = argv[++i];
            continue;
        }

        if (strcmp(arg, "--verbose") == 0 || strcmp(arg, "-v") == 0) {
            opts->verbose = true;
            continue;
        }

        if (strcmp(arg, "--quiet") == 0 || strcmp(arg, "-q") == 0) {
            opts->log_level = PF_LOG_ERROR;
            continue;
        }

        if (strcmp(arg, "--log-file") == 0) {
            if (i + 1 >= argc) {
                if (error) *error = "--log-file requires an argument";
                return false;
            }
            opts->log_file = argv[++i];
            continue;
        }

        if (strcmp(arg, "--log-level") == 0) {
            if (i + 1 >= argc) {
                if (error) *error = "--log-level requires an argument";
                return false;
            }
            const char* level = argv[++i];
            if (strcmp(level, "trace") == 0)      opts->log_level = PF_LOG_TRACE;
            else if (strcmp(level, "debug") == 0)  opts->log_level = PF_LOG_DEBUG;
            else if (strcmp(level, "info") == 0)   opts->log_level = PF_LOG_INFO;
            else if (strcmp(level, "warn") == 0)   opts->log_level = PF_LOG_WARN;
            else if (strcmp(level, "error") == 0)  opts->log_level = PF_LOG_ERROR;
            else {
                if (error) *error = "invalid log level: " + std::string(level);
                return false;
            }
            continue;
        }

        if (strcmp(arg, "--no-dns-leak") == 0) {
            opts->dns_leak_prevention = true;
            continue;
        }

        if (strcmp(arg, "--allow-dns-leak") == 0) {
            opts->dns_leak_prevention = false;
            continue;
        }

        if (strcmp(arg, "--inject-children") == 0) {
            opts->inject_children = true;
            continue;
        }

        if (strcmp(arg, "--timeout") == 0) {
            if (i + 1 >= argc) {
                if (error) *error = "--timeout requires an argument";
                return false;
            }
            opts->connect_timeout_ms = (uint32_t)atoi(argv[++i]);
            continue;
        }

        /* Unknown option or target without -- separator */
        if (arg[0] == '-') {
            if (error) *error = "unknown option: " + std::string(arg);
            return false;
        }

        /* Treat as target exe (implicit -- separator) */
        opts->target_exe = arg;
        for (int j = i + 1; j < argc; j++) {
            opts->target_args.push_back(argv[j]);
        }
        break;
    }

    return true;
}

} // namespace proxyfire

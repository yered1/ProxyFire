/*
 * ProxyFire - config_loader.cpp
 * Simple TOML-like configuration file parser
 */

#include "config_loader.h"
#include "proxy_uri.h"
#include "string_utils.h"

#include <fstream>
#include <cstring>
#include <algorithm>

namespace proxyfire {

static std::string strip_comment(const std::string& line) {
    /* Remove # comments (but not inside quotes) */
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); i++) {
        if (line[i] == '"') in_quotes = !in_quotes;
        if (line[i] == '#' && !in_quotes) {
            return trim(line.substr(0, i));
        }
    }
    return trim(line);
}

static std::string strip_quotes(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

static bool parse_bool(const std::string& val) {
    std::string v = val;
    std::transform(v.begin(), v.end(), v.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return v == "true" || v == "yes" || v == "1" || v == "on";
}

bool load_config_file(const char* path, ProxyFireConfig* config, std::string* error) {
    if (!path || !config) {
        if (error) *error = "null argument";
        return false;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        if (error) *error = "cannot open config file: " + std::string(path);
        return false;
    }

    /* Initialize with defaults */
    pf_config_init(config);

    std::string current_section;
    std::string line;
    int line_num = 0;

    while (std::getline(file, line)) {
        line_num++;
        line = strip_comment(line);

        if (line.empty()) continue;

        /* Section header */
        if (line.front() == '[') {
            if (line.size() >= 2 && line[0] == '[' && line[1] == '[') {
                /* Array section [[proxy]] */
                size_t end = line.find("]]");
                if (end == std::string::npos) {
                    if (error) *error = "invalid section at line " + std::to_string(line_num);
                    return false;
                }
                current_section = trim(line.substr(2, end - 2));
            } else {
                /* Regular section [general] */
                size_t end = line.find(']');
                if (end == std::string::npos) {
                    if (error) *error = "invalid section at line " + std::to_string(line_num);
                    return false;
                }
                current_section = trim(line.substr(1, end - 1));
            }
            continue;
        }

        /* Key = value */
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq));
        std::string value = strip_quotes(trim(line.substr(eq + 1)));

        if (current_section == "general") {
            if (key == "verbose") {
                config->verbose = parse_bool(value) ? 1 : 0;
            } else if (key == "dns_leak_prevention") {
                config->dns_leak_prevention = parse_bool(value) ? 1 : 0;
            } else if (key == "inject_children") {
                config->inject_children = parse_bool(value) ? 1 : 0;
            } else if (key == "log_file") {
                strncpy(config->log_file, value.c_str(), MAX_PATH - 1);
            } else if (key == "log_level") {
                if (value == "trace")      config->log_level = PF_LOG_TRACE;
                else if (value == "debug") config->log_level = PF_LOG_DEBUG;
                else if (value == "info")  config->log_level = PF_LOG_INFO;
                else if (value == "warn")  config->log_level = PF_LOG_WARN;
                else if (value == "error") config->log_level = PF_LOG_ERROR;
            } else if (key == "timeout") {
                config->connect_timeout_ms = (uint32_t)atoi(value.c_str());
            }
        }
        else if (current_section == "proxy") {
            if (key == "uri") {
                if (config->proxy_count >= PROXYFIRE_MAX_PROXIES) {
                    if (error) *error = "too many proxies (max " +
                                       std::to_string(PROXYFIRE_MAX_PROXIES) + ")";
                    return false;
                }

                ProxyEntry entry;
                std::string parse_err;
                if (!parse_proxy_uri(value.c_str(), &entry, &parse_err)) {
                    if (error) *error = "invalid proxy URI at line " +
                                       std::to_string(line_num) + ": " + parse_err;
                    return false;
                }

                /* Resolve proxy hostname to IP */
                entry.ip = resolve_hostname(entry.host);

                config->proxies[config->proxy_count++] = entry;
            }
        }
        else if (current_section == "bypass") {
            if (key == "rules") {
                /* Parse comma-separated CIDR rules */
                size_t start = 0;
                while (start < value.size()) {
                    size_t comma = value.find(',', start);
                    std::string rule;
                    if (comma == std::string::npos) {
                        rule = trim(value.substr(start));
                        start = value.size();
                    } else {
                        rule = trim(value.substr(start, comma - start));
                        start = comma + 1;
                    }

                    if (!rule.empty() && config->bypass_count < PROXYFIRE_MAX_BYPASS_RULES) {
                        uint32_t ip, mask;
                        if (parse_cidr(rule.c_str(), &ip, &mask)) {
                            config->bypass_rules[config->bypass_count].ip = ip;
                            config->bypass_rules[config->bypass_count].mask = mask;
                            config->bypass_count++;
                        }
                    }
                }
            }
        }
    }

    return true;
}

} // namespace proxyfire

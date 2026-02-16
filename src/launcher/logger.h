/*
 * ProxyFire - logger.h
 * Console and file logging
 */

#pragma once

#include <proxyfire/common.h>
#include <string>
#include <cstdarg>

namespace proxyfire {

/**
 * Initialize the logger.
 * @param log_file  Path to log file (empty = no file logging)
 * @param level     Minimum log level to output
 * @param verbose   Enable verbose mode (overrides level to DEBUG)
 */
void logger_init(const std::string& log_file, ProxyFireLogLevel level, bool verbose);

/**
 * Log a message at the given level.
 */
void logger_log(ProxyFireLogLevel level, const char* fmt, ...);
void logger_logv(ProxyFireLogLevel level, const char* fmt, va_list args);

/**
 * Convenience macros (if desired) - inline functions instead for type safety.
 */
inline void log_trace(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    logger_logv(PF_LOG_TRACE, fmt, args);
    va_end(args);
}

inline void log_debug(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    logger_logv(PF_LOG_DEBUG, fmt, args);
    va_end(args);
}

inline void log_info(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    logger_logv(PF_LOG_INFO, fmt, args);
    va_end(args);
}

inline void log_warn(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    logger_logv(PF_LOG_WARN, fmt, args);
    va_end(args);
}

inline void log_error(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    logger_logv(PF_LOG_ERROR, fmt, args);
    va_end(args);
}

/**
 * Close log file handles.
 */
void logger_cleanup();

} // namespace proxyfire

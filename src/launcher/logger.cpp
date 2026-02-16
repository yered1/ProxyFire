/*
 * ProxyFire - logger.cpp
 * Console and file logging
 */

#include "logger.h"
#include "string_utils.h"

#include <cstdio>
#include <cstdarg>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif

namespace proxyfire {

static FILE* g_log_file = nullptr;
static ProxyFireLogLevel g_min_level = PF_LOG_INFO;

#ifdef _WIN32
static CRITICAL_SECTION g_log_cs;
static bool g_cs_init = false;
static HANDLE g_console = INVALID_HANDLE_VALUE;
#endif

static const char* level_name(ProxyFireLogLevel level) {
    switch (level) {
        case PF_LOG_TRACE: return "TRACE";
        case PF_LOG_DEBUG: return "DEBUG";
        case PF_LOG_INFO:  return "INFO ";
        case PF_LOG_WARN:  return "WARN ";
        case PF_LOG_ERROR: return "ERROR";
        default:           return "?????";
    }
}

#ifdef _WIN32
static WORD level_color(ProxyFireLogLevel level) {
    switch (level) {
        case PF_LOG_TRACE: return FOREGROUND_INTENSITY;
        case PF_LOG_DEBUG: return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        case PF_LOG_INFO:  return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case PF_LOG_WARN:  return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case PF_LOG_ERROR: return FOREGROUND_RED | FOREGROUND_INTENSITY;
        default:           return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}
#endif

void logger_init(const std::string& log_file, ProxyFireLogLevel level, bool verbose) {
#ifdef _WIN32
    if (!g_cs_init) {
        InitializeCriticalSection(&g_log_cs);
        g_cs_init = true;
    }
    g_console = GetStdHandle(STD_ERROR_HANDLE);
#endif

    g_min_level = verbose ? PF_LOG_DEBUG : level;

    if (!log_file.empty()) {
        g_log_file = fopen(log_file.c_str(), "a");
    }
}

void logger_logv(ProxyFireLogLevel level, const char* fmt, va_list args) {
    if (level < g_min_level) return;

#ifdef _WIN32
    if (g_cs_init) EnterCriticalSection(&g_log_cs);
#endif

    /* Get timestamp */
    char ts[32];
    time_t now = time(nullptr);
    struct tm* tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    /* Format the message */
    char msg[4096];
    vsnprintf(msg, sizeof(msg), fmt, args);

    /* Write to stderr with color */
#ifdef _WIN32
    if (g_console != INVALID_HANDLE_VALUE) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(g_console, &csbi);

        /* Timestamp */
        fprintf(stderr, "[%s] ", ts);

        /* Colored level */
        SetConsoleTextAttribute(g_console, level_color(level));
        fprintf(stderr, "[%s]", level_name(level));
        SetConsoleTextAttribute(g_console, csbi.wAttributes);

        /* Message */
        fprintf(stderr, " %s\n", msg);
    } else {
        fprintf(stderr, "[%s] [%s] %s\n", ts, level_name(level), msg);
    }
#else
    fprintf(stderr, "[%s] [%s] %s\n", ts, level_name(level), msg);
#endif

    /* Write to log file (no color) */
    if (g_log_file) {
        char date_ts[64];
        strftime(date_ts, sizeof(date_ts), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(g_log_file, "[%s] [%s] %s\n", date_ts, level_name(level), msg);
        fflush(g_log_file);
    }

#ifdef _WIN32
    if (g_cs_init) LeaveCriticalSection(&g_log_cs);
#endif
}

void logger_log(ProxyFireLogLevel level, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logger_logv(level, fmt, args);
    va_end(args);
}

void logger_cleanup() {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = nullptr;
    }
#ifdef _WIN32
    if (g_cs_init) {
        DeleteCriticalSection(&g_log_cs);
        g_cs_init = false;
    }
#endif
}

} // namespace proxyfire

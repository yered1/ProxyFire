/*
 * ProxyFire - main.cpp
 * Launcher entry point
 *
 * This is the user-facing executable that:
 * 1. Parses command line arguments and config file
 * 2. Resolves proxy hostnames to IPs
 * 3. Creates the IPC named pipe server
 * 4. Launches the target process in a suspended state
 * 5. Detects the target's architecture (x86/x64)
 * 6. Injects the appropriate hook DLL
 * 7. Resumes the target process
 * 8. Monitors until the target exits
 *
 * Usage: proxyfire [options] -- <target.exe> [target args...]
 */

#include "cli_parser.h"
#include "config_loader.h"
#include "process_launcher.h"
#include "injector.h"
#include "ipc_server.h"
#include "logger.h"
#include "proxy_uri.h"
#include "string_utils.h"

#include <proxyfire/common.h>
#include <proxyfire/config.h>

#include <cstdio>
#include <cstring>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#endif

using namespace proxyfire;

static void print_banner() {
    fprintf(stderr,
        "ProxyFire v" PROXYFIRE_VERSION " - Transparent Proxy Wrapper\n"
        "https://github.com/yered1/ProxyFire\n\n"
    );
}

static void print_config_summary(const ProxyFireConfig& config) {
    log_info("Configuration:");
    log_info("  Proxy chain: %u hop(s)", config.proxy_count);
    for (uint32_t i = 0; i < config.proxy_count; i++) {
        const ProxyEntry& p = config.proxies[i];
        if (p.username[0]) {
            log_info("    [%u] %s://%s@%s:%u",
                    i + 1, proxy_proto_name(p.proto),
                    p.username, p.host, p.port);
        } else {
            log_info("    [%u] %s://%s:%u",
                    i + 1, proxy_proto_name(p.proto),
                    p.host, p.port);
        }
    }
    log_info("  DNS leak prevention: %s", config.dns_leak_prevention ? "ON" : "OFF");
    log_info("  Inject children: %s", config.inject_children ? "ON" : "OFF");
    log_info("  Connect timeout: %u ms", config.connect_timeout_ms);
    if (config.bypass_count > 0) {
        log_info("  Bypass rules: %u", config.bypass_count);
    }
}

#ifdef _WIN32
/*
 * Check if the current process is running with administrator privileges.
 */
static bool is_elevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD size = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size)) {
            elevated = elev.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated != FALSE;
}

/*
 * Re-launch proxyfire.exe with administrator privileges using ShellExecuteEx "runas".
 * Reconstructs the original command line and passes it to the elevated instance.
 * Returns the exit code of the elevated process, or 1 on failure.
 */
static int relaunch_elevated(int argc, char* argv[]) {
    /* Get path to our own executable */
    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    /* Reconstruct the command line arguments (skip argv[0]) */
    std::wstring args;
    for (int i = 1; i < argc; i++) {
        if (i > 1) args += L" ";
        std::wstring warg = to_wide(std::string(argv[i]));
        /* Quote arguments with spaces */
        if (warg.find(L' ') != std::wstring::npos) {
            args += L"\"" + warg + L"\"";
        } else {
            args += warg;
        }
    }

    log_info("Requesting administrator privileges...");

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    sei.lpVerb = L"runas";
    sei.lpFile = exe_path;
    sei.lpParameters = args.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            log_error("UAC elevation was cancelled by user");
        } else {
            log_error("Failed to elevate: %s", format_win_error(err).c_str());
        }
        return 1;
    }

    /* Wait for the elevated process to finish */
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD exit_code = 1;
        GetExitCodeProcess(sei.hProcess, &exit_code);
        CloseHandle(sei.hProcess);
        return (int)exit_code;
    }

    return 0;
}

/*
 * Check if a target executable's manifest requires elevation
 * (requestedExecutionLevel = "requireAdministrator" or "highestAvailable").
 * Also checks if the exe has the compatibility flag for admin.
 */
static bool target_requires_elevation(const std::string& exe_path) {
    /* Try to create the process - if it fails with ERROR_ELEVATION_REQUIRED,
     * we know it needs elevation. This is more reliable than parsing manifests. */
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    std::wstring wcmdline = L"\"" + to_wide(exe_path) + L"\"";

    BOOL result = CreateProcessW(
        nullptr,
        &wcmdline[0],
        nullptr, nullptr, FALSE,
        CREATE_SUSPENDED,
        nullptr, nullptr,
        &si, &pi
    );

    if (result) {
        /* Process created successfully - it doesn't require elevation */
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    return (GetLastError() == ERROR_ELEVATION_REQUIRED);
}
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
    /* Initialize Winsock */
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    /* Enable ANSI colors on Windows 10+ */
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(hConsole, &mode)) {
        SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif

    /* Parse command line */
    CliOptions opts;
    std::string parse_error;
    if (!parse_cli(argc, argv, &opts, &parse_error)) {
        fprintf(stderr, "Error: %s\n\n", parse_error.c_str());
        print_usage();
        return 1;
    }

    if (opts.show_help) {
        print_banner();
        print_usage();
        return 0;
    }

    if (opts.show_version) {
        print_version();
        return 0;
    }

    /* Initialize logger early */
    ProxyFireLogLevel log_level = PF_LOG_INFO;
    if (opts.log_level >= 0) log_level = (ProxyFireLogLevel)opts.log_level;
    logger_init(opts.log_file, log_level, opts.verbose);

    print_banner();

    /* Load config file if specified */
    ProxyFireConfig config;
    pf_config_init(&config);

    if (!opts.config_file.empty()) {
        std::string cfg_error;
        if (!load_config_file(opts.config_file.c_str(), &config, &cfg_error)) {
            log_error("Config file error: %s", cfg_error.c_str());
            return 1;
        }
        log_info("Loaded config from %s", opts.config_file.c_str());
    }

    /* CLI options override config file */
    if (!opts.proxy_uris.empty()) {
        config.proxy_count = 0;
        for (const auto& uri : opts.proxy_uris) {
            if (config.proxy_count >= PROXYFIRE_MAX_PROXIES) {
                log_error("Too many proxies (max %d)", PROXYFIRE_MAX_PROXIES);
                return 1;
            }

            ProxyEntry entry;
            std::string uri_error;
            if (!parse_proxy_uri(uri.c_str(), &entry, &uri_error)) {
                log_error("Invalid proxy URI '%s': %s", uri.c_str(), uri_error.c_str());
                return 1;
            }

            /* Resolve proxy hostname */
            entry.ip = resolve_hostname(entry.host);
            if (entry.ip == 0) {
                log_error("Cannot resolve proxy host '%s'", entry.host);
                return 1;
            }

            log_debug("Proxy %s:%u resolved to %s",
                     entry.host, entry.port,
                     ip_to_string(entry.ip).c_str());

            config.proxies[config.proxy_count++] = entry;
        }
    }

    if (opts.verbose) config.verbose = 1;
    if (!opts.dns_leak_prevention) config.dns_leak_prevention = 0;
    if (opts.inject_children) config.inject_children = 1;
    if (opts.connect_timeout_ms > 0) config.connect_timeout_ms = opts.connect_timeout_ms;
    if (opts.log_level >= 0) config.log_level = (uint8_t)opts.log_level;
    if (!opts.log_file.empty()) {
        strncpy(config.log_file, opts.log_file.c_str(), MAX_PATH - 1);
    }

    /* Validate configuration */
    if (config.proxy_count == 0) {
        log_error("No proxy configured. Use --proxy <uri> or --config <file>");
        print_usage();
        return 1;
    }

    if (opts.target_exe.empty()) {
        log_error("No target executable specified. Use: proxyfire [options] -- <target.exe>");
        print_usage();
        return 1;
    }

    print_config_summary(config);

#ifdef _WIN32
    /*
     * UAC auto-elevation: if the target process requires administrator
     * privileges and we're not already elevated, re-launch proxyfire.exe
     * with a UAC elevation prompt.
     */
    if (!is_elevated() && target_requires_elevation(opts.target_exe)) {
        log_info("Target requires administrator privileges (UAC elevation needed)");
        int result = relaunch_elevated(argc, argv);
        logger_cleanup();
        WSACleanup();
        return result;
    }

    /* Detect target architecture */
    PeArch target_arch = detect_pe_arch(opts.target_exe);
    log_info("Target: %s (%s)", opts.target_exe.c_str(), pe_arch_name(target_arch));

    /* Determine which hook DLL to use */
    std::wstring dll_suffix;
    if (target_arch == PeArch::X86) {
        dll_suffix = L"32";
    } else if (target_arch == PeArch::X64) {
        dll_suffix = L"64";
    } else {
        /* Default to current architecture */
        dll_suffix = to_wide(std::string(PROXYFIRE_ARCH_SUFFIX));
        log_warn("Could not detect target architecture, using %s",
                PROXYFIRE_ARCH_SUFFIX);
    }

    std::wstring hook_dll = get_hook_dll_path(dll_suffix.c_str());
    log_info("Hook DLL: %ls", hook_dll.c_str());

    /* Verify hook DLL exists */
    DWORD attribs = GetFileAttributesW(hook_dll.c_str());
    if (attribs == INVALID_FILE_ATTRIBUTES) {
        log_error("Hook DLL not found: %ls", hook_dll.c_str());
        log_error("Make sure proxyfire_hook%ls.dll is in the same directory as proxyfire.exe",
                 dll_suffix.c_str());
        return 1;
    }

    /* Start IPC server */
    auto log_callback = [](int level, uint32_t pid, const char* message) {
        logger_log((ProxyFireLogLevel)level, "[PID:%lu] %s", pid, message);
    };

    std::wstring pipe_name = ipc_server_start(&config, log_callback);
    if (pipe_name.empty()) {
        log_error("Failed to start IPC server");
        return 1;
    }

    /* Store pipe name in config (for child processes) */
    wcsncpy(config.pipe_name, pipe_name.c_str(), 255);

    /* Start IPC server thread */
    std::thread ipc_thread(ipc_server_run);
    ipc_thread.detach();

    /*
     * Create a named event for hook-ready synchronization.
     * The hook DLL signals this event after all hooks are installed,
     * and we wait for it before resuming the target's main thread.
     * This prevents a race where the target makes network calls
     * before hooks are in place, causing an illegal-instruction crash.
     */
    wchar_t ready_event_name[256];
    swprintf(ready_event_name, 256, L"ProxyFire_Ready_%lu_%lu",
             GetCurrentProcessId(), GetTickCount());

    HANDLE hReadyEvent = CreateEventW(nullptr, TRUE, FALSE, ready_event_name);
    if (!hReadyEvent) {
        log_error("Failed to create ready event: %s",
                  format_win_error(GetLastError()).c_str());
        ipc_server_stop();
        return 1;
    }

    /* Create target process in suspended state */
    PROCESS_INFORMATION pi;
    if (!create_suspended_process(opts.target_exe, opts.target_args, pipe_name,
                                   std::wstring(ready_event_name), &pi)) {
        DWORD err = GetLastError();

        /*
         * If process creation failed with ERROR_ELEVATION_REQUIRED and
         * we're not elevated, attempt UAC elevation. This catches cases
         * where target_requires_elevation() didn't detect the need
         * (e.g., exe manifest loaded dynamically).
         */
        if (err == ERROR_ELEVATION_REQUIRED && !is_elevated()) {
            log_info("Target requires elevation - requesting admin privileges...");
            CloseHandle(hReadyEvent);
            ipc_server_stop();
            int result = relaunch_elevated(argc, argv);
            logger_cleanup();
            WSACleanup();
            return result;
        }

        log_error("Failed to create target process");
        CloseHandle(hReadyEvent);
        ipc_server_stop();
        return 1;
    }

    /* Inject the hook DLL */
    log_info("Injecting hook DLL into PID %lu...", pi.dwProcessId);
    if (!inject_dll(pi.hProcess, hook_dll)) {
        log_error("DLL injection failed!");
        TerminateProcess(pi.hProcess, 1);
        close_process(&pi);
        CloseHandle(hReadyEvent);
        ipc_server_stop();
        return 1;
    }

    log_info("Hook DLL injected successfully");

    /*
     * Wait for the hook DLL to signal that all hooks are installed.
     * The DLL's InitThread runs after DllMain returns (loader lock is
     * released) and signals hReadyEvent once MH_EnableHook completes.
     * 30-second timeout to avoid hanging if the DLL fails.
     */
    log_info("Waiting for hook DLL to initialize...");
    DWORD wait_result = WaitForSingleObject(hReadyEvent, 30000);
    CloseHandle(hReadyEvent);

    if (wait_result != WAIT_OBJECT_0) {
        log_warn("Hook DLL did not signal ready in time (wait=%lu), resuming anyway",
                 wait_result);
    }

    /* Resume the target process */
    log_info("Resuming target process...");
    if (!resume_process(&pi)) {
        log_error("Failed to resume target process");
        TerminateProcess(pi.hProcess, 1);
        close_process(&pi);
        ipc_server_stop();
        return 1;
    }

    log_info("Target process running (PID: %lu)", pi.dwProcessId);
    log_info("All network connections will be routed through the proxy chain");
    log_info("---");

    /* Wait for the target process to exit */
    uint32_t exit_code = wait_for_process(&pi);

    log_info("---");
    log_info("Target process exited with code %lu", exit_code);

    /* Cleanup */
    close_process(&pi);
    ipc_server_stop();
    logger_cleanup();

    WSACleanup();
    return (int)exit_code;

#else
    log_error("ProxyFire requires Windows to run");
    logger_cleanup();
    return 1;
#endif
}

/*
 * ProxyFire - dllmain.cpp
 * Hook DLL entry point
 *
 * This DLL is injected into the target process by the ProxyFire launcher.
 * On DLL_PROCESS_ATTACH it:
 *   1. Connects to the launcher via named pipe IPC
 *   2. Receives configuration (proxy chain, rules, etc.)
 *   3. Initializes MinHook
 *   4. Installs all Winsock/DNS/Process hooks
 *   5. Enables hooks
 *
 * On DLL_PROCESS_DETACH it cleanly tears down all hooks.
 */

#include "hook_installer.h"
#include "hook_winsock.h"
#include "dns_faker.h"
#include "socket_context.h"
#include "udp_relay.h"
#include "ipc_client.h"

#include <proxyfire/common.h>
#include <proxyfire/config.h>

#ifdef _WIN32
#include <windows.h>
#include <MinHook.h>

/* Global configuration - shared with all hook files */
ProxyFireConfig g_config;

static HMODULE g_hModule = nullptr;
static bool g_hooks_installed = false;

/*
 * Signal the ready event to tell the launcher that hooks are installed.
 * The launcher waits for this event before resuming the target's main thread.
 */
static void signal_ready_event() {
    wchar_t event_name[512] = {};
    DWORD len = GetEnvironmentVariableW(PROXYFIRE_ENV_READY_EVENT, event_name, 512);
    if (len == 0 || len >= 512) return;

    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name);
    if (hEvent) {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }
}

/*
 * Initialize the hook system.
 * Called from a separate thread to avoid loader lock issues.
 *
 * DllMain does NOT wait for this thread.  Instead, after hooks are
 * installed we signal a named event (PROXYFIRE_READY_EVENT) that the
 * launcher waits on before resuming the target's main thread.  This
 * eliminates the race between hook installation and the first network
 * calls made by the target process.
 */
static DWORD WINAPI InitThread(LPVOID lpParam) {
    (void)lpParam;

    /* Initialize subsystems */
    proxyfire::dns_faker_init();
    proxyfire::socket_ctx_init();
    proxyfire::udp_relay_init();

    /* Connect to launcher IPC */
    if (!proxyfire::ipc_client_init()) {
        /* If IPC fails, we can't get config - try environment fallback */
        OutputDebugStringA("[ProxyFire] WARNING: Failed to connect to launcher IPC\n");
        /* Initialize with empty config - hooks will pass through */
        pf_config_init(&g_config);
        goto setup_hooks;
    }

    /* Register ourselves */
    proxyfire::ipc_client_register(GetCurrentProcessId(), GetCurrentThreadId());

    /* Get configuration from launcher */
    if (!proxyfire::ipc_client_get_config(&g_config)) {
        OutputDebugStringA("[ProxyFire] WARNING: Failed to get config from launcher\n");
        pf_config_init(&g_config);
    }

    proxyfire::ipc_client_log(PF_LOG_INFO, "Hook DLL loaded in PID %lu (%s)",
                              GetCurrentProcessId(), PROXYFIRE_ARCH);

setup_hooks:
    /* Initialize MinHook */
    if (MH_Initialize() != MH_OK) {
        proxyfire::ipc_client_log(PF_LOG_ERROR, "MH_Initialize() failed");
        signal_ready_event();  /* Signal even on failure so launcher doesn't hang */
        return 1;
    }

    /*
     * Pre-resolve ConnectEx BEFORE installing hooks.
     *
     * Go programs (and other IOCP-based apps) obtain ConnectEx via
     * WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER).  Our WSAIoctl hook
     * normally calls Original_WSAIoctl (the MinHook trampoline) to get
     * the real ConnectEx, but certain ws2_32.dll builds produce
     * prologues whose RIP-relative instructions are mis-relocated by
     * the trampoline, causing an access-violation crash.
     *
     * By resolving ConnectEx here (before any hooks are installed) we
     * call the real WSAIoctl directly and avoid the trampoline entirely.
     */
    proxyfire::pre_resolve_connectex();

    /* Install all hooks */
    if (!proxyfire::install_all_hooks()) {
        proxyfire::ipc_client_log(PF_LOG_ERROR, "Failed to install critical hooks");
        MH_Uninitialize();
        signal_ready_event();
        return 1;
    }

    /* Enable all hooks */
    if (!proxyfire::enable_all_hooks()) {
        proxyfire::ipc_client_log(PF_LOG_ERROR, "Failed to enable hooks");
        MH_Uninitialize();
        signal_ready_event();
        return 1;
    }

    g_hooks_installed = true;

    proxyfire::ipc_client_log(PF_LOG_INFO,
        "All hooks installed and enabled. Proxy chain: %u hop(s), DNS leak prevention: %s",
        g_config.proxy_count,
        g_config.dns_leak_prevention ? "ON" : "OFF");

    /* Tell the launcher it is safe to resume the target's main thread */
    signal_ready_event();

    return 0;
}

/*
 * Cleanup the hook system.
 */
static void Cleanup() {
    if (g_hooks_installed) {
        proxyfire::disable_all_hooks();
        MH_Uninitialize();
        g_hooks_installed = false;
    }

    proxyfire::ipc_client_log(PF_LOG_INFO, "Hook DLL unloading from PID %lu",
                              GetCurrentProcessId());

    proxyfire::udp_relay_cleanup();
    proxyfire::socket_ctx_cleanup();
    proxyfire::dns_faker_cleanup();
    proxyfire::ipc_client_cleanup();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            g_hModule = hModule;
            DisableThreadLibraryCalls(hModule);

            /*
             * Create a separate thread for initialization to avoid
             * deadlocks with the loader lock.  DllMain has restrictions
             * on what APIs can be called (no LoadLibrary, etc.).
             *
             * We do NOT wait for the thread here — InitThread cannot
             * make progress until DllMain returns and releases the
             * loader lock.  Instead, InitThread signals a named event
             * (PROXYFIRE_READY_EVENT) once hooks are installed.  The
             * launcher waits on that event before resuming the target's
             * main thread, ensuring hooks are active before the first
             * network call.
             */
            HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
            if (hThread) {
                CloseHandle(hThread);
            }
            break;
        }

        case DLL_PROCESS_DETACH:
            Cleanup();
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

#else
/* Non-Windows stub for compilation testing */
ProxyFireConfig g_config;
#endif

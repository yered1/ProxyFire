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
#include "dns_faker.h"
#include "socket_context.h"
#include "ipc_client.h"

#include <proxyfire/common.h>
#include <proxyfire/config.h>

#ifdef _WIN32
#include <windows.h>
#include <MinHook.h>

/* Global configuration - shared with all hook files */
proxyfire::ProxyFireConfig g_config;

static HMODULE g_hModule = nullptr;
static bool g_hooks_installed = false;

/*
 * Initialize the hook system.
 * Called from a separate thread to avoid loader lock issues.
 */
static DWORD WINAPI InitThread(LPVOID lpParam) {
    (void)lpParam;

    /* Initialize subsystems */
    proxyfire::dns_faker_init();
    proxyfire::socket_ctx_init();

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
        return 1;
    }

    /* Install all hooks */
    if (!proxyfire::install_all_hooks()) {
        proxyfire::ipc_client_log(PF_LOG_ERROR, "Failed to install critical hooks");
        MH_Uninitialize();
        return 1;
    }

    /* Enable all hooks */
    if (!proxyfire::enable_all_hooks()) {
        proxyfire::ipc_client_log(PF_LOG_ERROR, "Failed to enable hooks");
        MH_Uninitialize();
        return 1;
    }

    g_hooks_installed = true;

    proxyfire::ipc_client_log(PF_LOG_INFO,
        "All hooks installed and enabled. Proxy chain: %u hop(s), DNS leak prevention: %s",
        g_config.proxy_count,
        g_config.dns_leak_prevention ? "ON" : "OFF");

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
             * deadlocks with the loader lock. DllMain has restrictions
             * on what APIs can be called (no LoadLibrary, etc.).
             *
             * CreateThread is explicitly allowed in DllMain per MSDN.
             */
            HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
            if (hThread) {
                /* Wait for init to complete (with timeout) */
                WaitForSingleObject(hThread, 10000);
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
proxyfire::ProxyFireConfig g_config;
#endif

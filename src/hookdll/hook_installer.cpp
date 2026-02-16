/*
 * ProxyFire - hook_installer.cpp
 * Table-driven MinHook installation
 */

#include "hook_installer.h"
#include "hook_winsock.h"
#include "hook_dns.h"
#include "hook_process.h"
#include "ipc_client.h"

#include <MinHook.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace proxyfire {

struct HookEntry {
    const wchar_t* module;
    const char*    funcName;
    LPVOID         detour;
    LPVOID*        original;
    const char*    description;
    bool           critical;     /* If true, failure aborts initialization */
};

/* Original function pointers - defined in respective hook files */

/* Winsock hooks */
extern int     (WSAAPI *Original_connect)(SOCKET, const struct sockaddr*, int);
extern int     (WSAAPI *Original_WSAConnect)(SOCKET, const struct sockaddr*, int,
                LPWSABUF, LPWSABUF, LPQOS, LPQOS);
extern int     (WSAAPI *Original_closesocket)(SOCKET);
extern int     (WSAAPI *Original_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD,
                LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

/* DNS hooks */
extern int     (WSAAPI *Original_getaddrinfo)(const char*, const char*,
                const struct addrinfo*, struct addrinfo**);
extern int     (WSAAPI *Original_GetAddrInfoW)(const wchar_t*, const wchar_t*,
                const ADDRINFOW*, ADDRINFOW**);
extern struct hostent* (WSAAPI *Original_gethostbyname)(const char*);
extern int     (WSAAPI *Original_GetAddrInfoExW)(const wchar_t*, const wchar_t*,
                DWORD, LPGUID, const ADDRINFOEXW*, PADDRINFOEXW*, struct timeval*,
                LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);

/* Process hooks */
extern BOOL    (WINAPI *Original_CreateProcessW)(LPCWSTR, LPWSTR,
                LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
extern BOOL    (WINAPI *Original_CreateProcessA)(LPCSTR, LPSTR,
                LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static HookEntry g_hooks[] = {
    /* Winsock connection hooks - CRITICAL */
    {
        L"ws2_32.dll", "connect",
        (LPVOID)Hooked_connect, (LPVOID*)&Original_connect,
        "connect()", true
    },
    {
        L"ws2_32.dll", "WSAConnect",
        (LPVOID)Hooked_WSAConnect, (LPVOID*)&Original_WSAConnect,
        "WSAConnect()", true
    },
    {
        L"ws2_32.dll", "closesocket",
        (LPVOID)Hooked_closesocket, (LPVOID*)&Original_closesocket,
        "closesocket()", true
    },
    /* WSAIoctl - needed to intercept ConnectEx function pointer requests */
    {
        L"ws2_32.dll", "WSAIoctl",
        (LPVOID)Hooked_WSAIoctl, (LPVOID*)&Original_WSAIoctl,
        "WSAIoctl()", false
    },

    /* DNS hooks */
    {
        L"ws2_32.dll", "getaddrinfo",
        (LPVOID)Hooked_getaddrinfo, (LPVOID*)&Original_getaddrinfo,
        "getaddrinfo()", false
    },
    {
        L"ws2_32.dll", "GetAddrInfoW",
        (LPVOID)Hooked_GetAddrInfoW, (LPVOID*)&Original_GetAddrInfoW,
        "GetAddrInfoW()", false
    },
    {
        L"ws2_32.dll", "gethostbyname",
        (LPVOID)Hooked_gethostbyname, (LPVOID*)&Original_gethostbyname,
        "gethostbyname()", false
    },
    /* Async DNS - GetAddrInfoExW (used by modern Windows apps) */
    {
        L"ws2_32.dll", "GetAddrInfoExW",
        (LPVOID)Hooked_GetAddrInfoExW, (LPVOID*)&Original_GetAddrInfoExW,
        "GetAddrInfoExW()", false
    },

    /* Process hooks (for child injection) */
    {
        L"kernel32.dll", "CreateProcessW",
        (LPVOID)Hooked_CreateProcessW, (LPVOID*)&Original_CreateProcessW,
        "CreateProcessW()", false
    },
    {
        L"kernel32.dll", "CreateProcessA",
        (LPVOID)Hooked_CreateProcessA, (LPVOID*)&Original_CreateProcessA,
        "CreateProcessA()", false
    },
};

static const int g_hook_count = sizeof(g_hooks) / sizeof(g_hooks[0]);

bool install_all_hooks() {
    bool all_ok = true;

    for (int i = 0; i < g_hook_count; i++) {
        MH_STATUS status = MH_CreateHookApi(
            g_hooks[i].module,
            g_hooks[i].funcName,
            g_hooks[i].detour,
            g_hooks[i].original
        );

        if (status != MH_OK && status != MH_ERROR_MODULE_NOT_FOUND &&
            status != MH_ERROR_FUNCTION_NOT_FOUND) {
            ipc_client_log(PF_LOG_WARN, "Failed to hook %s: %s",
                          g_hooks[i].description, MH_StatusToString(status));
            if (g_hooks[i].critical) {
                all_ok = false;
            }
        } else if (status == MH_OK) {
            ipc_client_log(PF_LOG_DEBUG, "Hooked %s", g_hooks[i].description);
        } else {
            ipc_client_log(PF_LOG_DEBUG, "Skipped %s (not found)", g_hooks[i].description);
        }
    }

    return all_ok;
}

bool enable_all_hooks() {
    MH_STATUS status = MH_EnableHook(MH_ALL_HOOKS);
    return status == MH_OK;
}

bool disable_all_hooks() {
    MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
    return status == MH_OK;
}

} // namespace proxyfire

#else
/* Non-Windows stubs */
namespace proxyfire {
bool install_all_hooks() { return false; }
bool enable_all_hooks() { return false; }
bool disable_all_hooks() { return false; }
} // namespace proxyfire
#endif

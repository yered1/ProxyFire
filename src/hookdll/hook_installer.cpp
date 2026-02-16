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
};

/* Original function pointers - defined in respective hook files */

/* Winsock hooks */
extern int     (WSAAPI *Original_connect)(SOCKET, const struct sockaddr*, int);
extern int     (WSAAPI *Original_WSAConnect)(SOCKET, const struct sockaddr*, int,
                LPWSABUF, LPWSABUF, LPQOS, LPQOS);
extern int     (WSAAPI *Original_closesocket)(SOCKET);

/* DNS hooks */
extern int     (WSAAPI *Original_getaddrinfo)(const char*, const char*,
                const struct addrinfo*, struct addrinfo**);
extern int     (WSAAPI *Original_GetAddrInfoW)(const wchar_t*, const wchar_t*,
                const ADDRINFOW*, ADDRINFOW**);
extern struct hostent* (WSAAPI *Original_gethostbyname)(const char*);

/* Process hooks */
extern BOOL    (WINAPI *Original_CreateProcessW)(LPCWSTR, LPWSTR,
                LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
extern BOOL    (WINAPI *Original_CreateProcessA)(LPCSTR, LPSTR,
                LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static HookEntry g_hooks[] = {
    /* Winsock connection hooks */
    {
        L"ws2_32.dll", "connect",
        (LPVOID)Hooked_connect, (LPVOID*)&Original_connect,
        "connect()"
    },
    {
        L"ws2_32.dll", "WSAConnect",
        (LPVOID)Hooked_WSAConnect, (LPVOID*)&Original_WSAConnect,
        "WSAConnect()"
    },
    {
        L"ws2_32.dll", "closesocket",
        (LPVOID)Hooked_closesocket, (LPVOID*)&Original_closesocket,
        "closesocket()"
    },

    /* DNS hooks */
    {
        L"ws2_32.dll", "getaddrinfo",
        (LPVOID)Hooked_getaddrinfo, (LPVOID*)&Original_getaddrinfo,
        "getaddrinfo()"
    },
    {
        L"ws2_32.dll", "GetAddrInfoW",
        (LPVOID)Hooked_GetAddrInfoW, (LPVOID*)&Original_GetAddrInfoW,
        "GetAddrInfoW()"
    },
    {
        L"ws2_32.dll", "gethostbyname",
        (LPVOID)Hooked_gethostbyname, (LPVOID*)&Original_gethostbyname,
        "gethostbyname()"
    },

    /* Process hooks (for child injection) */
    {
        L"kernel32.dll", "CreateProcessW",
        (LPVOID)Hooked_CreateProcessW, (LPVOID*)&Original_CreateProcessW,
        "CreateProcessW()"
    },
    {
        L"kernel32.dll", "CreateProcessA",
        (LPVOID)Hooked_CreateProcessA, (LPVOID*)&Original_CreateProcessA,
        "CreateProcessA()"
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

        if (status != MH_OK && status != MH_ERROR_MODULE_NOT_FOUND) {
            ipc_client_log(PF_LOG_WARN, "Failed to hook %s: %s",
                          g_hooks[i].description, MH_StatusToString(status));
            /* Non-critical hooks (like CreateProcess) can fail */
            if (i < 3) {
                /* Connection hooks are critical */
                all_ok = false;
            }
        } else if (status == MH_OK) {
            ipc_client_log(PF_LOG_DEBUG, "Hooked %s", g_hooks[i].description);
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

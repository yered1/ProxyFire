/*
 * ProxyFire - hook_installer.cpp
 * Table-driven MinHook installation
 */

#include "hook_installer.h"
#include "hook_winsock.h"
#include "hook_dns.h"
#include "hook_process.h"
#include "hook_winhttp.h"
#include "hook_udp.h"
#include "ipc_client.h"

#include <MinHook.h>

#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace proxyfire {

/*
 * Follow JMP chains and skip non-essential prologue instructions
 * to find the actual function body that MinHook can trampoline.
 *
 * On modern Windows, some API functions start with CET ENDBR
 * instructions or are thin JMP stubs (forwarded exports, CFG
 * dispatch, or already-applied hooks from security software).
 * MinHook's trampoline builder can fail on these prologues.
 *
 * This function walks through such indirection so we can retry
 * MH_CreateHook at the resolved "real" address.
 *
 * Returns the resolved address, or nullptr if no resolution was
 * possible (i.e. the address from GetProcAddress is already the
 * real body, or the module/function was not found).
 */
static LPVOID resolve_function(const wchar_t* module, const char* funcName) {
    HMODULE hMod = GetModuleHandleW(module);
    if (!hMod) return nullptr;

    FARPROC pProc = GetProcAddress(hMod, funcName);
    if (!pProc) return nullptr;

    LPBYTE p = (LPBYTE)pProc;
    LPBYTE start = p;

    for (int depth = 0; depth < 8; depth++) {
        /* Skip ENDBR64 (F3 0F 1E FA) / ENDBR32 (F3 0F 1E FB) */
        if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E &&
            (p[3] == 0xFA || p[3] == 0xFB)) {
            p += 4;
            continue;
        }

        /* JMP rel32 (E9 xx xx xx xx) */
        if (p[0] == 0xE9) {
            INT32 offset;
            memcpy(&offset, p + 1, sizeof(offset));
            p = p + 5 + offset;
            continue;
        }

        /* JMP rel8 (EB xx) */
        if (p[0] == 0xEB) {
            INT8 offset = (INT8)p[1];
            p = p + 2 + offset;
            continue;
        }

#if defined(_M_X64) || defined(__x86_64__)
        /* x64: JMP [rip+disp32] (FF 25 xx xx xx xx) */
        if (p[0] == 0xFF && p[1] == 0x25) {
            INT32 disp;
            memcpy(&disp, p + 2, sizeof(disp));
            p = *(LPBYTE*)(p + 6 + disp);
            continue;
        }
#else
        /* x86: JMP [addr32] (FF 25 xx xx xx xx) */
        if (p[0] == 0xFF && p[1] == 0x25) {
            LPBYTE* target;
            memcpy(&target, p + 2, sizeof(target));
            p = *target;
            continue;
        }
#endif

        break;  /* No more indirection */
    }

    /* Only return a result if we actually resolved to a different address */
    if (p == start) return nullptr;
    return (LPVOID)p;
}

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
extern BOOL    (WSAAPI *Original_WSAConnectByNameW)(SOCKET, LPWSTR, LPWSTR,
                LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                const struct timeval*, LPWSAOVERLAPPED);
extern BOOL    (WSAAPI *Original_WSAConnectByNameA)(SOCKET, LPCSTR, LPCSTR,
                LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                const struct timeval*, LPWSAOVERLAPPED);

/* UDP hooks */
extern int     (WSAAPI *Original_sendto)(SOCKET, const char*, int, int,
                const struct sockaddr*, int);
extern int     (WSAAPI *Original_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
                const struct sockaddr*, int, LPWSAOVERLAPPED,
                LPWSAOVERLAPPED_COMPLETION_ROUTINE);
extern int     (WSAAPI *Original_recvfrom)(SOCKET, char*, int, int,
                struct sockaddr*, int*);
extern int     (WSAAPI *Original_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
                struct sockaddr*, LPINT, LPWSAOVERLAPPED,
                LPWSAOVERLAPPED_COMPLETION_ROUTINE);

/* DNS hooks */
extern int     (WSAAPI *Original_getaddrinfo)(const char*, const char*,
                const struct addrinfo*, struct addrinfo**);
extern int     (WSAAPI *Original_GetAddrInfoW)(const wchar_t*, const wchar_t*,
                const ADDRINFOW*, ADDRINFOW**);
extern struct hostent* (WSAAPI *Original_gethostbyname)(const char*);
extern int     (WSAAPI *Original_GetAddrInfoExW)(const wchar_t*, const wchar_t*,
                DWORD, LPGUID, const ADDRINFOEXW*, PADDRINFOEXW*, struct timeval*,
                LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);

/* WinHTTP hooks */
extern void*   (WINAPI *Original_WinHttpOpen)(const wchar_t*, DWORD,
                const wchar_t*, const wchar_t*, DWORD);
extern int     (WINAPI *Original_WinHttpSetOption)(void*, DWORD, void*, DWORD);

/* WinINet hooks */
extern void*   (WINAPI *Original_InternetOpenW)(const wchar_t*, DWORD,
                const wchar_t*, const wchar_t*, DWORD);
extern void*   (WINAPI *Original_InternetOpenA)(const char*, DWORD,
                const char*, const char*, DWORD);

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
    /* WSAConnectByName - connects by hostname, bypasses getaddrinfo+connect */
    {
        L"ws2_32.dll", "WSAConnectByNameW",
        (LPVOID)Hooked_WSAConnectByNameW, (LPVOID*)&Original_WSAConnectByNameW,
        "WSAConnectByNameW()", false
    },
    {
        L"ws2_32.dll", "WSAConnectByNameA",
        (LPVOID)Hooked_WSAConnectByNameA, (LPVOID*)&Original_WSAConnectByNameA,
        "WSAConnectByNameA()", false
    },

    /* UDP hooks - SOCKS5 UDP ASSOCIATE relay + DNS leak prevention */
    {
        L"ws2_32.dll", "sendto",
        (LPVOID)Hooked_sendto, (LPVOID*)&Original_sendto,
        "sendto()", false
    },
    {
        L"ws2_32.dll", "WSASendTo",
        (LPVOID)Hooked_WSASendTo, (LPVOID*)&Original_WSASendTo,
        "WSASendTo()", false
    },
    {
        L"ws2_32.dll", "recvfrom",
        (LPVOID)Hooked_recvfrom, (LPVOID*)&Original_recvfrom,
        "recvfrom()", false
    },
    {
        L"ws2_32.dll", "WSARecvFrom",
        (LPVOID)Hooked_WSARecvFrom, (LPVOID*)&Original_WSARecvFrom,
        "WSARecvFrom()", false
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

    /* WinHTTP hooks - force proxy settings on higher-level HTTP API */
    {
        L"winhttp.dll", "WinHttpOpen",
        (LPVOID)Hooked_WinHttpOpen, (LPVOID*)&Original_WinHttpOpen,
        "WinHttpOpen()", false
    },
    {
        L"winhttp.dll", "WinHttpSetOption",
        (LPVOID)Hooked_WinHttpSetOption, (LPVOID*)&Original_WinHttpSetOption,
        "WinHttpSetOption()", false
    },

    /* WinINet hooks - force proxy settings on Internet Explorer HTTP API */
    {
        L"wininet.dll", "InternetOpenW",
        (LPVOID)Hooked_InternetOpenW, (LPVOID*)&Original_InternetOpenW,
        "InternetOpenW()", false
    },
    {
        L"wininet.dll", "InternetOpenA",
        (LPVOID)Hooked_InternetOpenA, (LPVOID*)&Original_InternetOpenA,
        "InternetOpenA()", false
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

        /*
         * If the trampoline builder failed, try to resolve the function
         * through any JMP/ENDBR chains and hook at the real body instead.
         * This handles functions that are thin stubs, have been pre-hooked
         * by security software, or start with CET ENDBR instructions that
         * confuse the disassembler.
         */
        if (status == MH_ERROR_UNSUPPORTED_FUNCTION) {
            LPVOID resolved = resolve_function(g_hooks[i].module, g_hooks[i].funcName);
            if (resolved) {
                ipc_client_log(PF_LOG_DEBUG,
                    "Retrying %s at resolved address (followed JMP/ENDBR chain)",
                    g_hooks[i].description);
                status = MH_CreateHook(resolved, g_hooks[i].detour, g_hooks[i].original);
            }
        }

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

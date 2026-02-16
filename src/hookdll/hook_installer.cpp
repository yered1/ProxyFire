/*
 * ProxyFire - hook_installer.cpp
 * Table-driven MinHook installation with IAT hooking fallback
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
#include <tlhelp32.h>

namespace proxyfire {

/*
 * Follow JMP chains, skip CET ENDBR instructions, and resolve common
 * security-software hook stubs to find the actual function body that
 * MinHook can trampoline.
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

        /* x64: mov rax, imm64; jmp rax  (48 B8 ... FF E0) — common AV hook */
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) {
            UINT64 target;
            memcpy(&target, p + 2, sizeof(target));
            p = (LPBYTE)(ULONG_PTR)target;
            continue;
        }

        /* x64: push lo32; mov [rsp+4], hi32; ret — another AV hook pattern */
        /*       68 xx xx xx xx  C7 44 24 04  xx xx xx xx  C3             */
        if (p[0] == 0x68 && p[5] == 0xC7 && p[6] == 0x44 &&
            p[7] == 0x24 && p[8] == 0x04 && p[13] == 0xC3) {
            UINT32 lo, hi;
            memcpy(&lo, p + 1, sizeof(lo));
            memcpy(&hi, p + 9, sizeof(hi));
            p = (LPBYTE)(ULONG_PTR)(((UINT64)hi << 32) | lo);
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

        /* x86: push addr32; ret (68 xx xx xx xx C3) — common hook pattern */
        if (p[0] == 0x68 && p[5] == 0xC3) {
            UINT32 target;
            memcpy(&target, p + 1, sizeof(target));
            p = (LPBYTE)(ULONG_PTR)target;
            continue;
        }
#endif

        break;  /* No more indirection */
    }

    /* Only return a result if we actually resolved to a different address */
    if (p == start) return nullptr;
    return (LPVOID)p;
}

/*
 * Dump the first 16 bytes of a function to the log for diagnostics.
 * Used when hooking fails so we can identify the instruction pattern
 * causing the issue.
 */
static void log_function_bytes(const wchar_t* module, const char* funcName,
                                const char* description) {
    HMODULE hMod = GetModuleHandleW(module);
    if (!hMod) return;

    FARPROC pProc = GetProcAddress(hMod, funcName);
    if (!pProc) return;

    LPBYTE p = (LPBYTE)pProc;
    char hex[16 * 3 + 1];
    static const char digits[] = "0123456789ABCDEF";
    for (int i = 0; i < 16; i++) {
        hex[i * 3]     = digits[(p[i] >> 4) & 0xF];
        hex[i * 3 + 1] = digits[p[i] & 0xF];
        hex[i * 3 + 2] = ' ';
    }
    hex[16 * 3] = '\0';

    ipc_client_log(PF_LOG_WARN, "%s bytes at %p: %s", description, (void*)p, hex);
}

/* ------------------------------------------------------------------ */
/*  IAT (Import Address Table) hooking fallback                       */
/*                                                                    */
/*  When MinHook's inline hooking fails (the function prologue can't  */
/*  be trampolined), we patch the IAT of every loaded module instead. */
/*  This replaces the function pointer in the import table rather     */
/*  than modifying the function's code, so it works regardless of     */
/*  what the function's prologue looks like.                          */
/*                                                                    */
/*  Limitation: only catches statically-imported calls. Dynamically   */
/*  resolved calls via GetProcAddress are not affected. This is       */
/*  acceptable for Winsock functions which are almost always           */
/*  statically imported.                                              */
/* ------------------------------------------------------------------ */

static bool patch_module_iat(HMODULE hModule, const char* targetDll,
                              const char* funcName, LPVOID realFunc,
                              LPVOID detour) {
    LPBYTE pBase = (LPBYTE)hModule;

    __try {
        PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)pBase;
        if (pDOS->e_magic != IMAGE_DOS_SIGNATURE) return false;

        PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(pBase + pDOS->e_lfanew);
        if (pNT->Signature != IMAGE_NT_SIGNATURE) return false;

        DWORD importRVA  = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        if (importRVA == 0 || importSize == 0) return false;

        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + importRVA);

        for (; pImport->Name != 0; pImport++) {
            const char* dllName = (const char*)(pBase + pImport->Name);
            if (_stricmp(dllName, targetDll) != 0) continue;

            /* Walk the IAT and INT (Import Name Table) in parallel */
            PIMAGE_THUNK_DATA pOrigThunk = pImport->OriginalFirstThunk
                ? (PIMAGE_THUNK_DATA)(pBase + pImport->OriginalFirstThunk)
                : nullptr;
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pBase + pImport->FirstThunk);

            for (; pThunk->u1.Function != 0;
                   pOrigThunk ? (void)(pOrigThunk++) : (void)0, pThunk++) {
                bool match = false;

                /* Try matching by name via the INT */
                if (pOrigThunk && !IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                    PIMAGE_IMPORT_BY_NAME pName =
                        (PIMAGE_IMPORT_BY_NAME)(pBase + (DWORD)(pOrigThunk->u1.AddressOfData));
                    match = (strcmp(pName->Name, funcName) == 0);
                }

                /* Also try matching by address (covers ordinal imports) */
                if (!match && (LPVOID)(ULONG_PTR)pThunk->u1.Function == realFunc) {
                    match = true;
                }

                if (!match) continue;

                /* Found the entry - patch it */
                DWORD oldProtect;
                if (VirtualProtect(&pThunk->u1.Function, sizeof(ULONG_PTR),
                                    PAGE_READWRITE, &oldProtect)) {
                    pThunk->u1.Function = (ULONG_PTR)detour;
                    VirtualProtect(&pThunk->u1.Function, sizeof(ULONG_PTR),
                                    oldProtect, &oldProtect);
                    return true;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Malformed PE or access violation - skip this module */
    }

    return false;
}

static bool iat_hook_function(const wchar_t* moduleW, const char* moduleA,
                               const char* funcName, LPVOID detour,
                               LPVOID* ppOriginal) {
    HMODULE hTargetMod = GetModuleHandleW(moduleW);
    if (!hTargetMod) return false;

    LPVOID realFunc = (LPVOID)GetProcAddress(hTargetMod, funcName);
    if (!realFunc) return false;

    /* Set the original function pointer so the detour can call through */
    if (ppOriginal && *ppOriginal == nullptr) {
        *ppOriginal = realFunc;
    }

    int patched = 0;

    /* Patch IAT of all loaded modules */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);

        for (BOOL ok = Module32FirstW(hSnap, &me); ok; ok = Module32NextW(hSnap, &me)) {
            /* Don't patch the module that exports the function */
            if ((HMODULE)me.modBaseAddr == hTargetMod) continue;
            if (patch_module_iat((HMODULE)me.modBaseAddr, moduleA, funcName,
                                  realFunc, detour)) {
                patched++;
            }
        }
        CloseHandle(hSnap);
    } else {
        /* Fallback: at least patch the main executable */
        HMODULE hExe = GetModuleHandleW(nullptr);
        if (hExe && patch_module_iat(hExe, moduleA, funcName, realFunc, detour)) {
            patched++;
        }
    }

    return patched > 0;
}

/* ------------------------------------------------------------------ */
/*  Hook table                                                        */
/* ------------------------------------------------------------------ */

struct HookEntry {
    const wchar_t* module;
    const char*    moduleA;     /* Narrow name for IAT lookup */
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
        L"ws2_32.dll", "ws2_32.dll", "connect",
        (LPVOID)Hooked_connect, (LPVOID*)&Original_connect,
        "connect()", true
    },
    {
        L"ws2_32.dll", "ws2_32.dll", "WSAConnect",
        (LPVOID)Hooked_WSAConnect, (LPVOID*)&Original_WSAConnect,
        "WSAConnect()", true
    },
    {
        L"ws2_32.dll", "ws2_32.dll", "closesocket",
        (LPVOID)Hooked_closesocket, (LPVOID*)&Original_closesocket,
        "closesocket()", true
    },
    /* WSAIoctl - needed to intercept ConnectEx function pointer requests */
    {
        L"ws2_32.dll", "ws2_32.dll", "WSAIoctl",
        (LPVOID)Hooked_WSAIoctl, (LPVOID*)&Original_WSAIoctl,
        "WSAIoctl()", false
    },
    /* WSAConnectByName - connects by hostname, bypasses getaddrinfo+connect */
    {
        L"ws2_32.dll", "ws2_32.dll", "WSAConnectByNameW",
        (LPVOID)Hooked_WSAConnectByNameW, (LPVOID*)&Original_WSAConnectByNameW,
        "WSAConnectByNameW()", false
    },
    {
        L"ws2_32.dll", "ws2_32.dll", "WSAConnectByNameA",
        (LPVOID)Hooked_WSAConnectByNameA, (LPVOID*)&Original_WSAConnectByNameA,
        "WSAConnectByNameA()", false
    },

    /* UDP hooks - SOCKS5 UDP ASSOCIATE relay + DNS leak prevention */
    {
        L"ws2_32.dll", "ws2_32.dll", "sendto",
        (LPVOID)Hooked_sendto, (LPVOID*)&Original_sendto,
        "sendto()", false
    },
    {
        L"ws2_32.dll", "ws2_32.dll", "WSASendTo",
        (LPVOID)Hooked_WSASendTo, (LPVOID*)&Original_WSASendTo,
        "WSASendTo()", false
    },
    {
        L"ws2_32.dll", "ws2_32.dll", "recvfrom",
        (LPVOID)Hooked_recvfrom, (LPVOID*)&Original_recvfrom,
        "recvfrom()", false
    },
    {
        L"ws2_32.dll", "ws2_32.dll", "WSARecvFrom",
        (LPVOID)Hooked_WSARecvFrom, (LPVOID*)&Original_WSARecvFrom,
        "WSARecvFrom()", false
    },

    /* DNS hooks */
    {
        L"ws2_32.dll", "ws2_32.dll", "getaddrinfo",
        (LPVOID)Hooked_getaddrinfo, (LPVOID*)&Original_getaddrinfo,
        "getaddrinfo()", false
    },
    {
        L"ws2_32.dll", "ws2_32.dll", "GetAddrInfoW",
        (LPVOID)Hooked_GetAddrInfoW, (LPVOID*)&Original_GetAddrInfoW,
        "GetAddrInfoW()", false
    },
    {
        L"ws2_32.dll", "ws2_32.dll", "gethostbyname",
        (LPVOID)Hooked_gethostbyname, (LPVOID*)&Original_gethostbyname,
        "gethostbyname()", false
    },
    /* Async DNS - GetAddrInfoExW (used by modern Windows apps) */
    {
        L"ws2_32.dll", "ws2_32.dll", "GetAddrInfoExW",
        (LPVOID)Hooked_GetAddrInfoExW, (LPVOID*)&Original_GetAddrInfoExW,
        "GetAddrInfoExW()", false
    },

    /* WinHTTP hooks - force proxy settings on higher-level HTTP API */
    {
        L"winhttp.dll", "winhttp.dll", "WinHttpOpen",
        (LPVOID)Hooked_WinHttpOpen, (LPVOID*)&Original_WinHttpOpen,
        "WinHttpOpen()", false
    },
    {
        L"winhttp.dll", "winhttp.dll", "WinHttpSetOption",
        (LPVOID)Hooked_WinHttpSetOption, (LPVOID*)&Original_WinHttpSetOption,
        "WinHttpSetOption()", false
    },

    /* WinINet hooks - force proxy settings on Internet Explorer HTTP API */
    {
        L"wininet.dll", "wininet.dll", "InternetOpenW",
        (LPVOID)Hooked_InternetOpenW, (LPVOID*)&Original_InternetOpenW,
        "InternetOpenW()", false
    },
    {
        L"wininet.dll", "wininet.dll", "InternetOpenA",
        (LPVOID)Hooked_InternetOpenA, (LPVOID*)&Original_InternetOpenA,
        "InternetOpenA()", false
    },

    /* Process hooks (for child injection) */
    {
        L"kernel32.dll", "kernel32.dll", "CreateProcessW",
        (LPVOID)Hooked_CreateProcessW, (LPVOID*)&Original_CreateProcessW,
        "CreateProcessW()", false
    },
    {
        L"kernel32.dll", "kernel32.dll", "CreateProcessA",
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
         * Fallback 1: If trampoline creation failed, try resolving through
         * JMP/ENDBR/AV-hook chains and hook at the real function body.
         */
        if (status == MH_ERROR_UNSUPPORTED_FUNCTION) {
            LPVOID resolved = resolve_function(g_hooks[i].module, g_hooks[i].funcName);
            if (resolved) {
                ipc_client_log(PF_LOG_DEBUG,
                    "Retrying %s at resolved address %p (followed JMP/stub chain)",
                    g_hooks[i].description, resolved);
                status = MH_CreateHook(resolved, g_hooks[i].detour, g_hooks[i].original);
            }
        }

        /*
         * Fallback 2: If inline hooking completely failed, try IAT hooking.
         * This patches function pointers in the import tables of all loaded
         * modules, which works regardless of the function's prologue.
         */
        if (status == MH_ERROR_UNSUPPORTED_FUNCTION || status == MH_ERROR_MEMORY_ALLOC) {
            log_function_bytes(g_hooks[i].module, g_hooks[i].funcName,
                               g_hooks[i].description);

            ipc_client_log(PF_LOG_INFO,
                "Inline hook failed for %s, falling back to IAT hooking",
                g_hooks[i].description);

            if (iat_hook_function(g_hooks[i].module, g_hooks[i].moduleA,
                                   g_hooks[i].funcName, g_hooks[i].detour,
                                   g_hooks[i].original)) {
                ipc_client_log(PF_LOG_INFO, "IAT-hooked %s successfully",
                              g_hooks[i].description);
                status = MH_OK;  /* Treat as success */
            } else {
                ipc_client_log(PF_LOG_WARN,
                    "IAT hook also failed for %s (no imports found)",
                    g_hooks[i].description);
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

/*
 * ProxyFire - hook_process.cpp
 * Hooked CreateProcess for child process injection
 *
 * When inject_children is enabled, newly created child processes
 * are also injected with the ProxyFire hook DLL, ensuring all
 * child processes also route through the proxy.
 */

#include "hook_process.h"
#include "ipc_client.h"

#include <proxyfire/common.h>
#include <proxyfire/config.h>

#include <cstring>
#include <string>

#ifdef _WIN32
#include <windows.h>

extern proxyfire::ProxyFireConfig g_config;

/* Original function pointers */
BOOL (WINAPI *Original_CreateProcessW)(LPCWSTR, LPWSTR,
      LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
      LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = nullptr;
BOOL (WINAPI *Original_CreateProcessA)(LPCSTR, LPSTR,
      LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
      LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = nullptr;

namespace proxyfire {

/*
 * Helper: Inject the hook DLL into a suspended child process.
 * This uses the same technique as the launcher:
 *   1. VirtualAllocEx to allocate memory in child
 *   2. WriteProcessMemory to write DLL path
 *   3. CreateRemoteThread to call LoadLibraryW
 */
static bool inject_into_child(HANDLE hProcess, HANDLE hThread) {
    (void)hThread;

    /* Get our own DLL path */
    wchar_t dll_path[MAX_PATH] = {};
    HMODULE hSelf = nullptr;

    /* Get handle to our own DLL */
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)inject_into_child,
        &hSelf
    );

    if (!hSelf) return false;

    GetModuleFileNameW(hSelf, dll_path, MAX_PATH);
    if (dll_path[0] == L'\0') return false;

    size_t path_size = (wcslen(dll_path) + 1) * sizeof(wchar_t);

    /* Allocate memory in child process */
    LPVOID remote_mem = VirtualAllocEx(hProcess, nullptr, path_size,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        ipc_client_log(PF_LOG_ERROR, "Failed to allocate memory in child: %lu",
                      GetLastError());
        return false;
    }

    /* Write DLL path to child process */
    if (!WriteProcessMemory(hProcess, remote_mem, dll_path, path_size, nullptr)) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        ipc_client_log(PF_LOG_ERROR, "Failed to write to child process: %lu",
                      GetLastError());
        return false;
    }

    /* Get LoadLibraryW address (same in all processes due to ASLR sharing) */
    LPVOID load_library = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                  "LoadLibraryW");
    if (!load_library) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return false;
    }

    /* Create remote thread to load our DLL */
    HANDLE hRemote = CreateRemoteThread(hProcess, nullptr, 0,
                                         (LPTHREAD_START_ROUTINE)load_library,
                                         remote_mem, 0, nullptr);
    if (!hRemote) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        ipc_client_log(PF_LOG_ERROR, "Failed to create remote thread in child: %lu",
                      GetLastError());
        return false;
    }

    /* Wait for DLL to load */
    WaitForSingleObject(hRemote, 10000);
    CloseHandle(hRemote);

    /* Free the allocated memory */
    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);

    return true;
}

BOOL WINAPI Hooked_CreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    if (!g_config.inject_children) {
        return Original_CreateProcessW(lpApplicationName, lpCommandLine,
            lpProcessAttributes, lpThreadAttributes, bInheritHandles,
            dwCreationFlags, lpEnvironment, lpCurrentDirectory,
            lpStartupInfo, lpProcessInformation);
    }

    /* Add CREATE_SUSPENDED so we can inject before the child runs */
    DWORD originalFlags = dwCreationFlags;
    dwCreationFlags |= CREATE_SUSPENDED;

    BOOL result = Original_CreateProcessW(lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles,
        dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    if (result && lpProcessInformation) {
        ipc_client_log(PF_LOG_INFO, "Child process created (PID: %lu), injecting hook DLL",
                      lpProcessInformation->dwProcessId);

        /* Inject our hook DLL into the child */
        inject_into_child(lpProcessInformation->hProcess,
                         lpProcessInformation->hThread);

        /* Notify launcher about the child */
        ipc_client_notify_child(lpProcessInformation->dwProcessId,
                               lpProcessInformation->dwThreadId);

        /* If caller didn't request suspended, resume now */
        if (!(originalFlags & CREATE_SUSPENDED)) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }

    return result;
}

BOOL WINAPI Hooked_CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    if (!g_config.inject_children) {
        return Original_CreateProcessA(lpApplicationName, lpCommandLine,
            lpProcessAttributes, lpThreadAttributes, bInheritHandles,
            dwCreationFlags, lpEnvironment, lpCurrentDirectory,
            lpStartupInfo, lpProcessInformation);
    }

    DWORD originalFlags = dwCreationFlags;
    dwCreationFlags |= CREATE_SUSPENDED;

    BOOL result = Original_CreateProcessA(lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles,
        dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);

    if (result && lpProcessInformation) {
        ipc_client_log(PF_LOG_INFO, "Child process created (PID: %lu), injecting hook DLL",
                      lpProcessInformation->dwProcessId);

        inject_into_child(lpProcessInformation->hProcess,
                         lpProcessInformation->hThread);

        ipc_client_notify_child(lpProcessInformation->dwProcessId,
                               lpProcessInformation->dwThreadId);

        if (!(originalFlags & CREATE_SUSPENDED)) {
            ResumeThread(lpProcessInformation->hThread);
        }
    }

    return result;
}

} // namespace proxyfire

#endif /* _WIN32 */

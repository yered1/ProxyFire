/*
 * ProxyFire - injector.cpp
 * DLL injection using CreateRemoteThread + LoadLibraryW
 *
 * Injection sequence:
 * 1. VirtualAllocEx - Allocate memory in target for DLL path string
 * 2. WriteProcessMemory - Write the DLL path to allocated memory
 * 3. CreateRemoteThread - Execute LoadLibraryW with DLL path as argument
 * 4. WaitForSingleObject - Wait for DLL to load
 * 5. VirtualFreeEx - Free allocated memory
 */

#include "injector.h"
#include "logger.h"
#include "string_utils.h"

#ifdef _WIN32
#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

namespace proxyfire {

bool inject_dll(HANDLE hProcess, const std::wstring& dll_path) {
    if (!hProcess || dll_path.empty()) {
        log_error("inject_dll: invalid arguments");
        return false;
    }

    size_t path_size = (dll_path.size() + 1) * sizeof(wchar_t);

    /* Step 1: Allocate memory in the target process for the DLL path */
    LPVOID remote_mem = VirtualAllocEx(
        hProcess,
        nullptr,
        path_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remote_mem) {
        log_error("VirtualAllocEx failed: %s", format_win_error(GetLastError()).c_str());
        return false;
    }

    log_debug("Allocated %zu bytes in target at %p", path_size, remote_mem);

    /* Step 2: Write the DLL path into the allocated memory */
    SIZE_T bytes_written = 0;
    if (!WriteProcessMemory(hProcess, remote_mem, dll_path.c_str(), path_size, &bytes_written)) {
        log_error("WriteProcessMemory failed: %s", format_win_error(GetLastError()).c_str());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return false;
    }

    log_debug("Wrote DLL path to target process (%zu bytes)", (size_t)bytes_written);

    /* Step 3: Get LoadLibraryW address (same across all processes due to ASLR sharing) */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        log_error("Failed to get kernel32.dll handle");
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return false;
    }

    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        log_error("Failed to get LoadLibraryW address");
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return false;
    }

    /* Step 4: Create remote thread to call LoadLibraryW(dll_path) */
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW,
        remote_mem,
        0,
        nullptr
    );

    if (!hThread) {
        log_error("CreateRemoteThread failed: %s", format_win_error(GetLastError()).c_str());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return false;
    }

    log_debug("Created remote thread for LoadLibraryW");

    /* Step 5: Wait for the DLL to finish loading */
    DWORD wait_result = WaitForSingleObject(hThread, 15000);
    if (wait_result != WAIT_OBJECT_0) {
        log_error("LoadLibraryW thread timed out or failed (wait=%lu)", wait_result);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return false;
    }

    /* Check the thread exit code (LoadLibraryW return value) */
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);

    /* Step 6: Free the allocated memory */
    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);

    if (exit_code == 0) {
        log_error("LoadLibraryW returned NULL - DLL load failed in target");
        return false;
    }

    log_info("Successfully injected DLL into target process");
    return true;
}

std::wstring get_hook_dll_path(const wchar_t* arch_suffix) {
    wchar_t exe_path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    /* Get directory of the launcher executable */
    PathRemoveFileSpecW(exe_path);

    std::wstring dll_path = std::wstring(exe_path) + L"\\proxyfire_hook" +
                            arch_suffix + L".dll";

    return dll_path;
}

} // namespace proxyfire

#else
/* Non-Windows stub */
namespace proxyfire {
bool inject_dll(void*, const std::wstring&) { return false; }
std::wstring get_hook_dll_path(const wchar_t*) { return L""; }
} // namespace proxyfire
#endif

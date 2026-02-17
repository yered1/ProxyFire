/*
 * ProxyFire - process_launcher.cpp
 * Target process creation and management
 */

#include "process_launcher.h"
#include "logger.h"
#include "string_utils.h"

#include <proxyfire/common.h>

#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace proxyfire {

PeArch detect_pe_arch(const std::string& exe_path) {
#ifdef _WIN32
    HANDLE hFile = CreateFileA(exe_path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return PeArch::UNKNOWN;
    }

    /* Read DOS header */
    IMAGE_DOS_HEADER dos_header;
    DWORD bytes_read = 0;
    if (!ReadFile(hFile, &dos_header, sizeof(dos_header), &bytes_read, nullptr) ||
        bytes_read != sizeof(dos_header) ||
        dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return PeArch::UNKNOWN;
    }

    /* Seek to PE header */
    SetFilePointer(hFile, dos_header.e_lfanew, nullptr, FILE_BEGIN);

    /* Read PE signature + file header */
    DWORD pe_sig;
    IMAGE_FILE_HEADER file_header;
    if (!ReadFile(hFile, &pe_sig, sizeof(pe_sig), &bytes_read, nullptr) ||
        pe_sig != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return PeArch::UNKNOWN;
    }

    if (!ReadFile(hFile, &file_header, sizeof(file_header), &bytes_read, nullptr)) {
        CloseHandle(hFile);
        return PeArch::UNKNOWN;
    }

    CloseHandle(hFile);

    switch (file_header.Machine) {
        case IMAGE_FILE_MACHINE_I386:  return PeArch::X86;
        case IMAGE_FILE_MACHINE_AMD64: return PeArch::X64;
        default: return PeArch::UNKNOWN;
    }
#else
    (void)exe_path;
    return PeArch::UNKNOWN;
#endif
}

const char* pe_arch_name(PeArch arch) {
    switch (arch) {
        case PeArch::X86: return "x86";
        case PeArch::X64: return "x64";
        default:          return "unknown";
    }
}

#ifdef _WIN32

bool create_suspended_process(
    const std::string& exe_path,
    const std::vector<std::string>& args,
    const std::wstring& pipe_name,
    const std::wstring& ready_event_name,
    PROCESS_INFORMATION* pi)
{
    if (!pi) return false;
    memset(pi, 0, sizeof(PROCESS_INFORMATION));

    /* Build command line */
    std::string cmdline = "\"" + exe_path + "\"";
    for (const auto& arg : args) {
        cmdline += " ";
        /* Quote arguments containing spaces */
        if (arg.find(' ') != std::string::npos && arg[0] != '"') {
            cmdline += "\"" + arg + "\"";
        } else {
            cmdline += arg;
        }
    }

    log_debug("Command line: %s", cmdline.c_str());

    /*
     * Build a custom environment block with PROXYFIRE_PIPE set.
     * We copy the parent's environment and append our variable.
     */
    std::wstring env_block;

    /* Get current environment */
    wchar_t* current_env = GetEnvironmentStringsW();
    if (current_env) {
        const wchar_t* ptr = current_env;
        while (*ptr) {
            size_t len = wcslen(ptr);
            env_block.append(ptr, len);
            env_block.push_back(L'\0');
            ptr += len + 1;
        }
        FreeEnvironmentStringsW(current_env);
    }

    /* Add our pipe name variable */
    std::wstring pipe_var = std::wstring(PROXYFIRE_ENV_PIPE) + L"=" + pipe_name;
    env_block.append(pipe_var);
    env_block.push_back(L'\0');

    /* Add ready event name variable */
    if (!ready_event_name.empty()) {
        std::wstring event_var = std::wstring(PROXYFIRE_ENV_READY_EVENT) + L"=" + ready_event_name;
        env_block.append(event_var);
        env_block.push_back(L'\0');
    }

    /* Double null terminator */
    env_block.push_back(L'\0');

    /* Create the process in suspended state */
    STARTUPINFOW si = {};
    si.cb = sizeof(si);

    std::wstring wcmdline = to_wide(cmdline);

    BOOL result = CreateProcessW(
        nullptr,                        /* lpApplicationName */
        &wcmdline[0],                   /* lpCommandLine (mutable) */
        nullptr,                        /* lpProcessAttributes */
        nullptr,                        /* lpThreadAttributes */
        FALSE,                          /* bInheritHandles */
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        (LPVOID)env_block.c_str(),      /* lpEnvironment */
        nullptr,                        /* lpCurrentDirectory */
        &si,
        pi
    );

    if (!result) {
        log_error("CreateProcessW failed: %s", format_win_error(GetLastError()).c_str());
        return false;
    }

    log_info("Created suspended process PID %lu", pi->dwProcessId);
    return true;
}

bool resume_process(PROCESS_INFORMATION* pi) {
    if (!pi || !pi->hThread) return false;

    DWORD result = ResumeThread(pi->hThread);
    if (result == (DWORD)-1) {
        log_error("ResumeThread failed: %s", format_win_error(GetLastError()).c_str());
        return false;
    }
    return true;
}

uint32_t wait_for_process(PROCESS_INFORMATION* pi) {
    if (!pi || !pi->hProcess) return 1;

    WaitForSingleObject(pi->hProcess, INFINITE);

    DWORD exit_code = 1;
    GetExitCodeProcess(pi->hProcess, &exit_code);
    return exit_code;
}

void close_process(PROCESS_INFORMATION* pi) {
    if (!pi) return;
    if (pi->hProcess) CloseHandle(pi->hProcess);
    if (pi->hThread) CloseHandle(pi->hThread);
    pi->hProcess = nullptr;
    pi->hThread = nullptr;
}

#endif

} // namespace proxyfire

/*
 * ProxyFire - process_launcher.h
 * Target process creation and management
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#endif

namespace proxyfire {

/* PE architecture detection */
enum class PeArch {
    UNKNOWN,
    X86,
    X64
};

/**
 * Detect the architecture of a PE executable.
 */
PeArch detect_pe_arch(const std::string& exe_path);

/**
 * Get the PE architecture as a string.
 */
const char* pe_arch_name(PeArch arch);

#ifdef _WIN32

/**
 * Create a process in suspended state with a custom environment.
 *
 * @param exe_path      Path to the executable
 * @param args          Arguments for the executable
 * @param pipe_name     Named pipe name (set as env var for hook DLL)
 * @param pi            [out] Process information
 *
 * @return true on success
 */
bool create_suspended_process(
    const std::string& exe_path,
    const std::vector<std::string>& args,
    const std::wstring& pipe_name,
    PROCESS_INFORMATION* pi
);

/**
 * Resume the main thread of a suspended process.
 */
bool resume_process(PROCESS_INFORMATION* pi);

/**
 * Wait for a process to exit and return its exit code.
 */
uint32_t wait_for_process(PROCESS_INFORMATION* pi);

/**
 * Close process handles.
 */
void close_process(PROCESS_INFORMATION* pi);

#endif

} // namespace proxyfire

/*
 * ProxyFire - injector.h
 * DLL injection engine
 */

#pragma once

#include <string>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#endif

namespace proxyfire {

#ifdef _WIN32

/**
 * Inject a DLL into a target process using CreateRemoteThread + LoadLibraryW.
 *
 * The target process should be in a suspended state.
 *
 * @param hProcess      Handle to the target process
 * @param dll_path      Full path to the DLL to inject
 *
 * @return true on success
 */
bool inject_dll(HANDLE hProcess, const std::wstring& dll_path);

/**
 * Get the full path to the hook DLL for the given architecture.
 * Looks next to the launcher executable.
 */
std::wstring get_hook_dll_path(const wchar_t* arch_suffix);

#endif

} // namespace proxyfire

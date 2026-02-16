/*
 * ProxyFire - hook_winhttp.h
 * WinHTTP and WinINet proxy configuration hooks
 *
 * Instead of hooking every HTTP function, we intercept the session
 * creation and proxy configuration functions. WinHTTP and WinINet
 * natively support proxies, so we just need to force their proxy
 * settings to match our configuration.
 */

#pragma once

#ifdef _WIN32
#include <windows.h>

namespace proxyfire {

/* WinHTTP hooks */
void* WINAPI Hooked_WinHttpOpen(const wchar_t* pszAgentW, DWORD dwAccessType,
                                 const wchar_t* pszProxyW, const wchar_t* pszProxyBypassW,
                                 DWORD dwFlags);

int WINAPI Hooked_WinHttpSetOption(void* hInternet, DWORD dwOption,
                                    void* lpBuffer, DWORD dwBufferLength);

/* WinINet hooks */
void* WINAPI Hooked_InternetOpenW(const wchar_t* lpszAgent, DWORD dwAccessType,
                                   const wchar_t* lpszProxy, const wchar_t* lpszProxyBypass,
                                   DWORD dwFlags);

void* WINAPI Hooked_InternetOpenA(const char* lpszAgent, DWORD dwAccessType,
                                   const char* lpszProxy, const char* lpszProxyBypass,
                                   DWORD dwFlags);

} // namespace proxyfire

#endif

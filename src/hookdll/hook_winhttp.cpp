/*
 * ProxyFire - hook_winhttp.cpp
 * WinHTTP and WinINet proxy configuration hooks
 *
 * WinHTTP and WinINet are higher-level HTTP APIs that many Windows
 * applications use instead of raw Winsock. Rather than hooking every
 * HTTP function (WinHttpSendRequest, HttpSendRequestW, etc.), we
 * intercept session creation and proxy configuration to force traffic
 * through ProxyFire's configured proxy.
 *
 * WinHTTP (winhttp.dll):
 *   - WinHttpOpen: force WINHTTP_ACCESS_TYPE_NAMED_PROXY with our proxy string
 *   - WinHttpSetOption: intercept WINHTTP_OPTION_PROXY to prevent overrides
 *
 * WinINet (wininet.dll):
 *   - InternetOpenW/A: force INTERNET_OPEN_TYPE_PROXY with our proxy string
 */

#include "hook_winhttp.h"
#include "ipc_client.h"
#include "string_utils.h"

#include <proxyfire/config.h>
#include <proxyfire/proxy_types.h>

#include <cstdio>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <windows.h>

/*
 * WinHTTP / WinINet constants.
 * Defined inline to avoid pulling in <winhttp.h> / <wininet.h>, which can
 * conflict with Winsock headers and introduce unnecessary dependencies.
 */
#define PF_WINHTTP_ACCESS_TYPE_NAMED_PROXY  3
#define PF_WINHTTP_OPTION_PROXY             38

#define PF_INTERNET_OPEN_TYPE_PROXY         3

/* Global config - set during DLL init */
extern ProxyFireConfig g_config;

/* Original function pointers */
void* (WINAPI *Original_WinHttpOpen)(const wchar_t*, DWORD,
       const wchar_t*, const wchar_t*, DWORD) = nullptr;
int   (WINAPI *Original_WinHttpSetOption)(void*, DWORD,
       void*, DWORD) = nullptr;
void* (WINAPI *Original_InternetOpenW)(const wchar_t*, DWORD,
       const wchar_t*, const wchar_t*, DWORD) = nullptr;
void* (WINAPI *Original_InternetOpenA)(const char*, DWORD,
       const char*, const char*, DWORD) = nullptr;

namespace proxyfire {

/*
 * Build the proxy string for WinHTTP from the first configured proxy.
 *
 * WinHTTP format:
 *   HTTP proxy:  "http=host:port;https=host:port"
 *   SOCKS proxy: "socks=host:port"
 *
 * Note: WinHTTP SOCKS support (via WINHTTP_ACCESS_TYPE_NAMED_PROXY with
 * "socks=host:port") requires Windows 8.1 or later. On older systems,
 * SOCKS through WinHTTP is not natively supported. We log a warning but
 * still attempt the configuration.
 *
 * Returns an empty string if no proxies are configured.
 */
static std::wstring build_winhttp_proxy_string() {
    if (g_config.proxy_count == 0) {
        return std::wstring();
    }

    const ProxyEntry& proxy = g_config.proxies[0];
    char narrow_buf[600];

    switch (proxy.proto) {
        case PROXY_SOCKS5:
        case PROXY_SOCKS4:
        case PROXY_SOCKS4A:
            _snprintf_s(narrow_buf, sizeof(narrow_buf), _TRUNCATE,
                        "socks=%s:%u", proxy.host, proxy.port);
            if (proxy.proto == PROXY_SOCKS5) {
                ipc_client_log(PF_LOG_DEBUG,
                    "WinHTTP: using SOCKS5 proxy %s:%u "
                    "(requires Windows 8.1+ for native support)",
                    proxy.host, proxy.port);
            } else {
                ipc_client_log(PF_LOG_WARN,
                    "WinHTTP: SOCKS4/4a proxy %s:%u configured; "
                    "WinHTTP only natively supports SOCKS5 (Windows 8.1+). "
                    "Connection may fail.",
                    proxy.host, proxy.port);
            }
            break;

        case PROXY_HTTP:
            _snprintf_s(narrow_buf, sizeof(narrow_buf), _TRUNCATE,
                        "http=%s:%u;https=%s:%u",
                        proxy.host, proxy.port,
                        proxy.host, proxy.port);
            ipc_client_log(PF_LOG_DEBUG,
                "WinHTTP: using HTTP proxy %s:%u",
                proxy.host, proxy.port);
            break;

        default:
            ipc_client_log(PF_LOG_WARN,
                "WinHTTP: unknown proxy protocol %d", (int)proxy.proto);
            return std::wstring();
    }

    return to_wide(std::string(narrow_buf));
}

/*
 * Build the proxy string for WinINet from the first configured proxy.
 *
 * WinINet format:
 *   HTTP proxy:  "http=host:port https=host:port"
 *   SOCKS proxy: "socks=host:port"
 *
 * Returns an empty string if no proxies are configured.
 */
static std::string build_wininet_proxy_string() {
    if (g_config.proxy_count == 0) {
        return std::string();
    }

    const ProxyEntry& proxy = g_config.proxies[0];
    char buf[600];

    switch (proxy.proto) {
        case PROXY_SOCKS5:
        case PROXY_SOCKS4:
        case PROXY_SOCKS4A:
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "socks=%s:%u", proxy.host, proxy.port);
            ipc_client_log(PF_LOG_DEBUG,
                "WinINet: using SOCKS proxy %s:%u",
                proxy.host, proxy.port);
            break;

        case PROXY_HTTP:
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "http=%s:%u https=%s:%u",
                        proxy.host, proxy.port,
                        proxy.host, proxy.port);
            ipc_client_log(PF_LOG_DEBUG,
                "WinINet: using HTTP proxy %s:%u",
                proxy.host, proxy.port);
            break;

        default:
            ipc_client_log(PF_LOG_WARN,
                "WinINet: unknown proxy protocol %d", (int)proxy.proto);
            return std::string();
    }

    return std::string(buf);
}

/*
 * Hooked WinHttpOpen()
 *
 * Intercepts WinHTTP session creation to force proxy settings.
 * If a proxy is configured, we override dwAccessType to
 * WINHTTP_ACCESS_TYPE_NAMED_PROXY and supply our proxy string.
 */
void* WINAPI Hooked_WinHttpOpen(const wchar_t* pszAgentW, DWORD dwAccessType,
                                 const wchar_t* pszProxyW, const wchar_t* pszProxyBypassW,
                                 DWORD dwFlags)
{
    if (g_config.proxy_count == 0) {
        ipc_client_log(PF_LOG_DEBUG,
            "WinHttpOpen: no proxies configured, passing through");
        return Original_WinHttpOpen(pszAgentW, dwAccessType,
                                     pszProxyW, pszProxyBypassW, dwFlags);
    }

    std::wstring proxy_str = build_winhttp_proxy_string();
    if (proxy_str.empty()) {
        return Original_WinHttpOpen(pszAgentW, dwAccessType,
                                     pszProxyW, pszProxyBypassW, dwFlags);
    }

    ipc_client_log(PF_LOG_INFO,
        "WinHttpOpen: overriding proxy to %s",
        to_narrow(proxy_str).c_str());

    /*
     * Force WINHTTP_ACCESS_TYPE_NAMED_PROXY and supply our proxy string.
     * Pass NULL for bypass to ensure all traffic goes through the proxy.
     */
    return Original_WinHttpOpen(pszAgentW,
                                 PF_WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                                 proxy_str.c_str(),
                                 NULL,  /* No bypass - proxy everything */
                                 dwFlags);
}

/*
 * Hooked WinHttpSetOption()
 *
 * Intercepts WINHTTP_OPTION_PROXY to prevent applications from
 * overriding our proxy configuration after session creation.
 * All other options are passed through unchanged.
 */
int WINAPI Hooked_WinHttpSetOption(void* hInternet, DWORD dwOption,
                                    void* lpBuffer, DWORD dwBufferLength)
{
    if (dwOption == PF_WINHTTP_OPTION_PROXY && g_config.proxy_count > 0) {
        ipc_client_log(PF_LOG_DEBUG,
            "WinHttpSetOption: blocked WINHTTP_OPTION_PROXY override "
            "(keeping ProxyFire configuration)");
        /*
         * Return TRUE (success) to the caller so it thinks the option
         * was set, but we silently discard the change.
         */
        return TRUE;
    }

    return Original_WinHttpSetOption(hInternet, dwOption,
                                      lpBuffer, dwBufferLength);
}

/*
 * Hooked InternetOpenW()
 *
 * Intercepts WinINet session creation (wide-char version) to force
 * proxy settings. If a proxy is configured, we override dwAccessType
 * to INTERNET_OPEN_TYPE_PROXY and supply our proxy string.
 */
void* WINAPI Hooked_InternetOpenW(const wchar_t* lpszAgent, DWORD dwAccessType,
                                   const wchar_t* lpszProxy, const wchar_t* lpszProxyBypass,
                                   DWORD dwFlags)
{
    if (g_config.proxy_count == 0) {
        ipc_client_log(PF_LOG_DEBUG,
            "InternetOpenW: no proxies configured, passing through");
        return Original_InternetOpenW(lpszAgent, dwAccessType,
                                       lpszProxy, lpszProxyBypass, dwFlags);
    }

    std::string proxy_narrow = build_wininet_proxy_string();
    if (proxy_narrow.empty()) {
        return Original_InternetOpenW(lpszAgent, dwAccessType,
                                       lpszProxy, lpszProxyBypass, dwFlags);
    }

    std::wstring proxy_wide = to_wide(proxy_narrow);

    ipc_client_log(PF_LOG_INFO,
        "InternetOpenW: overriding proxy to %s",
        proxy_narrow.c_str());

    return Original_InternetOpenW(lpszAgent,
                                   PF_INTERNET_OPEN_TYPE_PROXY,
                                   proxy_wide.c_str(),
                                   NULL,  /* No bypass - proxy everything */
                                   dwFlags);
}

/*
 * Hooked InternetOpenA()
 *
 * Intercepts WinINet session creation (ANSI version) to force
 * proxy settings. Same logic as InternetOpenW but with narrow strings.
 */
void* WINAPI Hooked_InternetOpenA(const char* lpszAgent, DWORD dwAccessType,
                                   const char* lpszProxy, const char* lpszProxyBypass,
                                   DWORD dwFlags)
{
    if (g_config.proxy_count == 0) {
        ipc_client_log(PF_LOG_DEBUG,
            "InternetOpenA: no proxies configured, passing through");
        return Original_InternetOpenA(lpszAgent, dwAccessType,
                                       lpszProxy, lpszProxyBypass, dwFlags);
    }

    std::string proxy_str = build_wininet_proxy_string();
    if (proxy_str.empty()) {
        return Original_InternetOpenA(lpszAgent, dwAccessType,
                                       lpszProxy, lpszProxyBypass, dwFlags);
    }

    ipc_client_log(PF_LOG_INFO,
        "InternetOpenA: overriding proxy to %s",
        proxy_str.c_str());

    return Original_InternetOpenA(lpszAgent,
                                   PF_INTERNET_OPEN_TYPE_PROXY,
                                   proxy_str.c_str(),
                                   NULL,  /* No bypass - proxy everything */
                                   dwFlags);
}

} // namespace proxyfire

#endif /* _WIN32 */

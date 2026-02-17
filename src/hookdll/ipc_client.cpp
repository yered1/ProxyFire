/*
 * ProxyFire - ipc_client.cpp
 * Named pipe IPC client
 */

#include "ipc_client.h"
#include "ipc_messages.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <windows.h>

namespace proxyfire {

static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_pipe_cs;
static bool g_cs_initialized = false;

bool ipc_client_init() {
    if (!g_cs_initialized) {
        InitializeCriticalSection(&g_pipe_cs);
        g_cs_initialized = true;
    }

    /* Read pipe name from environment */
    wchar_t pipe_name[512] = {};
    DWORD len = GetEnvironmentVariableW(PROXYFIRE_ENV_PIPE, pipe_name, 512);
    if (len == 0 || len >= 512) {
        return false;
    }

    /* Connect to the launcher's named pipe */
    g_pipe = CreateFileW(
        pipe_name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (g_pipe == INVALID_HANDLE_VALUE) {
        /* Retry once after a short delay */
        Sleep(100);
        g_pipe = CreateFileW(
            pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
    }

    if (g_pipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    /* Set pipe to message read mode to match the server's PIPE_TYPE_MESSAGE.
     * In message mode each ReadFile returns exactly one complete message
     * (or ERROR_MORE_DATA if the buffer is smaller than the message). */
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(g_pipe, &mode, NULL, NULL);

    return true;
}

static bool pipe_send(const void* data, uint32_t len) {
    if (g_pipe == INVALID_HANDLE_VALUE) return false;

    EnterCriticalSection(&g_pipe_cs);

    DWORD written = 0;
    BOOL ok = WriteFile(g_pipe, data, len, &written, NULL);

    LeaveCriticalSection(&g_pipe_cs);

    return ok && written == len;
}

static bool pipe_recv(void* buf, uint32_t len) {
    if (g_pipe == INVALID_HANDLE_VALUE) return false;

    char* ptr = (char*)buf;
    uint32_t remaining = len;

    while (remaining > 0) {
        DWORD read_bytes = 0;
        BOOL ok = ReadFile(g_pipe, ptr, remaining, &read_bytes, NULL);
        if (!ok) {
            /*
             * In PIPE_READMODE_MESSAGE mode, if our buffer is smaller
             * than the full message, ReadFile returns FALSE with
             * ERROR_MORE_DATA.  The bytes that fit are still placed in
             * the buffer and the remaining bytes can be read with
             * subsequent ReadFile calls.  This is the expected path
             * when we read the IpcHeader first and then read the
             * payload separately.
             */
            if (GetLastError() != ERROR_MORE_DATA || read_bytes == 0)
                return false;
        } else if (read_bytes == 0) {
            return false;
        }
        ptr += read_bytes;
        remaining -= read_bytes;
    }

    return true;
}

bool ipc_client_register(uint32_t pid, uint32_t tid) {
    auto msg = ipc_build_register(pid, tid);
    return pipe_send(msg.data(), (uint32_t)msg.size());
}

bool ipc_client_get_config(ProxyFireConfig* config) {
    if (!config) return false;

    /* Send config request */
    auto req = ipc_build_config_request();
    if (!pipe_send(req.data(), (uint32_t)req.size())) {
        return false;
    }

    /* Receive config response */
    IpcHeader header;
    if (!pipe_recv(&header, sizeof(header))) {
        return false;
    }

    if (header.magic != PROXYFIRE_IPC_MAGIC ||
        header.type != (uint32_t)IPC_CONFIG_RESPONSE) {
        return false;
    }

    if (header.payload_len != sizeof(ProxyFireConfig)) {
        return false;
    }

    if (!pipe_recv(config, sizeof(ProxyFireConfig))) {
        return false;
    }

    return true;
}

void ipc_client_log(ProxyFireLogLevel level, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    auto msg = ipc_build_log(level, GetCurrentProcessId(), buf);
    pipe_send(msg.data(), (uint32_t)msg.size());
}

bool ipc_client_notify_child(uint32_t child_pid, uint32_t child_tid) {
    auto msg = ipc_build_child_notify(child_pid, child_tid);
    return pipe_send(msg.data(), (uint32_t)msg.size());
}

bool ipc_client_dns_register(uint32_t fake_ip, const char* hostname) {
    auto msg = ipc_build_dns_register(fake_ip, hostname);
    return pipe_send(msg.data(), (uint32_t)msg.size());
}

bool ipc_client_connected() {
    return g_pipe != INVALID_HANDLE_VALUE;
}

void ipc_client_cleanup() {
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
    if (g_cs_initialized) {
        DeleteCriticalSection(&g_pipe_cs);
        g_cs_initialized = false;
    }
}

} // namespace proxyfire

#else
/* Non-Windows stub */
namespace proxyfire {
bool ipc_client_init() { return false; }
bool ipc_client_register(uint32_t, uint32_t) { return false; }
bool ipc_client_get_config(ProxyFireConfig*) { return false; }
void ipc_client_log(ProxyFireLogLevel, const char*, ...) {}
bool ipc_client_notify_child(uint32_t, uint32_t) { return false; }
bool ipc_client_dns_register(uint32_t, const char*) { return false; }
bool ipc_client_connected() { return false; }
void ipc_client_cleanup() {}
} // namespace proxyfire
#endif

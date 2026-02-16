/*
 * ProxyFire - ipc_server.cpp
 * Named pipe IPC server
 *
 * Creates a named pipe that hook DLLs connect to for:
 * - Configuration distribution
 * - Log message collection
 * - DNS table synchronization
 * - Child process notifications
 */

#include "ipc_server.h"
#include "ipc_messages.h"
#include "logger.h"
#include "string_utils.h"

#include <proxyfire/common.h>
#include <proxyfire/ipc_protocol.h>

#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

namespace proxyfire {

static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static const ProxyFireConfig* g_config = nullptr;
static LogCallback g_log_callback;
static volatile bool g_running = false;
static HANDLE g_stop_event = nullptr;
static std::wstring g_pipe_name;

std::wstring ipc_server_start(const ProxyFireConfig* config, LogCallback log_cb) {
    g_config = config;
    g_log_callback = log_cb;

    /* Generate unique pipe name */
    wchar_t name[256];
    swprintf(name, 256, L"%s%lu_%lu",
             PROXYFIRE_PIPE_PREFIX,
             GetCurrentProcessId(),
             GetTickCount());
    g_pipe_name = name;

    /* Create stop event */
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    /*
     * Create a security descriptor that restricts pipe access to the current
     * user and SYSTEM only. This prevents other users/processes from connecting
     * to steal proxy credentials or inject false configurations.
     */
    SECURITY_ATTRIBUTES sa = {};
    SECURITY_DESCRIPTOR sd = {};
    PSECURITY_DESCRIPTOR psd = nullptr;
    bool have_acl = false;

    /* Build a DACL string: Allow full access to Owner and SYSTEM only */
    /* D:P = DACL with PROTECTED flag
     * (A;;GA;;;OW) = Allow Generic All to Owner
     * (A;;GA;;;SY) = Allow Generic All to SYSTEM */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;OW)(A;;GA;;;SY)",
            SDDL_REVISION_1, &psd, nullptr)) {
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = psd;
        sa.bInheritHandle = FALSE;
        have_acl = true;
    } else {
        log_warn("Failed to create pipe ACL (error %lu), pipe will use default security",
                 GetLastError());
    }

    /* Create the named pipe */
    g_pipe = CreateNamedPipeW(
        g_pipe_name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        (DWORD)IPC_MAX_MSG_SIZE,
        (DWORD)IPC_MAX_MSG_SIZE,
        0,
        have_acl ? &sa : nullptr
    );

    if (psd) LocalFree(psd);

    if (g_pipe == INVALID_HANDLE_VALUE) {
        log_error("CreateNamedPipeW failed: %s",
                  format_win_error(GetLastError()).c_str());
        return L"";
    }

    g_running = true;
    log_debug("IPC server started on %ls", g_pipe_name.c_str());

    return g_pipe_name;
}

static void handle_message(const uint8_t* data, size_t len) {
    IpcHeader header;
    if (!ipc_parse_header(data, len, &header)) return;

    const uint8_t* payload = data + sizeof(IpcHeader);

    switch ((IpcMsgType)header.type) {
        case IPC_REGISTER_PROCESS: {
            if (header.payload_len >= sizeof(IpcRegisterProcess)) {
                const IpcRegisterProcess* reg = (const IpcRegisterProcess*)payload;
                log_debug("Hook DLL registered: PID %lu, TID %lu",
                         reg->pid, reg->tid);
            }
            break;
        }

        case IPC_CONFIG_REQUEST: {
            /* Send config back */
            if (g_config && g_pipe != INVALID_HANDLE_VALUE) {
                auto response = ipc_build_config_response(*g_config);
                DWORD written = 0;
                WriteFile(g_pipe, response.data(), (DWORD)response.size(),
                         &written, nullptr);
            }
            break;
        }

        case IPC_LOG_MESSAGE: {
            if (header.payload_len >= sizeof(IpcLogMessage)) {
                const IpcLogMessage* log_msg = (const IpcLogMessage*)payload;
                const char* msg_text = (const char*)(payload + sizeof(IpcLogMessage));
                size_t msg_max = header.payload_len - sizeof(IpcLogMessage);

                /* Ensure null-termination within bounds */
                if (msg_max == 0 || memchr(msg_text, '\0', msg_max) == nullptr) {
                    break;
                }

                if (g_log_callback) {
                    g_log_callback(log_msg->level, log_msg->pid, msg_text);
                }
            }
            break;
        }

        case IPC_CHILD_NOTIFY: {
            if (header.payload_len >= sizeof(IpcChildNotify)) {
                const IpcChildNotify* child = (const IpcChildNotify*)payload;
                log_info("Child process notification: PID %lu, TID %lu",
                        child->child_pid, child->child_tid);
            }
            break;
        }

        case IPC_DNS_REGISTER: {
            if (header.payload_len >= sizeof(IpcDnsRegister)) {
                const IpcDnsRegister* dns = (const IpcDnsRegister*)payload;
                const char* hostname = (const char*)(payload + sizeof(IpcDnsRegister));
                size_t hostname_max = header.payload_len - sizeof(IpcDnsRegister);

                /* Ensure null-termination within bounds */
                if (hostname_max == 0 || memchr(hostname, '\0', hostname_max) == nullptr) {
                    break;
                }

                log_debug("DNS mapping: %s -> fake IP %u.%u.%u.%u",
                         hostname,
                         (dns->fake_ip) & 0xFF,
                         (dns->fake_ip >> 8) & 0xFF,
                         (dns->fake_ip >> 16) & 0xFF,
                         (dns->fake_ip >> 24) & 0xFF);
            }
            break;
        }

        default:
            break;
    }
}

void ipc_server_run() {
    uint8_t buffer[IPC_MAX_MSG_SIZE];

    while (g_running) {
        /* Wait for a client to connect */
        OVERLAPPED ov = {};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        BOOL connected = ConnectNamedPipe(g_pipe, &ov);
        if (!connected) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                /* Wait for connection or stop event */
                HANDLE events[] = { ov.hEvent, g_stop_event };
                DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);

                if (wait != WAIT_OBJECT_0) {
                    /* Stop requested */
                    CancelIo(g_pipe);
                    CloseHandle(ov.hEvent);
                    break;
                }
            } else if (err != ERROR_PIPE_CONNECTED) {
                CloseHandle(ov.hEvent);
                Sleep(100);
                continue;
            }
        }

        CloseHandle(ov.hEvent);

        /* Client connected - read messages */
        while (g_running) {
            DWORD bytes_read = 0;
            BOOL ok = ReadFile(g_pipe, buffer, sizeof(buffer), &bytes_read, nullptr);

            if (!ok || bytes_read == 0) {
                break;  /* Client disconnected */
            }

            handle_message(buffer, bytes_read);
        }

        /* Disconnect and prepare for next client */
        DisconnectNamedPipe(g_pipe);

        /* Recreate pipe for next client with same ACL */
        CloseHandle(g_pipe);
        PSECURITY_DESCRIPTOR psd2 = nullptr;
        SECURITY_ATTRIBUTES sa2 = {};
        bool have_acl2 = false;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;OW)(A;;GA;;;SY)",
                SDDL_REVISION_1, &psd2, nullptr)) {
            sa2.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa2.lpSecurityDescriptor = psd2;
            sa2.bInheritHandle = FALSE;
            have_acl2 = true;
        }
        g_pipe = CreateNamedPipeW(
            g_pipe_name.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            (DWORD)IPC_MAX_MSG_SIZE,
            (DWORD)IPC_MAX_MSG_SIZE,
            0,
            have_acl2 ? &sa2 : nullptr
        );
        if (psd2) LocalFree(psd2);
    }
}

void ipc_server_stop() {
    g_running = false;
    if (g_stop_event) {
        SetEvent(g_stop_event);
    }
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
    if (g_stop_event) {
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
    }
}

bool ipc_server_has_clients() {
    return g_running;
}

} // namespace proxyfire

#else
/* Non-Windows stubs */
namespace proxyfire {
std::wstring ipc_server_start(const ProxyFireConfig*, LogCallback) { return L""; }
void ipc_server_run() {}
void ipc_server_stop() {}
bool ipc_server_has_clients() { return false; }
} // namespace proxyfire
#endif

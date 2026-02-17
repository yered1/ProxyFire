/*
 * ProxyFire - ipc_server.cpp
 * Named pipe IPC server
 *
 * Creates a named pipe that hook DLLs connect to for:
 * - Configuration distribution
 * - Log message collection
 * - DNS table synchronization
 * - Child process notifications
 *
 * The pipe uses MESSAGE mode so that each WriteFile from the client
 * creates a discrete message and each ReadFile returns exactly one
 * complete message.  This prevents coalescing of back-to-back writes
 * (e.g. registration + config request) into a single read that would
 * silently drop subsequent messages.
 *
 * The pipe is created with FILE_FLAG_OVERLAPPED so that blocking I/O
 * can be cancelled via the stop event.  ALL ReadFile/WriteFile calls
 * use a proper OVERLAPPED structure (passing NULL on an overlapped
 * handle is undefined behaviour per MSDN).
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

/* SDDL string for pipe ACL: owner + SYSTEM only */
static const wchar_t* PIPE_SDDL = L"D:P(A;;GA;;;OW)(A;;GA;;;SY)";

/*
 * Helper: create the named pipe with message mode, overlapped, and ACL.
 * Used both for initial creation and recreation after client disconnect.
 */
static HANDLE create_message_pipe() {
    PSECURITY_DESCRIPTOR psd = nullptr;
    SECURITY_ATTRIBUTES sa = {};
    bool have_acl = false;

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PIPE_SDDL, SDDL_REVISION_1, &psd, nullptr)) {
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = psd;
        sa.bInheritHandle = FALSE;
        have_acl = true;
    } else {
        log_warn("Failed to create pipe ACL (error %lu), using default security",
                 GetLastError());
    }

    HANDLE h = CreateNamedPipeW(
        g_pipe_name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        (DWORD)IPC_MAX_MSG_SIZE,
        (DWORD)IPC_MAX_MSG_SIZE,
        0,
        have_acl ? &sa : nullptr
    );

    if (psd) LocalFree(psd);
    return h;
}

/*
 * Helper: overlapped WriteFile on the pipe.
 * Handles ERROR_IO_PENDING and waits for completion with a timeout.
 */
static bool pipe_write_overlapped(const void* data, DWORD len) {
    if (g_pipe == INVALID_HANDLE_VALUE) return false;

    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return false;

    DWORD written = 0;
    BOOL ok = WriteFile(g_pipe, data, len, &written, &ov);

    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            /* Wait up to 5 seconds for the write to complete */
            if (WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0) {
                ok = GetOverlappedResult(g_pipe, &ov, &written, FALSE);
            }
        }
    }

    CloseHandle(ov.hEvent);
    return ok && written == len;
}

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

    g_pipe = create_message_pipe();

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
            /* Send config back using overlapped WriteFile */
            if (g_config && g_pipe != INVALID_HANDLE_VALUE) {
                auto response = ipc_build_config_response(*g_config);
                if (!pipe_write_overlapped(response.data(), (DWORD)response.size())) {
                    log_warn("Failed to send config response to hook DLL");
                }
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
        /* Wait for a client to connect (overlapped for cancellation) */
        OVERLAPPED ov_conn = {};
        ov_conn.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        BOOL connected = ConnectNamedPipe(g_pipe, &ov_conn);
        if (!connected) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                /* Wait for connection or stop event */
                HANDLE events[] = { ov_conn.hEvent, g_stop_event };
                DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);

                if (wait != WAIT_OBJECT_0) {
                    /* Stop requested */
                    CancelIo(g_pipe);
                    CloseHandle(ov_conn.hEvent);
                    break;
                }
            } else if (err != ERROR_PIPE_CONNECTED) {
                CloseHandle(ov_conn.hEvent);
                Sleep(100);
                continue;
            }
        }

        CloseHandle(ov_conn.hEvent);

        /*
         * Client connected - read messages using overlapped I/O.
         *
         * Each ReadFile returns exactly one complete IPC message because
         * the pipe is in MESSAGE mode.  The OVERLAPPED structure allows
         * us to wait on both the read completion and the stop event.
         */
        HANDLE hReadEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        while (g_running && hReadEvent) {
            OVERLAPPED ov_read = {};
            ov_read.hEvent = hReadEvent;
            ResetEvent(hReadEvent);

            DWORD bytes_read = 0;
            BOOL ok = ReadFile(g_pipe, buffer, sizeof(buffer), &bytes_read, &ov_read);

            if (!ok) {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING) {
                    /* Wait for data or stop event */
                    HANDLE events[] = { hReadEvent, g_stop_event };
                    DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);

                    if (wait != WAIT_OBJECT_0) {
                        CancelIo(g_pipe);
                        break;
                    }

                    ok = GetOverlappedResult(g_pipe, &ov_read, &bytes_read, FALSE);
                    if (!ok || bytes_read == 0) break;
                } else {
                    break;  /* Client disconnected or error */
                }
            }

            if (bytes_read == 0) break;

            handle_message(buffer, bytes_read);
        }

        if (hReadEvent) CloseHandle(hReadEvent);

        /* Disconnect and prepare for next client */
        DisconnectNamedPipe(g_pipe);

        /* Recreate pipe for next client */
        CloseHandle(g_pipe);
        g_pipe = create_message_pipe();
        if (g_pipe == INVALID_HANDLE_VALUE) {
            log_error("Failed to recreate pipe for next client");
            break;
        }
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

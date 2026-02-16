/*
 * ProxyFire - Transparent Proxy Wrapper for Windows
 *
 * ipc_protocol.h - IPC message definitions for launcher <-> hook DLL
 */

#pragma once

#include "common.h"
#include "config.h"

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

/* IPC message types */
typedef enum IpcMsgType {
    IPC_REGISTER_PROCESS  = 1,   /* DLL -> Launcher: "I am PID X" */
    IPC_CONFIG_REQUEST    = 2,   /* DLL -> Launcher: request full config */
    IPC_CONFIG_RESPONSE   = 3,   /* Launcher -> DLL: serialized config */
    IPC_LOG_MESSAGE       = 4,   /* DLL -> Launcher: log string */
    IPC_CHILD_NOTIFY      = 5,   /* DLL -> Launcher: "I spawned child PID Z" */
    IPC_SHUTDOWN          = 6,   /* Launcher -> DLL: prepare for teardown */
    IPC_HEARTBEAT         = 7,   /* Bidirectional: keepalive */
    IPC_DNS_REGISTER      = 8,   /* DLL -> Launcher: register hostname->fakeIP */
    IPC_DNS_LOOKUP        = 9,   /* DLL -> Launcher: lookup fakeIP->hostname */
    IPC_DNS_RESPONSE      = 10   /* Launcher -> DLL: hostname result */
} IpcMsgType;

#pragma pack(push, 1)

/* IPC message header */
typedef struct IpcHeader {
    uint32_t    magic;          /* PROXYFIRE_IPC_MAGIC */
    uint32_t    type;           /* IpcMsgType */
    uint32_t    payload_len;    /* Bytes following this header */
} IpcHeader;

/* IPC_REGISTER_PROCESS payload */
typedef struct IpcRegisterProcess {
    uint32_t    pid;
    uint32_t    tid;            /* Main thread ID */
} IpcRegisterProcess;

/* IPC_CONFIG_RESPONSE payload is a raw ProxyFireConfig struct */

/* IPC_LOG_MESSAGE payload */
typedef struct IpcLogMessage {
    uint8_t     level;          /* ProxyFireLogLevel */
    uint32_t    pid;
    /* Followed by null-terminated UTF-8 string */
} IpcLogMessage;

/* IPC_CHILD_NOTIFY payload */
typedef struct IpcChildNotify {
    uint32_t    child_pid;
    uint32_t    child_tid;
} IpcChildNotify;

/* IPC_DNS_REGISTER payload */
typedef struct IpcDnsRegister {
    uint32_t    fake_ip;        /* Network byte order */
    /* Followed by null-terminated hostname string */
} IpcDnsRegister;

/* IPC_DNS_LOOKUP payload */
typedef struct IpcDnsLookup {
    uint32_t    fake_ip;        /* Network byte order */
} IpcDnsLookup;

/* IPC_DNS_RESPONSE payload */
typedef struct IpcDnsResponse {
    uint32_t    fake_ip;        /* Network byte order */
    uint8_t     found;          /* 1 if hostname was found */
    /* Followed by null-terminated hostname string if found */
} IpcDnsResponse;

#pragma pack(pop)

/* Helper: total message size */
#define IPC_MSG_SIZE(payload_size) (sizeof(IpcHeader) + (payload_size))

/* Helper: max IPC message size (config can be large) */
#define IPC_MAX_MSG_SIZE (sizeof(IpcHeader) + sizeof(ProxyFireConfig) + 1024)

/*
 * ProxyFire - ipc_messages.cpp
 * IPC message serialization/deserialization
 */

#include "ipc_messages.h"
#include <cstring>

namespace proxyfire {

std::vector<uint8_t> ipc_build_message(IpcMsgType type, const void* payload, uint32_t payload_len) {
    std::vector<uint8_t> msg(sizeof(IpcHeader) + payload_len);

    IpcHeader header;
    header.magic = PROXYFIRE_IPC_MAGIC;
    header.type = (uint32_t)type;
    header.payload_len = payload_len;

    memcpy(msg.data(), &header, sizeof(IpcHeader));
    if (payload && payload_len > 0) {
        memcpy(msg.data() + sizeof(IpcHeader), payload, payload_len);
    }

    return msg;
}

std::vector<uint8_t> ipc_build_register(uint32_t pid, uint32_t tid) {
    IpcRegisterProcess payload;
    payload.pid = pid;
    payload.tid = tid;
    return ipc_build_message(IPC_REGISTER_PROCESS, &payload, sizeof(payload));
}

std::vector<uint8_t> ipc_build_config_request() {
    return ipc_build_message(IPC_CONFIG_REQUEST, nullptr, 0);
}

std::vector<uint8_t> ipc_build_config_response(const ProxyFireConfig& config) {
    return ipc_build_message(IPC_CONFIG_RESPONSE, &config, sizeof(ProxyFireConfig));
}

std::vector<uint8_t> ipc_build_log(ProxyFireLogLevel level, uint32_t pid, const char* message) {
    size_t msg_len = message ? strlen(message) : 0;
    size_t payload_len = sizeof(IpcLogMessage) + msg_len + 1;

    std::vector<uint8_t> payload_buf(payload_len, 0);
    IpcLogMessage* log_msg = (IpcLogMessage*)payload_buf.data();
    log_msg->level = (uint8_t)level;
    log_msg->pid = pid;
    if (message) {
        memcpy(payload_buf.data() + sizeof(IpcLogMessage), message, msg_len + 1);
    }

    return ipc_build_message(IPC_LOG_MESSAGE, payload_buf.data(), (uint32_t)payload_len);
}

std::vector<uint8_t> ipc_build_child_notify(uint32_t child_pid, uint32_t child_tid) {
    IpcChildNotify payload;
    payload.child_pid = child_pid;
    payload.child_tid = child_tid;
    return ipc_build_message(IPC_CHILD_NOTIFY, &payload, sizeof(payload));
}

std::vector<uint8_t> ipc_build_dns_register(uint32_t fake_ip, const char* hostname) {
    size_t host_len = hostname ? strlen(hostname) : 0;
    size_t payload_len = sizeof(IpcDnsRegister) + host_len + 1;

    std::vector<uint8_t> payload_buf(payload_len, 0);
    IpcDnsRegister* dns = (IpcDnsRegister*)payload_buf.data();
    dns->fake_ip = fake_ip;
    if (hostname) {
        memcpy(payload_buf.data() + sizeof(IpcDnsRegister), hostname, host_len + 1);
    }

    return ipc_build_message(IPC_DNS_REGISTER, payload_buf.data(), (uint32_t)payload_len);
}

std::vector<uint8_t> ipc_build_dns_lookup(uint32_t fake_ip) {
    IpcDnsLookup payload;
    payload.fake_ip = fake_ip;
    return ipc_build_message(IPC_DNS_LOOKUP, &payload, sizeof(payload));
}

std::vector<uint8_t> ipc_build_dns_response(uint32_t fake_ip, bool found, const char* hostname) {
    size_t host_len = (found && hostname) ? strlen(hostname) : 0;
    size_t payload_len = sizeof(IpcDnsResponse) + host_len + 1;

    std::vector<uint8_t> payload_buf(payload_len, 0);
    IpcDnsResponse* resp = (IpcDnsResponse*)payload_buf.data();
    resp->fake_ip = fake_ip;
    resp->found = found ? 1 : 0;
    if (found && hostname) {
        memcpy(payload_buf.data() + sizeof(IpcDnsResponse), hostname, host_len + 1);
    }

    return ipc_build_message(IPC_DNS_RESPONSE, payload_buf.data(), (uint32_t)payload_len);
}

std::vector<uint8_t> ipc_build_shutdown() {
    return ipc_build_message(IPC_SHUTDOWN, nullptr, 0);
}

bool ipc_parse_header(const uint8_t* data, size_t len, IpcHeader* header) {
    if (!data || len < sizeof(IpcHeader) || !header) {
        return false;
    }

    memcpy(header, data, sizeof(IpcHeader));

    if (header->magic != PROXYFIRE_IPC_MAGIC) {
        return false;
    }

    return true;
}

bool ipc_validate_message(const uint8_t* data, size_t len) {
    IpcHeader header;
    if (!ipc_parse_header(data, len, &header)) {
        return false;
    }

    if (len < sizeof(IpcHeader) + header.payload_len) {
        return false;
    }

    if (header.type < IPC_REGISTER_PROCESS || header.type > IPC_DNS_RESPONSE) {
        return false;
    }

    return true;
}

} // namespace proxyfire

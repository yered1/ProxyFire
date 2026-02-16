/*
 * ProxyFire - ipc_messages.h
 * IPC message serialization/deserialization helpers
 */

#pragma once

#include <proxyfire/ipc_protocol.h>
#include <proxyfire/config.h>
#include <vector>
#include <string>
#include <cstdint>

namespace proxyfire {

/* Serialize a message with header + payload into a byte buffer */
std::vector<uint8_t> ipc_build_message(IpcMsgType type, const void* payload, uint32_t payload_len);

/* Build a REGISTER_PROCESS message */
std::vector<uint8_t> ipc_build_register(uint32_t pid, uint32_t tid);

/* Build a CONFIG_REQUEST message (no payload) */
std::vector<uint8_t> ipc_build_config_request();

/* Build a CONFIG_RESPONSE message */
std::vector<uint8_t> ipc_build_config_response(const ProxyFireConfig& config);

/* Build a LOG_MESSAGE */
std::vector<uint8_t> ipc_build_log(ProxyFireLogLevel level, uint32_t pid, const char* message);

/* Build a CHILD_NOTIFY message */
std::vector<uint8_t> ipc_build_child_notify(uint32_t child_pid, uint32_t child_tid);

/* Build a DNS_REGISTER message */
std::vector<uint8_t> ipc_build_dns_register(uint32_t fake_ip, const char* hostname);

/* Build a DNS_LOOKUP message */
std::vector<uint8_t> ipc_build_dns_lookup(uint32_t fake_ip);

/* Build a DNS_RESPONSE message */
std::vector<uint8_t> ipc_build_dns_response(uint32_t fake_ip, bool found, const char* hostname);

/* Build a SHUTDOWN message */
std::vector<uint8_t> ipc_build_shutdown();

/* Parse a message header from raw bytes. Returns false if invalid. */
bool ipc_parse_header(const uint8_t* data, size_t len, IpcHeader* header);

/* Validate magic and bounds */
bool ipc_validate_message(const uint8_t* data, size_t len);

} // namespace proxyfire

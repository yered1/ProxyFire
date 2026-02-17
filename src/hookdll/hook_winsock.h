/*
 * ProxyFire - hook_winsock.h
 * Hooked Winsock2 connection functions
 */

#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

namespace proxyfire {

/* Hooked function declarations */
int WSAAPI Hooked_connect(SOCKET s, const struct sockaddr* name, int namelen);
int WSAAPI Hooked_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen,
                              LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                              LPQOS lpSQOS, LPQOS lpGQOS);
int WSAAPI Hooked_closesocket(SOCKET s);
int WSAAPI Hooked_WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer,
                            DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
                            LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped,
                            LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

/* Internal ConnectEx hook (installed dynamically via WSAIoctl interception) */
BOOL PASCAL Hooked_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen,
                              PVOID lpSendBuffer, DWORD dwSendDataLength,
                              LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);

/* WSAConnectByName - connects by hostname, bypasses DNS hooks */
BOOL WSAAPI Hooked_WSAConnectByNameW(SOCKET s, LPWSTR nodename, LPWSTR servicename,
                                      LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
                                      LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
                                      const struct timeval* timeout, LPWSAOVERLAPPED Reserved);
BOOL WSAAPI Hooked_WSAConnectByNameA(SOCKET s, LPCSTR nodename, LPCSTR servicename,
                                      LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
                                      LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
                                      const struct timeval* timeout, LPWSAOVERLAPPED Reserved);

/*
 * Pre-resolve the ConnectEx extension function pointer BEFORE hooks are
 * installed.  This avoids the need to call Original_WSAIoctl (trampoline)
 * at runtime, which can crash if the trampoline mis-relocates an
 * instruction in WSAIoctl's prologue.
 *
 * Must be called after MH_Initialize() but before install_all_hooks().
 */
void pre_resolve_connectex();

/* Get/set the real ConnectEx pointer (used by hook_installer for direct hook) */
LPFN_CONNECTEX get_real_connectex();
void set_real_connectex(LPFN_CONNECTEX fn);

/* Original function pointers - must be accessible from proxy_chain.cpp */
extern int (WSAAPI *Original_connect)(SOCKET, const struct sockaddr*, int);

} // namespace proxyfire

#endif

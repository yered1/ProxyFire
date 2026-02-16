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

} // namespace proxyfire

/* Original function pointers - must be accessible from proxy_chain.cpp */
extern int (WSAAPI *Original_connect)(SOCKET, const struct sockaddr*, int);

#endif

# ProxyFire

**Transparent proxy wrapper for Windows.** Forces any application's network traffic through a defined proxy server, supporting SOCKS5, SOCKS4/4a, and HTTP CONNECT proxies.

```
proxyfire --proxy socks5://user:pass@1.2.3.4:1080 -- curl.exe https://example.com
```

ProxyFire works with **any Windows executable** - GUI or CLI, regardless of the programming language it was built with. It operates at the Winsock2, WinHTTP, and WinINet layers, intercepting all TCP connections before they leave the process.

## Features

- **Multiple proxy protocols**: SOCKS5 (with username/password auth), SOCKS4, SOCKS4a, HTTP CONNECT
- **Proxy chaining**: Route through multiple proxies in sequence (multi-hop)
- **TCP and UDP proxying**: Full TCP proxying through all protocols; UDP proxying via SOCKS5 UDP ASSOCIATE (RFC 1928)
- **DNS leak prevention**: Intercepts all DNS queries (Winsock, async, and raw UDP port 53) and resolves remotely through the proxy
- **Full API coverage**: Hooks 22 functions across Winsock2, WinHTTP, and WinINet
- **IPv6 support**: Full IPv6 proxying through SOCKS5 (ATYP IPv6) and HTTP CONNECT (bracket notation)
- **UAC auto-elevation**: Automatically detects and re-launches with elevated privileges when targeting processes that require admin rights
- **Child process injection**: Optionally inject into spawned child processes
- **Works with any EXE**: GUI apps, CLI tools, .NET, Java, Python, Electron, native - all work
- **x86 and x64 support**: Automatically detects target architecture
- **Configuration file**: TOML-based config for persistent settings
- **Connection logging**: Verbose logging of all proxied connections
- **Bypass rules**: Exclude specific IP ranges from proxying (LAN, localhost, multicast, etc.)
- **Secure IPC**: Named pipe communication with ACL-restricted access (owner + SYSTEM only)
- **No system-wide changes**: Only affects the target process (and optionally its children)

## How It Works

ProxyFire uses **DLL injection** and **API hooking** to transparently redirect network connections:

1. **Launch**: Creates the target process in a suspended state
2. **Inject**: Loads `proxyfire_hook.dll` into the target process using `CreateRemoteThread` + `LoadLibraryW`
3. **Hook**: Uses [MinHook](https://github.com/TsudaKageyu/minhook) to install inline hooks on Winsock2, WinHTTP, WinINet, and DNS functions
4. **Intercept**: When the application calls `connect()`, `WinHttpOpen()`, `InternetOpen()`, etc., the hooks redirect through the configured proxy
5. **Resume**: The target process runs normally, unaware that its traffic is being proxied

## Installation

### Building from Source

Requirements:
- CMake 3.15+
- Visual Studio 2019+ (MSVC) or MinGW-w64
- Windows SDK

```bash
# Clone
git clone https://github.com/yered1/ProxyFire.git
cd ProxyFire

# Build x64
cmake -B build_x64 -A x64
cmake --build build_x64 --config Release

# Build x86 (for 32-bit targets)
cmake -B build_x86 -A Win32
cmake --build build_x86 --config Release
```

Output files:
```
build_x64/src/launcher/Release/proxyfire.exe
build_x64/src/hookdll/Release/proxyfire_hook64.dll
build_x86/src/hookdll/Release/proxyfire_hook32.dll
```

Copy `proxyfire.exe`, `proxyfire_hook64.dll`, and `proxyfire_hook32.dll` to the same directory.

## Usage

### Basic Usage

```bash
# Route through a SOCKS5 proxy
proxyfire --proxy socks5://proxy-server:1080 -- myapp.exe --arg1 --arg2

# SOCKS5 with authentication
proxyfire --proxy socks5://user:pass@proxy-server:1080 -- firefox.exe

# HTTP CONNECT proxy
proxyfire --proxy http://proxy-server:8080 -- curl.exe https://example.com

# HTTPS proxy (same as HTTP - uses HTTP CONNECT method)
proxyfire --proxy https://proxy-server:8080 -- curl.exe https://example.com

# SOCKS4a proxy
proxyfire --proxy socks4a://proxy-server:1080 -- wget.exe https://example.com
```

### Proxy Chaining

```bash
# Chain through two proxies: traffic goes App -> P1 -> P2 -> Destination
proxyfire --proxy socks5://first:1080 --proxy socks5://second:1080 -- app.exe
```

### Advanced Options

```bash
# Verbose logging
proxyfire -v --proxy socks5://proxy:1080 -- app.exe

# Also inject into child processes
proxyfire --inject-children --proxy socks5://proxy:1080 -- app.exe

# Disable DNS leak prevention (use local DNS instead of remote)
proxyfire --allow-dns-leak --proxy socks5://proxy:1080 -- app.exe

# Custom timeout and log file
proxyfire --timeout 60000 --log-file proxy.log --proxy socks5://proxy:1080 -- app.exe

# Use a config file
proxyfire --config proxyfire.toml -- app.exe
```

### Configuration File

Create a `proxyfire.toml` file (see `proxyfire.toml.example`):

```toml
[general]
verbose = false
dns_leak_prevention = true
inject_children = false
log_level = "info"
timeout = 30000

[[proxy]]
uri = "socks5://user:pass@proxy-server:1080"

[bypass]
rules = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
```

### Command Line Reference

```
Usage: proxyfire [options] -- <target.exe> [target args...]

Options:
  --proxy <uri>         Proxy URI (repeatable for chaining)
  --config <file>       Load configuration from TOML file
  --verbose, -v         Enable verbose logging
  --quiet, -q           Suppress all output except errors
  --log-file <file>     Write logs to file
  --log-level <level>   Log level: trace, debug, info, warn, error
  --no-dns-leak         Enable DNS leak prevention (default)
  --allow-dns-leak      Disable DNS leak prevention (allows local DNS,
                        direct IPv6, and UDP DNS queries)
  --inject-children     Also inject into child processes
  --timeout <ms>        Proxy connection timeout in milliseconds
  --help, -h            Show help message
  --version             Show version information

Proxy URI formats:
  socks5://[user:pass@]host:port
  socks4://host:port
  socks4a://host:port
  http://[user:pass@]host:port
  https://[user:pass@]host:port    (same as http://, uses CONNECT method)
```

## Architecture

```
+-----------------------------------------------------+
|  proxyfire.exe (Launcher)                            |
|  +-------------+  +----------+  +---------------+   |
|  | CLI Parser   |  | Injector |  | IPC Server    |   |
|  | Config Loader|  |          |  | (Named Pipe)  |   |
|  +-------------+  +----------+  +---------------+   |
+---------------+-------------------------+------------+
                | DLL Injection           | IPC
                | (CreateRemoteThread)    | Messages
                v                         v
+-----------------------------------------------------+
|  Target Process (e.g., curl.exe)                     |
|  +---------------------------------------------+    |
|  |  proxyfire_hook64.dll (Injected)             |    |
|  |  +----------+ +----------+ +------------+    |    |
|  |  | Winsock  | | DNS      | | WinHTTP/   |    |    |
|  |  | Hooks    | | Hooks    | | WinINet    |    |    |
|  |  | connect  | | getaddr  | | Hooks      |    |    |
|  |  | WSAConn  | | info()   | |            |    |    |
|  |  | ConnectEx| | ExW()    | | InternetOp |    |    |
|  |  | ByName() | | sendto() | | WinHttpOp  |    |    |
|  |  | UDP relay| | recvfrom | |            |    |    |
|  |  +----+-----+ +----+-----+ +-----+------+    |    |
|  |       |             |             |           |    |
|  |  +----v-------------v-------------v-------+   |    |
|  |  |  Proxy Chain Connector                 |   |    |
|  |  |  TCP: SOCKS5 / SOCKS4 / HTTP CONNECT  |   |    |
|  |  |  UDP: SOCKS5 UDP ASSOCIATE relay       |   |    |
|  |  +-------------------+--------------------+   |    |
|  +------------------------------+----------------+    |
|                                 |                     |
+-----------------------------------------------------+
                          |
                          v
                   +--------------+
                   | Proxy Server |
                   | (SOCKS5/HTTP)|
                   +------+-------+
                          |
                          v
                   +--------------+
                   | Destination  |
                   | Server       |
                   +--------------+
```

### Hooked Functions

| Function | Module | Purpose |
|----------|--------|---------|
| `connect()` | ws2_32.dll | Intercept all outgoing TCP connections |
| `WSAConnect()` | ws2_32.dll | Extended connect with QOS support |
| `ConnectEx()` | ws2_32.dll | Async connect (via WSAIoctl interception) |
| `WSAConnectByNameW/A()` | ws2_32.dll | Connect by hostname (bypasses DNS+connect) |
| `WSAIoctl()` | ws2_32.dll | Intercept ConnectEx function pointer requests |
| `closesocket()` | ws2_32.dll | Track socket lifecycle |
| `sendto()` | ws2_32.dll | SOCKS5 UDP relay / DNS leak prevention |
| `WSASendTo()` | ws2_32.dll | SOCKS5 UDP relay (scatter/gather) / DNS leak prevention |
| `recvfrom()` | ws2_32.dll | SOCKS5 UDP relay receive |
| `WSARecvFrom()` | ws2_32.dll | SOCKS5 UDP relay receive (scatter/gather) |
| `getaddrinfo()` | ws2_32.dll | DNS leak prevention (returns fake IPs) |
| `GetAddrInfoW()` | ws2_32.dll | Wide-string DNS leak prevention |
| `GetAddrInfoExW()` | ws2_32.dll | Async DNS leak prevention (.NET, UWP) |
| `gethostbyname()` | ws2_32.dll | Legacy DNS leak prevention |
| `WinHttpOpen()` | winhttp.dll | Force WinHTTP proxy settings |
| `WinHttpSetOption()` | winhttp.dll | Block WinHTTP proxy overrides |
| `InternetOpenW()` | wininet.dll | Force WinINet proxy settings (wide) |
| `InternetOpenA()` | wininet.dll | Force WinINet proxy settings (ANSI) |
| `CreateProcessW()` | kernel32.dll | Child process injection |
| `CreateProcessA()` | kernel32.dll | Child process injection |

### DNS Leak Prevention

When DNS leak prevention is enabled (default), ProxyFire uses a multi-layer approach:

1. **DNS API Hooks**: Intercepts `getaddrinfo`, `GetAddrInfoW`, `GetAddrInfoExW`, and `gethostbyname` - returns "fake" IP addresses from the reserved `240.0.0.0/4` range. When `connect()` sees a fake IP, it passes the original hostname to the SOCKS5 proxy for remote DNS resolution.

2. **UDP DNS Handling**: When using a SOCKS5 proxy, DNS queries sent via raw UDP are relayed through the proxy using UDP ASSOCIATE. For non-SOCKS5 proxies, `sendto()` and `WSASendTo()` hooks block UDP packets to port 53.

3. **WinHTTP/WinINet Proxy**: Forces higher-level HTTP APIs to use the configured proxy, which handles DNS resolution on the proxy side.

### Automatic Bypass Rules

The following address ranges are automatically bypassed (never proxied):
- `127.0.0.0/8` - Loopback
- `0.0.0.0` - Bind address
- `169.254.0.0/16` - Link-local
- `224.0.0.0/4` - Multicast
- `255.255.255.255` - Broadcast
- Proxy server addresses themselves (prevents routing loops)
- User-defined CIDR rules via config

## Security

- **IPC Pipe ACL**: The named pipe used for launcher-DLL communication is protected with a Windows ACL that only allows access by the pipe owner and SYSTEM. Other users cannot read proxy credentials.
- **Credential Handling**: Proxy passwords are securely cleared from memory after use in HTTP CONNECT `Proxy-Authorization` headers using `SecureZeroMemory`.
- **Config File**: If using a configuration file with proxy credentials, ensure the file permissions are restricted (owner-only access recommended).

## Limitations

- **Windows only**: Requires Windows 7+ (x86 or x64). WinHTTP SOCKS proxy requires Windows 8.1+.
- **UDP proxying requires SOCKS5**: Full UDP relay is only available when the first proxy in the chain is SOCKS5 (via UDP ASSOCIATE). Non-SOCKS5 proxies only block DNS UDP.
- **Overlapped UDP**: Asynchronous/overlapped UDP I/O (`WSASendTo`/`WSARecvFrom` with `LPOVERLAPPED`) falls back to direct send when relay is active. Synchronous and non-overlapped calls are fully relayed.
- **Proxy timeout**: If the proxy server is unreachable, connections may hang for up to the configured timeout (default 30 seconds) before failing. For GUI apps, this may cause a brief "Not Responding" state.
- **Anti-cheat software**: Some applications with anti-tampering may detect the hook DLL.
- **Raw sockets**: Applications using `SOCK_RAW` bypass all hooks. This is uncommon for normal applications.
- **DLL search path**: Ensure `proxyfire_hook64.dll` / `proxyfire_hook32.dll` are in the same directory as `proxyfire.exe`.

## License

MIT License. See [LICENSE](LICENSE) for details.

MinHook is included under the BSD 2-Clause License. See `third_party/minhook/` for details.

## Credits

- [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu - Inline API hooking library
- Inspired by [Proxifier](https://www.proxifier.com/), [proxychains-ng](https://github.com/rofl0r/proxychains-ng), and [proxychains-windows](https://github.com/shunf4/proxychains-windows)

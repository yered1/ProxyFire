# ProxyFire

**Transparent proxy wrapper for Windows.** Forces any application's network traffic through a defined proxy server, supporting SOCKS5, SOCKS4/4a, and HTTP CONNECT proxies.

```
proxyfire --proxy socks5://user:pass@1.2.3.4:1080 -- curl.exe https://example.com
```

ProxyFire works with **any Windows executable** - GUI or CLI, regardless of the programming language it was built with. It operates at the Winsock2 layer, intercepting all TCP connections before they leave the process.

## Features

- **Multiple proxy protocols**: SOCKS5 (with username/password auth), SOCKS4, SOCKS4a, HTTP CONNECT
- **Proxy chaining**: Route through multiple proxies in sequence (multi-hop)
- **DNS leak prevention**: Intercepts DNS queries and resolves remotely through the proxy
- **Child process injection**: Optionally inject into spawned child processes
- **Works with any EXE**: GUI apps, CLI tools, .NET, Java, Python, Electron, native - all work
- **x86 and x64 support**: Automatically detects target architecture
- **Configuration file**: TOML-based config for persistent settings
- **Connection logging**: Verbose logging of all proxied connections
- **Bypass rules**: Exclude specific IP ranges from proxying (LAN, localhost, etc.)
- **No system-wide changes**: Only affects the target process (and optionally its children)

## How It Works

ProxyFire uses **DLL injection** and **Winsock2 API hooking** to transparently redirect network connections:

1. **Launch**: Creates the target process in a suspended state
2. **Inject**: Loads `proxyfire_hook.dll` into the target process using `CreateRemoteThread` + `LoadLibraryW`
3. **Hook**: Uses [MinHook](https://github.com/TsudaKageyu/minhook) to install inline hooks on Winsock2 functions (`connect`, `WSAConnect`, `getaddrinfo`, `gethostbyname`, etc.)
4. **Intercept**: When the application calls `connect()`, the hook redirects the connection through the configured proxy chain
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
  --allow-dns-leak      Disable DNS leak prevention
  --inject-children     Also inject into child processes
  --timeout <ms>        Proxy connection timeout in milliseconds
  --help, -h            Show help message
  --version             Show version information

Proxy URI formats:
  socks5://[user:pass@]host:port
  socks4://host:port
  socks4a://host:port
  http://[user:pass@]host:port
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  proxyfire.exe (Launcher)                           │
│  ┌─────────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ CLI Parser   │  │ Injector │  │ IPC Server    │  │
│  │ Config Loader│  │          │  │ (Named Pipe)  │  │
│  └─────────────┘  └──────────┘  └───────────────┘  │
└───────────────┬─────────────────────────┬───────────┘
                │ DLL Injection           │ IPC
                │ (CreateRemoteThread)    │ Messages
                ▼                         ▼
┌─────────────────────────────────────────────────────┐
│  Target Process (e.g., curl.exe)                    │
│  ┌─────────────────────────────────────────────┐    │
│  │  proxyfire_hook64.dll (Injected)            │    │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────┐  │    │
│  │  │ Winsock  │ │ DNS      │ │ Process    │  │    │
│  │  │ Hooks    │ │ Hooks    │ │ Hooks      │  │    │
│  │  │ connect()│ │ getaddr  │ │ CreateProc │  │    │
│  │  │ WSAConn()│ │ info()   │ │ ess()      │  │    │
│  │  └────┬─────┘ └────┬─────┘ └────────────┘  │    │
│  │       │             │                        │    │
│  │  ┌────▼─────────────▼────────────────────┐  │    │
│  │  │  Proxy Chain Connector                │  │    │
│  │  │  SOCKS5 / SOCKS4 / HTTP CONNECT      │  │    │
│  │  └───────────────────┬───────────────────┘  │    │
│  └──────────────────────┼──────────────────────┘    │
│                         │                           │
└─────────────────────────┼───────────────────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │ Proxy Server │
                   │ (SOCKS5/HTTP)│
                   └──────┬───────┘
                          │
                          ▼
                   ┌──────────────┐
                   │ Destination  │
                   │ Server       │
                   └──────────────┘
```

### Hooked Functions

| Function | Module | Purpose |
|----------|--------|---------|
| `connect()` | ws2_32.dll | Intercept all outgoing TCP connections |
| `WSAConnect()` | ws2_32.dll | Extended connect with QOS support |
| `closesocket()` | ws2_32.dll | Track socket lifecycle |
| `getaddrinfo()` | ws2_32.dll | DNS leak prevention (returns fake IPs) |
| `GetAddrInfoW()` | ws2_32.dll | Wide-string DNS leak prevention |
| `gethostbyname()` | ws2_32.dll | Legacy DNS leak prevention |
| `CreateProcessW()` | kernel32.dll | Child process injection |
| `CreateProcessA()` | kernel32.dll | Child process injection |

### DNS Leak Prevention

When DNS leak prevention is enabled (default), ProxyFire intercepts all DNS resolution calls and returns "fake" IP addresses from the reserved `240.0.0.0/4` range. When `connect()` sees a fake IP, it passes the original hostname to the SOCKS5 proxy for remote DNS resolution. This means DNS queries never leave the proxy tunnel.

## Limitations

- **TCP only**: UDP traffic is not currently proxied (SOCKS5 UDP ASSOCIATE support is planned)
- **Windows only**: Requires Windows 7+ (x86 or x64)
- **Admin rights**: May be required for some target processes
- **Anti-cheat software**: Some applications with anti-tampering may detect the hook DLL
- **IPv6**: Currently passes through without proxying (IPv4 is fully supported)

## License

MIT License. See [LICENSE](LICENSE) for details.

MinHook is included under the BSD 2-Clause License. See `third_party/minhook/` for details.

## Credits

- [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu - Inline API hooking library
- Inspired by [Proxifier](https://www.proxifier.com/), [proxychains-ng](https://github.com/rofl0r/proxychains-ng), and [proxychains-windows](https://github.com/shunf4/proxychains-windows)

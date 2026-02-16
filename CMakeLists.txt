cmake_minimum_required(VERSION 3.15)
project(ProxyFire VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Detect architecture for DLL naming
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PROXYFIRE_ARCH "x64")
    set(PROXYFIRE_ARCH_SUFFIX "64")
else()
    set(PROXYFIRE_ARCH "x86")
    set(PROXYFIRE_ARCH_SUFFIX "32")
endif()

message(STATUS "ProxyFire: Building for ${PROXYFIRE_ARCH}")

# Global compile definitions
add_compile_definitions(
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
    UNICODE
    _UNICODE
    PROXYFIRE_VERSION="${PROJECT_VERSION}"
    PROXYFIRE_ARCH="${PROXYFIRE_ARCH}"
    PROXYFIRE_ARCH_SUFFIX="${PROXYFIRE_ARCH_SUFFIX}"
)

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX- /MP /Zi)
    add_link_options(/DEBUG)
else()
    # MinGW / GCC
    add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

# Third-party
add_subdirectory(third_party/minhook)

# Our libraries
add_subdirectory(src/common)
add_subdirectory(src/hookdll)
add_subdirectory(src/launcher)

add_library(proxyfire_hook SHARED
    dllmain.cpp
    hook_installer.cpp
    hook_winsock.cpp
    hook_dns.cpp
    hook_process.cpp
    proxy_connector.cpp
    proxy_chain.cpp
    ipc_client.cpp
    socket_context.cpp
    dns_faker.cpp
)

set_target_properties(proxyfire_hook PROPERTIES
    OUTPUT_NAME "proxyfire_hook${PROXYFIRE_ARCH_SUFFIX}"
)

target_include_directories(proxyfire_hook PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/common
    ${PROJECT_SOURCE_DIR}/third_party/minhook/include
)

target_link_libraries(proxyfire_hook PRIVATE
    minhook
    proxyfire_common
)

if(WIN32)
    target_link_libraries(proxyfire_hook PRIVATE ws2_32 shlwapi)
endif()

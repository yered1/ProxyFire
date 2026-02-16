add_library(proxyfire_common STATIC
    proxy_uri.cpp
    string_utils.cpp
    ipc_messages.cpp
)

target_include_directories(proxyfire_common PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(proxyfire_common PUBLIC ws2_32)
endif()

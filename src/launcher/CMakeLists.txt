add_executable(proxyfire
    main.cpp
    cli_parser.cpp
    config_loader.cpp
    process_launcher.cpp
    injector.cpp
    ipc_server.cpp
    logger.cpp
)

target_include_directories(proxyfire PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/common
)

target_link_libraries(proxyfire PRIVATE
    proxyfire_common
)

if(WIN32)
    target_link_libraries(proxyfire PRIVATE ws2_32 shlwapi)
endif()

cmake_minimum_required(VERSION 3.15)

add_library(minhook STATIC
    src/buffer.c
    src/hook.c
    src/trampoline.c
    src/hde/hde32.c
    src/hde/hde64.c
)

target_include_directories(minhook PUBLIC include)

# Disable warnings for third-party code
if(MSVC)
    target_compile_options(minhook PRIVATE /W0)
else()
    target_compile_options(minhook PRIVATE -w)
endif()

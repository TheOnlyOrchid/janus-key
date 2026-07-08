cmake_minimum_required(VERSION 3.24)
project(janus_key LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR
            "Intel Pins windows kit is not compatible with MinGW GCC. "
            "Configure this project with clang-cl or MSVC instead.")
endif ()

set(PIN_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pin)
set(PIN_ARCH intel64)

add_library(janus_key_pintool SHARED
        src/main.cpp
)

set_target_properties(janus_key_pintool PROPERTIES
        PREFIX ""
)

target_include_directories(janus_key_pintool PRIVATE
        ${PIN_ROOT}/source/include/pin
        ${PIN_ROOT}/source/include/pin/gen
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/include/adaptor
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/include/c++
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/include
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/include/pinos
        ${PIN_ROOT}/extras/xed-${PIN_ARCH}/include/xed
        ${PIN_ROOT}/extras/components/include
)

target_compile_definitions(janus_key_pintool PRIVATE
        TARGET_IA32E
        HOST_IA32E
        TARGET_WINDOWS
        PIN_CRT=1
        PIN_RT=1
        __x86_64__
        _GNU_SOURCE
        _XOPEN_SOURCE=700
        _POSIX_C_SOURCE=200809L
        _LIBCPP_DISABLE_AVAILABILITY
        _LIBCPP_NO_VCRUNTIME
        _LIBCPP_HAS_MUSL_LIBC
)

target_compile_options(janus_key_pintool PRIVATE
        "-D_arch_long=long long"
)

target_link_libraries(janus_key_pintool PRIVATE
        ${PIN_ROOT}/${PIN_ARCH}/lib/pin.lib
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/lib/pinrt-adaptor-static.lib
        ${PIN_ROOT}/extras/xed-${PIN_ARCH}/lib/xed.lib
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/lib/c++.lib
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/lib/pincrt4.lib
        kernel32.lib
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/lib/crtbeginS.obj
        ${PIN_ROOT}/${PIN_ARCH}/pinrt/lib/stdlib_new_delete.obj
)

# Intel PIN stuff apparently
if (MSVC)
    target_compile_options(janus_key_pintool PRIVATE
            /GR- /GS- /EHs- /EHa- /Oi- /Zc:threadSafeInit-
            -nostdinc
            -Wno-non-c-typedef-for-linkage
    )
    target_link_options(janus_key_pintool PRIVATE
            /export:main
            /NODEFAULTLIB
            /FORCE:MULTIPLE
            /INCREMENTAL:NO
            /MANIFEST:NO
    )
endif ()

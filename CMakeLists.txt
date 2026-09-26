cmake_minimum_required(VERSION 3.24)
project(janus_key LANGUAGES C CXX)

option(BUILD_TESTING "Build the unified test suite" ON)
if (BUILD_TESTING)
    enable_testing()
endif ()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif ()

if (WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR
            "Intel Pins windows kit is not compatible with MinGW GCC. "
            "Configure this project with clang-cl or MSVC instead.")
endif ()

set(PIN_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pin)
set(PIN_ARCH intel64)

if (WIN32)
    set(IMGUI_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui)
    add_executable(janus_key_gui WIN32
            src/gui/main.cpp
            src/gui/session.cpp
            ${IMGUI_ROOT}/imgui.cpp
            ${IMGUI_ROOT}/imgui_draw.cpp
            ${IMGUI_ROOT}/imgui_tables.cpp
            ${IMGUI_ROOT}/imgui_widgets.cpp
            ${IMGUI_ROOT}/backends/imgui_impl_win32.cpp
            ${IMGUI_ROOT}/backends/imgui_impl_dx11.cpp)
    target_include_directories(janus_key_gui PRIVATE ${IMGUI_ROOT} ${IMGUI_ROOT}/backends)
    target_compile_definitions(janus_key_gui PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(janus_key_gui PRIVATE d3d11 d3dcompiler dwmapi imm32 shell32 ole32)
endif ()

add_library(janus_key_pintool SHARED
        src/app/main.cpp
        src/capture/code_identity_catalog.cpp
        src/capture/function_catalog.cpp
        src/capture/memory_api.cpp
        src/capture/pe_image_identity.cpp
        src/capture/pin_tracer.cpp
        src/capture/process_termination_monitor.cpp
        src/capture/register_capture.cpp
        src/capture/windows_x64_abi.cpp
        src/process/process_coordinator.cpp
        src/process/process_launch_planner.cpp
        src/process/run_finalizer.cpp
        src/trace/binary_trace_sink.cpp
        src/trace/compression_codec.cpp
        src/trace/csv_trace_sink.cpp
        src/trace/trace_block_format.cpp
)

set_target_properties(janus_key_pintool PROPERTIES
        PREFIX ""
)

target_include_directories(janus_key_pintool PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
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

if (WIN32)
    # This configuration is for the intel64 Pin kit.
    if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "This Pintool configuration requires an x64 toolchain.")
    endif ()

    set(PIN_ROOT "${CMAKE_SOURCE_DIR}/third_party/pin")
    set(PINRT_LIB_DIR "${PIN_ROOT}/intel64/pinrt/lib")

    # Prebuilt startup objects belong in the target's object inputs,
    # before the import/static libraries.
    set(PIN_STARTUP_OBJECTS
            "${PINRT_LIB_DIR}/crtbeginS.obj"
            "${PINRT_LIB_DIR}/stdlib_new_delete.obj"
    )

    set_source_files_properties(${PIN_STARTUP_OBJECTS}
            PROPERTIES EXTERNAL_OBJECT TRUE
    )

    target_sources(janus_key_pintool PRIVATE
            ${PIN_STARTUP_OBJECTS}
    )

    # Do not put the startup .obj files in this list.
    target_link_libraries(janus_key_pintool PRIVATE
            "${PINRT_LIB_DIR}/c++.lib"
            "${PINRT_LIB_DIR}/pincrt4.lib"
            "${PIN_ROOT}/intel64/lib/pin.lib"
            "${PINRT_LIB_DIR}/pinrt-adaptor-static.lib"
            "${PIN_ROOT}/extras/xed-intel64/lib/xed.lib"
            kernel32
    )
endif ()

# Windows Pintool compiler/linker options.
# Place after add_library(janus_key_pintool ...).
#
# IMPORTANT: The selected compiler must be supported by your Pin kit.
# The Microsoft cl.exe branch is for MSVC-compatible kits, not Pin 4.2.
if (WIN32)
    if (NOT MSVC)
        message(FATAL_ERROR
                "This Windows Pintool configuration requires an MSVC-style "
                "compiler driver: cl.exe or clang-cl.exe."
        )
    endif ()

    target_compile_options(janus_key_pintool PRIVATE
            /GR-
            /GS-
            /EHs-
            /EHa-
            /EHc-
            /Oi-
            /Zc:threadSafeInit-
    )

    if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        # Microsoft cl.exe: use its native include-path option.
        # Do not pass Clang-specific warning flags here.
        target_compile_options(janus_key_pintool PRIVATE
                /X
        )

    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # clang-cl.exe: retain the Clang-specific Pin options.
        target_compile_options(janus_key_pintool PRIVATE
                -nostdinc
                -fno-builtin
                -Wno-non-c-typedef-for-linkage
        )

    else ()
        message(FATAL_ERROR
                "Unhandled Windows Pintool compiler: "
                "${CMAKE_CXX_COMPILER_ID}"
        )
    endif ()

    target_link_options(janus_key_pintool PRIVATE
            /EXPORT:main
            /NODEFAULTLIB
            /INCREMENTAL:NO
            /MANIFEST:NO
    )
endif ()

if (WIN32)
    add_dependencies(janus_key_gui janus_key_pintool)
endif ()

# The baseline tool is only needed for explicit profiler benchmarks.
option(JANUS_BUILD_BENCHMARK_TOOL "Build the empty Pin benchmark tool" OFF)
if (JANUS_BUILD_BENCHMARK_TOOL)
    add_library(pin_baseline SHARED tests/benchmarks/pin_baseline.cpp)
    set_target_properties(pin_baseline PROPERTIES PREFIX "")
    foreach (property IN ITEMS INCLUDE_DIRECTORIES COMPILE_DEFINITIONS COMPILE_OPTIONS LINK_LIBRARIES LINK_OPTIONS)
        get_target_property(value janus_key_pintool ${property})
        set_property(TARGET pin_baseline PROPERTY ${property} "${value}")
    endforeach ()
    if (WIN32)
        target_sources(pin_baseline PRIVATE ${PIN_STARTUP_OBJECTS})
    endif ()
endif ()

if (BUILD_TESTING AND WIN32)
    set(suite_case_sources
            tests/unit/trace/crc32_test.cpp
            tests/unit/capture/call_correlator_test.cpp
            tests/integration/process/process_tree_target.cpp
            tests/integration/capture/self_modifying_target.cpp
            tests/unit/trace/binary_encoder_test.cpp
            tests/unit/trace/trace_block_test.cpp
            tests/unit/capture/memory_api_test.cpp
            tests/unit/support/profiler_clock_test.cpp
            tests/unit/process/process_launch_planner_test.cpp
            tests/unit/capture/code_identity_catalog_test.cpp
            tests/unit/capture/pe_image_identity_test.cpp
            tests/integration/capture/trace_target.cpp
            tests/integration/capture/register_capture_target.cpp
            tests/integration/capture/register_capture_validation.cpp
            tests/integration/capture/capture_coverage_target.cpp
            tests/integration/capture/capture_coverage_validation.cpp
            tests/integration/capture/trace_reader_validation.cpp
            tests/unit/gui/gui_session_test.cpp)
    foreach (suite_case_source IN LISTS suite_case_sources)
        get_filename_component(suite_case "${suite_case_source}" NAME_WE)
        # Each former executable keeps its entry point as a callable suite case.
        set_source_files_properties(${suite_case_source} PROPERTIES
                COMPILE_DEFINITIONS "main=${suite_case}_main")
    endforeach ()

    add_executable(run_tests
            tests/runner/run_tests.cpp
            src/trace/compression_codec.cpp
            src/trace/trace_block_format.cpp
            src/trace/trace_stream_reader.cpp
            src/capture/memory_api.cpp
            src/process/process_launch_planner.cpp
            src/capture/code_identity_catalog.cpp
            src/capture/pe_image_identity.cpp
            src/gui/session.cpp)
    foreach (suite_case_source IN LISTS suite_case_sources)
        target_sources(run_tests PRIVATE ${suite_case_source})
    endforeach ()
    target_include_directories(run_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(run_tests PRIVATE UNICODE _UNICODE NOMINMAX
            JANUS_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    # CaptureFault uses Windows structured exceptions; assertions must run in Release.
    target_compile_options(run_tests PRIVATE /EHa /UNDEBUG)
    set_source_files_properties(tests/integration/capture/trace_target.cpp PROPERTIES COMPILE_OPTIONS /arch:AVX2)
    target_link_libraries(run_tests PRIVATE shell32)
    add_dependencies(run_tests janus_key_pintool)
    add_test(NAME run_tests COMMAND run_tests)
    set_tests_properties(run_tests PROPERTIES TIMEOUT 300)
endif ()

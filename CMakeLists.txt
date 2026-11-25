cmake_minimum_required(VERSION 3.20)
project(ce_4player LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build portable unit tests" ON)

# Portable core library (pattern parsing/scanning, config, spawn math) for both Windows DLL and Linux host tests
add_library(ce4p_core STATIC
    src/core/config.cpp
    src/core/pattern_scanner.cpp
    src/core/spawn_helper.cpp
)
target_include_directories(ce4p_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(WIN32)
    include(FetchContent)
    FetchContent_Declare(
        minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG v1.3.3
    )
    FetchContent_MakeAvailable(minhook)

    add_library(version SHARED
        src/dllmain.cpp
        src/proxy/version_proxy.cpp
        src/proxy/version.def
        src/core/logger.cpp
        src/core/memory_patch.cpp
        src/core/module_watcher.cpp
        src/core/hook_manager.cpp
        src/hooks/lobby_hooks.cpp
        src/hooks/h1_engine_hooks.cpp
    )

    set_target_properties(version PROPERTIES
        OUTPUT_NAME "version"
        PREFIX ""
        SUFFIX ".dll"
    )

    target_include_directories(version PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_link_libraries(version PRIVATE
        ce4p_core
        minhook
        psapi
    )

    target_compile_definitions(version PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )

    if(MINGW)
        target_link_options(version PRIVATE
            -static-libgcc
            -static-libstdc++
            -Wl,--enable-stdcall-fixup
        )
    endif()
endif()

if(BUILD_TESTS)
    enable_testing()
    add_executable(test_pattern_scanner
        tests/test_pattern_scanner.cpp
    )
    target_link_libraries(test_pattern_scanner PRIVATE ce4p_core)
    add_test(NAME PatternScannerTests COMMAND test_pattern_scanner)

    add_executable(test_config_and_spawn
        tests/test_config_and_spawn.cpp
    )
    target_link_libraries(test_config_and_spawn PRIVATE ce4p_core)
    add_test(NAME ConfigAndSpawnTests COMMAND test_config_and_spawn)
endif()

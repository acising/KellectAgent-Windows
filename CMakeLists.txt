cmake_minimum_required(VERSION 3.22)
project(kellect CXX)

ADD_DEFINITIONS(-DWIN32_LEAN_AND_MEAN) #preprocess to avoid duplicate macro definition

add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static CRT (/MT release, /MTd debug): self-contained exes, no VC++ redist.
# Matches the GUI /MT strategy.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if (NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
endif()

# ---------------------------------------------------------------------------
# kellect_core: the ETW pipeline, shared by both products.
#   kellect.exe        - console agent (GUI launches it as a child process)
#   KellectService.exe - Windows service host (no GUI)
# Keeping one library is what guarantees the two products collect identically.
# ---------------------------------------------------------------------------
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")
list(REMOVE_ITEM CORE_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/source/main.cpp")

add_library(kellect_core STATIC ${CORE_SOURCES})
target_include_directories(kellect_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(kellect_core PUBLIC DbgHelp.lib ws2_32.lib advapi32.lib tdh.lib ole32.lib)

# 关闭 easylogging++ 默认日志文件(myeasylog.log):默认 logger 在读取配置前就会
# 创建该文件,conf 层拦不住。MyLogger 自己写 log\agent.log。
target_compile_definitions(kellect_core PRIVATE ELPP_NO_DEFAULT_LOG_FILE)

# ---------------------------------------------------------------------------
# Product 1: console agent
# ---------------------------------------------------------------------------
add_executable(kellect "${CMAKE_CURRENT_SOURCE_DIR}/source/main.cpp")
target_link_libraries(kellect PRIVATE kellect_core)

# ---------------------------------------------------------------------------
# Product 2: Windows service (no GUI)
# ---------------------------------------------------------------------------
option(KELLECT_BUILD_SERVICE "Build KellectService.exe" ON)
if (KELLECT_BUILD_SERVICE)
    add_executable(KellectService
        "${CMAKE_CURRENT_SOURCE_DIR}/service/main.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/service/service_config.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/service/service_host.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/service/supervisor.cpp")
    target_link_libraries(KellectService PRIVATE kellect_core advapi32.lib)
    target_compile_definitions(KellectService PRIVATE UNICODE _UNICODE)
    # Service hosts are console-subsystem binaries launched by the SCM: no
    # manifest elevation (the SCM starts them as LocalSystem).
endif()

# ---------------------------------------------------------------------------
# Runtime layout: bin\<exe> + bin\config\
# ---------------------------------------------------------------------------
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/source/config/" DESTINATION "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/config")

include(CTest)
if (BUILD_TESTING)
    add_executable(evidence_test tools/evidence_test.cpp)
    target_link_libraries(evidence_test PRIVATE kellect_core)
    set_target_properties(evidence_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests"
        PDB_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
    if (MSVC)
        target_compile_options(evidence_test PRIVATE /Zi)
        target_link_options(evidence_test PRIVATE /DEBUG:FULL)
    endif()
    add_test(NAME evidence_archive COMMAND evidence_test)
endif()

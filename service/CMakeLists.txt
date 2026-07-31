cmake_minimum_required(VERSION 3.16)
project(kellectsvc LANGUAGES CXX)

# Repo root whether we are a subproject (add_subdirectory from the repo root) or
# a standalone configure (cmake -S service). Output the wrapper beside kellect.exe.
get_filename_component(KELLECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# /MT static CRT: zero redist, Win7-compatible (same rationale as the Qt GUI).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---- event-log message table: messages.mc -> messages.rc -> embedded .res ----
# Event Viewer renders our %1 insertion strings via the message table embedded
# in KellectService.exe (EventMessageFile registry value points back here).
find_program(MC_COMPILER mc.exe)
set(MC_OUT ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(KELLECT_MSG_RC "")
if(MC_COMPILER)
    add_custom_command(
        OUTPUT  ${MC_OUT}/messages.rc ${MC_OUT}/messages.h ${MC_OUT}/MSG00409.bin
        COMMAND ${CMAKE_COMMAND} -E make_directory ${MC_OUT}
        COMMAND ${MC_COMPILER} -h ${MC_OUT} -r ${MC_OUT}
                ${CMAKE_CURRENT_SOURCE_DIR}/src/messages.mc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/messages.mc
        COMMENT "Compiling event-log message table (mc.exe)"
        VERBATIM)
    set(KELLECT_MSG_RC ${MC_OUT}/messages.rc)
else()
    message(WARNING "mc.exe not found; KellectService will build without an "
        "event-log message table (Event Viewer will not render message text).")
endif()

add_executable(KellectService
    src/KellectService.cpp
    src/ChildSupervisor.cpp
    src/ServiceConfig.cpp
    src/EventLog.cpp
    ${KELLECT_MSG_RC}
)

target_include_directories(KellectService PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(KellectService PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(KellectService PRIVATE /utf-8 /W3)
target_link_libraries(KellectService PRIVATE advapi32 shell32)

set_target_properties(KellectService PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${KELLECT_ROOT}/bin)

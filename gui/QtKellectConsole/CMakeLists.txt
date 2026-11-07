cmake_minimum_required(VERSION 3.16)
project(KellectConsole LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 源文件含 UTF-8 中文注释;MSVC 默认按系统 codepage(936)解析会报 C4819
add_compile_options(/utf-8)

# 动态 Qt 前缀(官方预编译 msvc2019_64;aqt 获取见 README)
set(CMAKE_PREFIX_PATH "D:/Code/Qt/5.15.2/msvc2019_64" CACHE PATH "Dynamic Qt 5.15 prefix")

find_package(Qt5 COMPONENTS Widgets Network Test REQUIRED)

# /MD(Release)/ /MDd(Debug):官方 Qt 以 /MD 发布,混链不受 Qt 支持;
# CRT DLL 由 MSI 以 app-local 方式随包安装(Win7 无系统副本,Win10 冗余无害)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:DebugDLL>")

set(SOURCES
    src/main.cpp
    src/CrashHandler.cpp
    src/ui/MainWindow.cpp
    src/ui/LogModel.cpp
    src/ui/LogHeader.cpp
    src/ui/EventColor.cpp
    src/ui/LogDelegate.cpp
    src/service/ServicePanel.cpp
    src/domain/Preset.cpp
    src/domain/LogParser.cpp
    src/domain/Utf8Accumulator.cpp
    src/domain/SettingsStore.cpp
    src/process/KellectProcessService.cpp
    src/process/OutputForwarder.cpp
)
set(HEADERS
    src/ui/MainWindow.h
    src/ui/LogHeader.h
    src/service/ServicePanel.h
)

# qt5_add_resources 接受 .qrc(不是 .qss),否则 rcc 解析失败
qt5_add_resources(QSS resources/dark.qrc)

add_executable(KellectConsole WIN32
    ${SOURCES}
    ${HEADERS}
    ${QSS}
    app.rc
)
target_include_directories(KellectConsole PRIVATE src)
target_link_libraries(KellectConsole PRIVATE
    Qt5::Widgets
    Qt5::Network
)
target_compile_definitions(KellectConsole PRIVATE UNICODE _UNICODE)
set_target_properties(KellectConsole PROPERTIES
    OUTPUT_NAME "KellectConsole"
)

enable_testing()
add_subdirectory(tests)

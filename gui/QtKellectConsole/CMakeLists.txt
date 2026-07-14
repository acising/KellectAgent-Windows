cmake_minimum_required(VERSION 3.16)
project(KellectConsole LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 源文件含 UTF-8 中文注释;MSVC 默认按系统 codepage(936)解析会报 C4819
add_compile_options(/utf-8)

# 静态 Qt 前缀(自编产物)
set(CMAKE_PREFIX_PATH "D:/Code/Qt/5.15.2-static" CACHE PATH "Static Qt 5.15 prefix")

find_package(Qt5 COMPONENTS Widgets Test REQUIRED)

# 强制 /MT(Release)/ /MTd(Debug),与静态 Qt 的 -static-runtime 一致
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(SOURCES
    src/main.cpp
    src/CrashHandler.cpp
    src/ui/MainWindow.cpp
    src/ui/LogModel.cpp
    src/ui/LogHeader.cpp
    src/ui/EventColor.cpp
    src/ui/LogDelegate.cpp
    src/domain/Preset.cpp
    src/domain/LogParser.cpp
    src/domain/Utf8Accumulator.cpp
    src/domain/SettingsStore.cpp
    src/process/KellectProcessService.cpp
)
set(HEADERS
    src/ui/MainWindow.h
    src/ui/LogHeader.h
)

# Resolution #2: qt5_add_resources 接受 .qrc(不是 .qss),否则 rcc 解析失败
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
    Qt5::QWindowsIntegrationPlugin  # 静态 Qt 必需:平台插件静态链入
)
target_compile_definitions(KellectConsole PRIVATE UNICODE _UNICODE)
set_target_properties(KellectConsole PROPERTIES
    OUTPUT_NAME "KellectConsole"
)

enable_testing()
add_subdirectory(tests)

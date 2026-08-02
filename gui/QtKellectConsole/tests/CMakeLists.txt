# 各 QtTest 在对应任务里 add_executable + add_test 注册
add_executable(tst_flags tst_flags.cpp)
target_link_libraries(tst_flags PRIVATE Qt5::Test)
target_include_directories(tst_flags PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME tst_flags COMMAND tst_flags)

add_executable(tst_preset tst_preset.cpp)
target_link_libraries(tst_preset PRIVATE Qt5::Test)
target_include_directories(tst_preset PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_preset PRIVATE ${CMAKE_SOURCE_DIR}/src/domain/Preset.cpp)
add_test(NAME tst_preset COMMAND tst_preset)

add_executable(tst_utf8accumulator tst_utf8accumulator.cpp)
target_link_libraries(tst_utf8accumulator PRIVATE Qt5::Test)
target_include_directories(tst_utf8accumulator PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_utf8accumulator PRIVATE ${CMAKE_SOURCE_DIR}/src/domain/Utf8Accumulator.cpp)
add_test(NAME tst_utf8accumulator COMMAND tst_utf8accumulator)

add_executable(tst_settingsstore tst_settingsstore.cpp)
target_link_libraries(tst_settingsstore PRIVATE Qt5::Test)
target_include_directories(tst_settingsstore PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_settingsstore PRIVATE ${CMAKE_SOURCE_DIR}/src/domain/SettingsStore.cpp)
add_test(NAME tst_settingsstore COMMAND tst_settingsstore)

add_executable(tst_processservice tst_processservice.cpp)
target_link_libraries(tst_processservice PRIVATE Qt5::Test)
target_include_directories(tst_processservice PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_processservice PRIVATE
    ${CMAKE_SOURCE_DIR}/src/process/KellectProcessService.cpp
    ${CMAKE_SOURCE_DIR}/src/domain/Utf8Accumulator.cpp)
add_test(NAME tst_processservice COMMAND tst_processservice)

add_executable(tst_logmodel tst_logmodel.cpp)
target_link_libraries(tst_logmodel PRIVATE Qt5::Test Qt5::Gui)
target_include_directories(tst_logmodel PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_logmodel PRIVATE ${CMAKE_SOURCE_DIR}/src/ui/LogModel.cpp)
add_test(NAME tst_logmodel COMMAND tst_logmodel)

add_executable(tst_eventcolor tst_eventcolor.cpp)
target_link_libraries(tst_eventcolor PRIVATE Qt5::Test Qt5::Gui)
target_include_directories(tst_eventcolor PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_eventcolor PRIVATE ${CMAKE_SOURCE_DIR}/src/ui/EventColor.cpp)
add_test(NAME tst_eventcolor COMMAND tst_eventcolor)

add_executable(tst_logparser tst_logparser.cpp)
target_link_libraries(tst_logparser PRIVATE Qt5::Test)
target_include_directories(tst_logparser PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_logparser PRIVATE ${CMAKE_SOURCE_DIR}/src/domain/LogParser.cpp)
add_test(NAME tst_logparser COMMAND tst_logparser)

add_executable(tst_outputforwarder tst_outputforwarder.cpp)
target_link_libraries(tst_outputforwarder PRIVATE Qt5::Test Qt5::Network)
target_include_directories(tst_outputforwarder PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_outputforwarder PRIVATE ${CMAKE_SOURCE_DIR}/src/process/OutputForwarder.cpp)
add_test(NAME tst_outputforwarder COMMAND tst_outputforwarder)

add_executable(tst_windowsserviceclient tst_windowsserviceclient.cpp)
target_link_libraries(tst_windowsserviceclient PRIVATE Qt5::Test advapi32)
target_include_directories(tst_windowsserviceclient PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_sources(tst_windowsserviceclient PRIVATE ${CMAKE_SOURCE_DIR}/src/process/WindowsServiceClient.cpp)
add_test(NAME tst_windowsserviceclient COMMAND tst_windowsserviceclient)

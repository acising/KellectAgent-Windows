cmake_minimum_required(VERSION 3.22)
project(kellect)
ADD_DEFINITIONS(-DWIN32_LEAN_AND_MEAN) #preprocess to avoid duplicate macro definition

add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")#set exe building path
file(GLOB_RECURSE INCLUDE_DIR_LIST "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp") #iterate the cpp files
set(SRC_ALL ${INCLUDE_DIR_LIST})
file(GLOB_RECURSE THIRD_LIB "${CMAKE_CURRENT_SOURCE_DIR}/lib/*.lib")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/source/config/" DESTINATION "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/config") #copy configs to bin/
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/source/dlls/" DESTINATION "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

include_directories(./include)
add_executable(kellect ${SRC_ALL})
target_link_libraries(kellect ${THIRD_LIB})

cmake_minimum_required(VERSION 3.0)

project(protocol_stack)

set(lib_name "protocol_stack")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED 14)
set(CMAKE_CXX_FLAGS "-g -fpermissive -lpcap -lpthread")

file(GLOB includes "include/*.h")
file(GLOB sources "src/*.cc")


include_directories("include/" "/usr/include/pcap/")
include(FindPCAP.cmake)

find_package(Threads REQUIRED)
add_library(${lib_name} SHARED ${includes} ${sources})

add_subdirectory(test_scripts)
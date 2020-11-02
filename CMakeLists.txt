cmake_minimum_required(VERSION 3.8)

project(user_space_protocol_stack)

set(lib_name "user_space_protocol_stack")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED 14)
set(CMAKE_CXX_FLAGS "-g -fpermissive -lpcap -lpthread")

file(GLOB headers "include/*.h")
file(GLOB sources "src/*.cc")

set(utils_root "${PROJECT_SOURCE_DIR}/cmake")
file(GLOB cmake_utils "${utils_root}/*.cmake")
foreach(util IN LISTS cmake_utils)
    include(${util})
endforeach(util IN LISTS cmake_utils)

include_directories("include/" "/usr/include/pcap/")


add_library(${lib_name} SHARED ${headers} ${sources})

add_subdirectory(test_scripts)
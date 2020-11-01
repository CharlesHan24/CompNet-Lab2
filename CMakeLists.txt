cmake_minimum_required(VERSION 3.8)

project(user_space_protocol_stack)

set(lib_name "user_space_protocol_stack")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED 14)

file(GLOB proj_headers "include/*.h")
file(GLOB proj_sources "src/*.cc")

set(utils_root "${PROJECT_SOURCE_DIR}/cmake")
file(GLOB cmake_utils "${utils_root}/*.cmake")
foreach(util IN LISTS cmake_utils)
    include(${util})
endforeach(util IN LISTS cmake_utils)

include_directories("include/" ${PCAP_INCLUDE_DIRS})

link_libraries(${PCAP_LIBRARIES})
add_definitions(-DBOOST_LOG_DYN_LINK)


add_library(${lib_name} SHARED ${proj_headers} ${proj_sources})

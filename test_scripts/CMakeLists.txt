# include_directories(${PCAP_INCLUDE_DIRS})

# add_executable(eth_tests eth_tests.cpp)
# target_link_libraries(eth_tests LINK_PUBLIC ${lib_name})
# message(STATUS ${lib_name})

file(GLOB tests_src "*.cpp")

foreach(test_src IN LISTS tests_src)
    get_filename_component(test_name ${test_src} NAME_WE)
    set(CMAKE_CXX_FLAGS "-g -fpermissive -lpcap -lpthread")
    add_executable(${test_name} ${test_src})
    target_link_libraries(${test_name} LINK_PUBLIC ${lib_name} "/usr/lib/x86_64-linux-gnu/libpcap.so.1.8.1" "/usr/lib/x86_64-linux-gnu/libpthread.so")
endforeach(test_src IN LISTS tests_src)

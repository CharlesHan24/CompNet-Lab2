file(GLOB test_scripts "*.cpp")

foreach(test_script IN LISTS test_scripts)
    get_filename_component(file_name ${test_script} NAME_WE)
    set(CMAKE_CXX_FLAGS "-g -fpermissive -lpcap -lpthread")
    add_executable(${file_name} ${test_script})
    target_link_libraries(${file_name} LINK_PUBLIC ${lib_name} ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
endforeach(test_script IN LISTS tests_scripts)

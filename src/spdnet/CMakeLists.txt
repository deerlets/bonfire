cmake_minimum_required(VERSION 2.8)

file(GLOB_RECURSE SRC *.c)
file(GLOB_RECURSE INC *.h)

add_library(spdnet SHARED ${SRC})
set_target_properties(spdnet PROPERTIES PUBLIC_HEADER "${INC}")
set_target_properties(spdnet PROPERTIES VERSION 0.1.0 SOVERSION 0.1)

target_link_libraries(spdnet zmq pthread)
if (WIN32)
    target_link_libraries(spdnet ws2_32)
endif ()

install(TARGETS spdnet
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/spdnet)

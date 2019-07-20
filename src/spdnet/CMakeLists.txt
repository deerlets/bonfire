cmake_minimum_required(VERSION 2.8)

file(GLOB SRC *.c)
file(GLOB INC spdnet.h)

add_definitions(-DSPDNET_INTERNAL)

add_library(spdnet SHARED ${SRC})
set_target_properties(spdnet PROPERTIES PUBLIC_HEADER "${INC}")
set_target_properties(spdnet PROPERTIES VERSION 1.3.0 SOVERSION 1)

target_link_libraries(spdnet zmq pthread)
if (WIN32)
    target_link_libraries(spdnet ws2_32)
endif ()

install(TARGETS spdnet
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)

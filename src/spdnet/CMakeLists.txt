cmake_minimum_required(VERSION 3.12)

file(GLOB SRC *.c)
file(GLOB INC spdnet.h)

add_library(spdnet SHARED ${SRC})
set_target_properties(spdnet PROPERTIES PUBLIC_HEADER "${INC}")
set_target_properties(spdnet PROPERTIES VERSION 1.0.0 SOVERSION 1)

target_link_libraries(spdnet zmq pthread)

install(TARGETS spdnet
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)
